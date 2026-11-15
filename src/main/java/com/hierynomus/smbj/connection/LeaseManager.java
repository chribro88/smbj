/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.smbj.connection;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.mssmb2.LeaseKey;
import com.hierynomus.mssmb2.messages.SMB2LeaseBreakAcknowledgment;
import com.hierynomus.mssmb2.messages.SMB2LeaseBreakNotification;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.TreeConnect;

/**
 * Lease table retained by a session's canonical {@link Connection}, including while bound
 * channels survive its transport. A break's lease key resolves to its owning {@link LeaseEntry}
 * (spec 06). A directory's lease key is minted <b>once per node
 * (path)</b> and reused (Apple's per-node key); the {@code path -> key} map also lets a
 * child open thread its parent directory's own lease key.
 */
public class LeaseManager implements Closeable {
    private static final Logger logger = LoggerFactory.getLogger(LeaseManager.class);

    private final ConcurrentMap<LeaseKey, LeaseEntry> byKey = new ConcurrentHashMap<>();
    private final ConcurrentMap<LeasePath, LeaseKey> byPath = new ConcurrentHashMap<>();
    // Path identity and handle reservations change together; cache I/O stays outside this lock.
    private final Object registrationLock = new Object();
    private final AtomicBoolean closed = new AtomicBoolean();

    // A break must be resolved/acknowledged OFF the transport read thread: sending the ack is
    // itself an SMB2 request whose reply can only arrive on that same read thread.
    private final ExecutorService breakExecutor = Executors.newSingleThreadExecutor(new ThreadFactory() {
        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "smbj-lease-break");
            t.setDaemon(true);
            return t;
        }
    });
    private final AtomicInteger breaksHandled = new AtomicInteger(0);
    // Awaiting CLOSE on the break executor could deadlock the break that permits CLOSE to finish.
    // Keep every submitted completion queued: running it on the caller could make closeNoWait block,
    // while rejecting it would leave an already-sent CLOSE without a response observer.
    private final ExecutorService closeExecutor = createCloseExecutor();

    private static ExecutorService createCloseExecutor() {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            8, 8, 60L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<Runnable>(),
            new ThreadFactory() {
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "smbj-lease-close");
                    t.setDaemon(true);
                    return t;
                }
            }
        );
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    void dispatchClose(Runnable completion) {
        closeExecutor.execute(completion);
    }

    /** Stable per-node key: mint once per normalized path within share, reuse thereafter. */
    public LeaseKey leaseKeyForPath(String shareName, String path) {
        synchronized (registrationLock) {
            ensureOpen();
            return byPath.computeIfAbsent(new LeasePath(null, shareName, path), p -> LeaseKey.random());
        }
    }

    /** Stable per-node key: mint once per normalized path, reuse thereafter. */
    public LeaseKey leaseKeyForPath(String path) {
        return leaseKeyForPath((String) null, path);
    }

    /** The lease key previously minted for {@code (shareName, path)}, or {@code null} if never opened. */
    public LeaseKey leaseKeyForExistingPath(String shareName, String path) {
        return byPath.get(new LeasePath(null, shareName, path));
    }

    /** The lease key previously minted for {@code path}, or {@code null} if never opened. */
    public LeaseKey leaseKeyForExistingPath(String path) {
        return leaseKeyForExistingPath((String) null, path);
    }

    /** The live lease entry for {@code (shareName, path)}, or {@code null} if none is registered. */
    public LeaseEntry getByPath(String shareName, String path) {
        LeaseKey key = byPath.get(new LeasePath(null, shareName, path));
        return key == null ? null : byKey.get(key);
    }

    /** The live lease entry for {@code path}, or {@code null} if none is registered. */
    public LeaseEntry getByPath(String path) {
        if (isClosed(null)) return null;
        LeaseEntry found = getByPath((String) null, path);
        if (found != null) return found;
        for (LeaseEntry entry : byKey.values()) {
            if (normalizePath(entry.getPath()).equals(normalizePath(path))) {
                if (found != null) return null;
                found = entry;
            }
        }
        return found;
    }

    public LeaseKey leaseKeyForPath(TreeConnect tree, String path) {
        synchronized (registrationLock) {
            requireOpen(tree);
            return byPath.computeIfAbsent(new LeasePath(tree, null, path), p -> LeaseKey.random());
        }
    }

    public LeaseKey leaseKeyForExistingPath(TreeConnect tree, String path) {
        return byPath.get(new LeasePath(tree, null, path));
    }

    public LeaseEntry getByPath(TreeConnect tree, String path) {
        if (isClosed(tree)) return null;
        LeaseKey key = byPath.get(new LeasePath(tree, null, path));
        LeaseEntry entry = key == null ? null : byKey.get(key);
        return entry != null && entry.getTreeConnect() == tree ? entry : null;
    }

    public void invalidateDirectoryCache(TreeConnect tree, String path) {
        LeaseEntry entry = getByPath(tree, path);
        if (entry != null) entry.invalidateCache();
    }

    /**
     * Register an entry BEFORE sending its CREATE (a break can race the grant response),
     * reserving its first handle reference until CREATE fails or the returned Directory closes.
     */
    public void register(LeaseEntry entry) {
        synchronized (registrationLock) {
            registerEntry(entry);
        }
    }

    private void registerEntry(LeaseEntry entry) {
        requireOpen(entry.getTreeConnect());
        entry.retainReference(this);
        byKey.put(entry.getLeaseKey(), entry);
        byPath.putIfAbsent(new LeasePath(entry.getTreeConnect(), entry.getShareName(), entry.getPath()), entry.getLeaseKey());
    }

    /** Atomically select the current path lease and reserve a CREATE on it. */
    public LeaseEntry acquire(String shareName, String path, LeaseKey parentKey, long requestedState) {
        return acquire(null, shareName, path, parentKey, requestedState);
    }

    public LeaseEntry acquire(TreeConnect tree, String path, LeaseKey parentKey, long requestedState) {
        return acquire(tree, null, path, parentKey, requestedState);
    }

    private LeaseEntry acquire(TreeConnect tree, String shareName, String path, LeaseKey parentKey, long requestedState) {
        LeaseEntry existing;
        LeaseEntry acquired;
        synchronized (registrationLock) {
            requireOpen(tree);
            LeasePath pathKey = new LeasePath(tree, shareName, path);
            LeaseKey key = byPath.get(pathKey);
            existing = key == null ? null : byKey.get(key);
            if (existing != null && !existing.isBroken()) {
                existing.retainReference(this);
                return existing;
            }
            if (existing != null) {
                byPath.remove(pathKey);
            }
            key = byPath.computeIfAbsent(pathKey, p -> LeaseKey.random());
            acquired = tree == null ? new LeaseEntry(key, parentKey, requestedState, shareName, path)
                : new LeaseEntry(key, parentKey, requestedState, path, tree);
            registerEntry(acquired);
        }
        if (existing != null) {
            existing.invalidateCache();
        }
        return acquired;
    }

    /** Release a failed CREATE or a closed handle, keeping routing until the last handle closes. */
    public void release(LeaseEntry entry) {
        synchronized (registrationLock) {
            if (entry.releaseReference() == 0) {
                byKey.remove(entry.getLeaseKey(), entry);
            }
        }
    }

    /** Actively evicts cached enumeration and closes cached handle for a directory in the specified share. */
    public void invalidateDirectoryCache(String shareName, String path) {
        LeaseEntry entry = getByPath(shareName, path);
        if (entry != null) {
            entry.invalidateCache();
        }
    }

    /** Actively evicts cached enumeration and closes cached handle for a directory. */
    public void invalidateDirectoryCache(String path) {
        invalidateDirectoryCache((String) null, path);
    }

    /**
     * Invalidate caches and detach the path keys for a directory and all its descendants.
     * Entries remain addressable by lease key: application handles can still be open after a
     * deletion, and the server can send breaks that must be acknowledged until those handles close.
     */
    public void invalidateDirectoryAndDescendants(String shareName, String path) {
        invalidateDirectoryAndDescendants(null, shareName, path);
    }

    public void invalidateDirectoryAndDescendants(TreeConnect tree, String path) {
        invalidateDirectoryAndDescendants(tree, null, path);
    }

    private void invalidateDirectoryAndDescendants(TreeConnect tree, String shareName, String path) {
        LeasePath target = new LeasePath(tree, shareName, path);

        List<LeaseEntry> detached = new ArrayList<>();
        synchronized (registrationLock) {
            for (Map.Entry<LeasePath, LeaseKey> mapEntry : byPath.entrySet()) {
                LeasePath k = mapEntry.getKey();
                if (target.contains(k)) {
                    LeaseKey lk = mapEntry.getValue();
                    byPath.remove(k, lk);
                }
            }

            for (LeaseEntry entry : byKey.values()) {
                LeasePath entryKey = new LeasePath(entry.getTreeConnect(), entry.getShareName(), entry.getPath());
                if (target.contains(entryKey)) {
                    detached.add(entry);
                }
            }
        }
        for (LeaseEntry entry : detached) {
            entry.invalidateCache();
        }
    }

    /** Invalidate caches and detach path keys for a directory and all its descendants. */
    public void invalidateDirectoryAndDescendants(String path) {
        invalidateDirectoryAndDescendants((String) null, path);
    }

    /** Resolve an inbound break's lease key to its entry (spec 06). */
    public LeaseEntry lookup(LeaseKey key) {
        return byKey.get(key);
    }

    /** Drop the entry (no lease granted / handle closed). The node key in {@code byPath} is kept. */
    public void unregister(LeaseKey key) {
        synchronized (registrationLock) {
            byKey.remove(key);
        }
    }

    /** Invalidate only the leases belonging to this exact session owner. */
    public void releaseSession(Session session) {
        List<LeaseEntry> detached = new ArrayList<>();
        synchronized (registrationLock) {
            for (LeaseEntry entry : byKey.values()) {
                if (entry.getSession() == session && byKey.remove(entry.getLeaseKey(), entry)) {
                    entry.setBroken(true);
                    detached.add(entry);
                }
            }
            byPath.keySet().removeIf(path -> path.tree != null && path.tree.getSession() == session);
        }
        for (LeaseEntry entry : detached) entry.invalidateCache();
    }

    /** Drop one exact tree's keys and caches before TREE_DISCONNECT, including failure cleanup. */
    public void releaseTree(TreeConnect tree) {
        List<LeaseEntry> detached = new ArrayList<>();
        synchronized (registrationLock) {
            for (LeaseEntry entry : byKey.values()) {
                if (entry.getTreeConnect() == tree && byKey.remove(entry.getLeaseKey(), entry)) {
                    entry.setBroken(true);
                    detached.add(entry);
                }
            }
            byPath.keySet().removeIf(path -> path.tree == tree);
        }
        for (LeaseEntry entry : detached) entry.invalidateCache();
    }

    /** Number of lease breaks fully handled (test/diagnostic hook). */
    public int getBreaksHandled() {
        return breaksHandled.get();
    }

    @Override
    public void close() {
        close(true);
    }

    /** Discard local cache state without sending SMB requests during forced teardown. */
    public void abort() {
        close(false);
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("Lease manager is closed");
        }
    }

    private void close(boolean closeHandles) {
        List<LeaseEntry> entries;
        synchronized (registrationLock) {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            entries = new ArrayList<>(byKey.values());
            byKey.clear();
            byPath.clear();
        }
        breakExecutor.shutdownNow();
        closeExecutor.shutdownNow();
        for (LeaseEntry entry : entries) {
            entry.setBroken(true);
            if (closeHandles) {
                entry.invalidateCache();
            } else {
                entry.discardCache();
            }
        }
    }

    /**
     * Entry point from the receive-thread break handler: dispatch the resolve/invalidate/ack
     * work OFF the read thread.
     */
    public void dispatchBreak(final SMB2LeaseBreakNotification notification) {
        if (closed.get()) return;
        dispatchBreak(notification, lookup(notification.getLeaseKey()));
    }

    /** Preserve the resolved owner if session cleanup races queued break handling. */
    public void dispatchBreak(final SMB2LeaseBreakNotification notification, final LeaseEntry entry) {
        if (closed.get() || entry == null) return;
        final Session owner = entry.getSession();
        try {
            breakExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        onBreak(notification, entry, owner);
                    } catch (Exception t) {
                        logger.error("Lease-break handling failed for {}", notification.getLeaseKey(), t);
                    }
                }
            });
        } catch (RejectedExecutionException e) {
            if (!closed.get() && !breakExecutor.isShutdown()) throw e;
            logger.debug("Ignoring lease break after owner shutdown: {}", notification.getLeaseKey());
        }
    }

    /** Resolve → epoch-check → invalidate → update state → ack (runs on {@link #breakExecutor}). */
    void onBreak(SMB2LeaseBreakNotification n) throws Exception {
        LeaseEntry entry = byKey.get(n.getLeaseKey());
        onBreak(n, entry, entry == null ? null : entry.getSession());
    }

    private void onBreak(SMB2LeaseBreakNotification n, LeaseEntry entry, Session owner) throws Exception {
        if (entry == null || byKey.get(n.getLeaseKey()) != entry || entry.getSession() != owner) {
            logger.debug("Lease break for unknown key {}, ignoring", n.getLeaseKey());
            return;
        }

        // Epoch-delta staleness guard (V2). NewEpoch == 0 (non-V2) => always apply.
        int delta = epochDelta(n.getNewEpoch(), entry.getEpoch());
        if (n.getNewEpoch() != 0 && delta <= 0) {
            logger.debug("Stale lease break (newEpoch {} <= stored {}), ignoring", n.getNewEpoch(), entry.getEpoch());
            return;
        }

        // Stop new queries from caching before invalidation can block on closing the cache handle.
        entry.setBroken(true);
        entry.invalidateCacheNoWait();
        entry.setGrantedState(n.getNewLeaseState());
        if (n.getNewEpoch() != 0) {
            entry.setEpoch(n.getNewEpoch());
        }

        // Acknowledge if required (the RH-directory case). Ack state is a subset of NewLeaseState.
        if (n.isAckRequired() && owner != null) {
            SMB2LeaseBreakAcknowledgment ack = new SMB2LeaseBreakAcknowledgment(
                entry.getDialect(), owner.getSessionId(), entry.getTreeId(),
                n.getLeaseKey(), n.getNewLeaseState());
            owner.send(ack); // normal (signed) send path; reply observed by the chain
            logger.debug("Acknowledged lease break for {} -> state {}", n.getLeaseKey(), n.getNewLeaseState());
        }
        breaksHandled.incrementAndGet();
    }

    /**
     * Epoch delta per Apple's smbfs model: 0 if equal, positive if newer (apply),
     * wrap-aware, -1 if stale/reordered (ignore).
     */
    static int epochDelta(int newEpoch, int storedEpoch) {
        if (newEpoch == storedEpoch) {
            return 0;
        }
        if (newEpoch > storedEpoch) {
            return newEpoch - storedEpoch;
        }
        // storedEpoch > newEpoch: a large gap means the 16-bit epoch wrapped (server is newer).
        if (storedEpoch - newEpoch > 32767) {
            return (0x10000 - storedEpoch) + newEpoch;
        }
        return -1; // stale / reordered
    }

    public static String normalizeShare(String shareName) {
        if (shareName == null) {
            return "";
        }
        String s = shareName.replace('/', '\\').trim().toLowerCase(Locale.ROOT);
        while (s.startsWith("\\")) {
            s = s.substring(1);
        }
        while (s.endsWith("\\")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    public static String normalizePath(String path) {
        if (path == null) {
            return "";
        }
        String p = path.replace('/', '\\').toLowerCase(Locale.ROOT);
        while (p.startsWith("\\")) {
            p = p.substring(1);
        }
        while (p.endsWith("\\")) {
            p = p.substring(0, p.length() - 1);
        }
        return p;
    }

    public static String formatPathKey(String normalizedShare, String normalizedPath) {
        return normalizedShare.length() + ":" + normalizedShare + ":" + normalizedPath;
    }

    public static String normalizePathKey(String shareName, String path) {
        String s = normalizeShare(shareName);
        String p = normalizePath(path);
        // Frame the namespace separately from the path, including the legacy null-share
        // namespace. Concatenating with a path separator lets (null, "share\\docs") collide
        // with ("share", "docs"). A length prefix also avoids delimiter collisions.
        return formatPathKey(s, p);
    }

    private boolean isClosed(TreeConnect tree) {
        return closed.get() || breakExecutor.isShutdown() || (tree != null
                && (tree.isClosed() || tree.getSession().getChannelCount() == 0));
    }

    private void requireOpen(TreeConnect tree) {
        if (isClosed(tree)) throw new IllegalStateException("SMB lease owner is closed");
    }

    private static final class LeasePath {
        private final TreeConnect tree;
        private final String share;
        private final String path;

        private LeasePath(TreeConnect tree, String share, String path) {
            this.tree = tree;
            this.share = tree == null ? normalizeShare(share) : "";
            this.path = normalizePath(path);
        }

        private boolean contains(LeasePath other) {
            return tree == other.tree && share.equals(other.share)
                && (path.isEmpty() || path.equals(other.path) || other.path.startsWith(path + "\\"));
        }

        @Override public boolean equals(Object other) {
            if (!(other instanceof LeasePath)) return false;
            LeasePath key = (LeasePath) other;
            return tree == key.tree && share.equals(key.share) && path.equals(key.path);
        }

        @Override public int hashCode() {
            return 31 * (31 * System.identityHashCode(tree) + share.hashCode()) + path.hashCode();
        }
    }
}
