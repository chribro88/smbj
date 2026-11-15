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
package com.hierynomus.smbj.share;

import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2TreeDisconnect;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.*;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DirectoryLeaseIsolationTest {
    @Test
    void sameTreeCanServeItsOwnCachedListing() throws Exception {
        try (Fixture f = new Fixture()) {
            assertEquals(f.listing, f.share(f.source).list("dir", FileIdBothDirectoryInformation.class));
            verify(f.owner, never()).send(any());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2})
    void anotherSessionShareOrTreeGenerationCannotReadTheCachedListing(int variant) throws Exception {
        try (Fixture f = new Fixture()) {
            Session owner = variant == 0 ? f.session(48) : f.owner;
            TreeConnect tree = f.tree(owner, variant == 1 ? "other" : "share", 7);
            DiskShare share = f.share(tree);
            RuntimeException denied = new RuntimeException("Access denied for this directory owner");
            doThrow(denied).when(share).openDirectory(eq("dir"), any(), any(), any(), any(), any());
            assertSame(denied, assertThrows(RuntimeException.class,
                    () -> share.list("dir", FileIdBothDirectoryInformation.class)));
            assertEquals(0, f.entry.getCache().getServeHits());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void successfulOrFailedTreeCloseInvalidatesOnlyItsOwnLease(boolean failed) throws Exception {
        try (Fixture f = new Fixture()) {
            TreeConnect otherTree = f.tree(f.owner, "other", 8);
            LeaseEntry other = f.entry(otherTree, "other-dir");
            if (failed) {
                when(f.owner.send(any())).thenThrow(new TransportException("Peer lost"));
                assertThrows(TransportException.class, f.source::close);
            } else {
                when(f.owner.send(any())).thenReturn(CompletableFuture.completedFuture(
                        new SMB2TreeDisconnect(SMB2Dialect.SMB_3_1_1, 47, 7)));
                f.source.close();
            }
            assertNull(f.manager.lookup(f.entry.getLeaseKey()));
            assertTrue(f.entry.isBroken());
            assertSame(other, f.manager.lookup(other.getLeaseKey()));
            assertFalse(other.isBroken());
        }
    }

    @Test
    void eachSessionShareAndTreeGenerationCanCacheTheSameRelativePath() throws Exception {
        try (Fixture f = new Fixture()) {
            for (int variant = 0; variant < 3; variant++) {
                Session owner = variant == 0 ? f.session(48) : f.owner;
                TreeConnect tree = f.tree(owner, variant == 1 ? "other" : "share", 7);
                LeaseEntry entry = f.entry(tree, "dir");
                List<FileIdBothDirectoryInformation> own = Collections.singletonList(mock(FileIdBothDirectoryInformation.class));
                entry.getCache().populate("dir", FileIdBothDirectoryInformation.class, null, own);
                assertEquals(own, f.share(tree).list("dir", FileIdBothDirectoryInformation.class));
                assertEquals(f.listing, f.share(f.source).list("dir", FileIdBothDirectoryInformation.class));
            }
            assertNull(f.manager.getByPath("dir"), "A diagnostic without tree identity must not choose an ambiguous entry");
        }
    }

    @Test
    void stableReopenAndParentKeysStayWithinTheOwningTree() throws Exception {
        try (Fixture f = new Fixture()) {
            TreeConnect other = f.tree(f.owner, "other", 7);
            LeaseKey parent = f.manager.leaseKeyForPath(f.source, "");
            assertEquals(parent, f.manager.leaseKeyForExistingPath(f.source, ""));
            assertNull(f.manager.leaseKeyForExistingPath(other, ""));
            assertEquals(f.entry.getLeaseKey(), f.manager.leaseKeyForPath(f.source, "DIR"));
            assertNotEquals(f.entry.getLeaseKey(), f.manager.leaseKeyForPath(other, "dir"));
            f.manager.unregister(f.entry.getLeaseKey());
            assertEquals(f.entry.getLeaseKey(), f.manager.leaseKeyForPath(f.source, "dir"));
        }
    }

    @Test
    void scopedLeaseOwnerCannotBeReassignedToAnotherSession() throws Exception {
        try (Fixture f = new Fixture()) {
            assertThrows(IllegalArgumentException.class,
                    () -> f.entry.setOwner(f.session(47), 7, SMB2Dialect.SMB_3_1_1));
            assertThrows(IllegalArgumentException.class,
                    () -> f.entry.setOwner(f.owner, 8, SMB2Dialect.SMB_3_1_1));
            assertSame(f.owner, f.entry.getSession());
            assertSame(f.source, f.entry.getTreeConnect());
        }
    }

    @Test
    void closedManagerCannotRecreateStateThroughAnOpenTree() throws Exception {
        try (Fixture f = new Fixture()) {
            f.manager.close();
            assertFalse(f.source.isClosed(), "A transport loss can close the manager before the tree object");
            assertThrows(IllegalStateException.class, () -> f.manager.leaseKeyForPath(f.source, "late"));
            LeaseKey key = LeaseKey.random();
            assertThrows(IllegalStateException.class, () -> f.manager.register(
                    new LeaseEntry(key, null, SMB2LeaseState.readHandle(), "late", f.source)));
            assertNull(f.manager.lookup(key));
            assertNull(f.manager.leaseKeyForExistingPath(f.source, "late"));
        }
    }

    @Test
    void sessionReleaseRemovesItsPathKeysWithoutTouchingAnotherSession() throws Exception {
        try (Fixture f = new Fixture()) {
            TreeConnect otherTree = f.tree(f.session(48), "share", 7);
            LeaseEntry other = f.entry(otherTree, "dir");
            f.manager.releaseSession(f.owner);
            assertNull(f.manager.leaseKeyForExistingPath(f.source, "dir"));
            assertNull(f.manager.lookup(f.entry.getLeaseKey()));
            assertSame(other, f.manager.getByPath(otherTree, "dir"));
            assertEquals(other.getLeaseKey(), f.manager.leaseKeyForExistingPath(otherTree, "dir"));
        }
    }

    @Test
    void sessionWithoutChannelsCannotRecreateKeysInAnotherSessionsLiveManager() throws Exception {
        try (Fixture f = new Fixture()) {
            TreeConnect otherTree = f.tree(f.session(48), "share", 7);
            LeaseEntry other = f.entry(otherTree, "dir");
            when(f.owner.getChannelCount()).thenReturn(0);
            f.manager.releaseSession(f.owner);
            assertThrows(IllegalStateException.class, () -> f.manager.leaseKeyForPath(f.source, "late"));
            assertNull(f.manager.leaseKeyForExistingPath(f.source, "late"));
            assertSame(other, f.manager.getByPath(otherTree, "dir"));
        }
    }

    @Test
    void racingTreeCloseAndRegistrationLeavesNoLeaseOrPathKeys() throws Exception {
        try (Fixture f = new Fixture()) {
            when(f.owner.send(any())).thenReturn(CompletableFuture.completedFuture(
                    new SMB2TreeDisconnect(SMB2Dialect.SMB_3_1_1, 47, 7)));
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                for (int iteration = 0; iteration < 100; iteration++) {
                    TreeConnect tree = f.tree(f.owner, "racing", iteration + 10);
                    CountDownLatch start = new CountDownLatch(1);
                    AtomicReference<LeaseKey> allocated = new AtomicReference<>();
                    Future<?> publication = worker.submit(() -> {
                        start.await();
                        try {
                            LeaseKey key = f.manager.leaseKeyForPath(tree, "dir");
                            allocated.set(key);
                            f.manager.register(new LeaseEntry(key, null, SMB2LeaseState.readHandle(), "dir", tree));
                        } catch (IllegalStateException closed) { assertTrue(tree.isClosed()); }
                        return null;
                    });
                    start.countDown(); tree.close(); publication.get(3, TimeUnit.SECONDS);
                    assertNull(f.manager.leaseKeyForExistingPath(tree, "dir"));
                    if (allocated.get() != null) assertNull(f.manager.lookup(allocated.get()));
                    assertThrows(IllegalStateException.class, () -> f.manager.leaseKeyForPath(tree, "later"));
                }
                assertSame(f.entry, f.manager.lookup(f.entry.getLeaseKey()));
            } finally {
                worker.shutdownNow(); assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS));
            }
        }
    }

    private static class Fixture implements AutoCloseable {
        final LeaseManager manager = new LeaseManager();
        final Connection connection = mock(Connection.class);
        final ConnectionContext context = mock(ConnectionContext.class);
        final SmbConfig config = SmbConfig.createDefaultConfig();
        final Session owner;
        final TreeConnect source;
        final LeaseEntry entry;
        final List<FileIdBothDirectoryInformation> listing = Collections.singletonList(mock(FileIdBothDirectoryInformation.class));

        Fixture() {
            when(connection.getLeaseManager()).thenReturn(manager);
            when(connection.getConnectionContext()).thenReturn(context);
            when(context.supportsDirectoryLeasing()).thenReturn(true);
            when(context.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(
                    SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
            owner = session(47); source = tree(owner, "share", 7); entry = entry(source, "dir");
            entry.getCache().populate("dir", FileIdBothDirectoryInformation.class, null, listing);
        }

        Session session(long id) {
            Session result = mock(Session.class);
            when(result.getConnection()).thenReturn(connection);
            when(result.getLeaseManager()).thenReturn(manager);
            when(result.getSessionId()).thenReturn(id);
            when(result.getChannelCount()).thenReturn(1);
            return result;
        }

        TreeConnect tree(Session session, String share, long id) {
            return new TreeConnect(id, new SmbPath("peer", share), session, Collections.emptySet(),
                    config, context, new SMBEventBus(), Collections.emptySet(), Collections.emptySet());
        }

        DiskShare share(TreeConnect tree) {
            return spy(new DiskShare(new SmbPath("peer", tree.getShareName()), tree, null));
        }

        LeaseEntry entry(TreeConnect tree, String path) {
            LeaseEntry result = new LeaseEntry(manager.leaseKeyForPath(tree, path), null, SMB2LeaseState.readHandle(), path, tree);
            result.setGranted(true); result.setGrantedState(SMB2LeaseState.readHandle());
            manager.register(result);
            return result;
        }

        @Override public void close() { manager.close(); }
    }
}
