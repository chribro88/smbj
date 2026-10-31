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
package com.hierynomus.smbj.session;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2CreateRequest;
import com.hierynomus.mssmb2.messages.SMB2Logoff;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectRequest;
import com.hierynomus.mssmb2.messages.SMB2TreeConnectResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.PacketEncryptor;
import com.hierynomus.smbj.connection.Signatory;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.event.TreeDisconnected;
import com.hierynomus.smbj.paths.PathResolveException;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.share.*;
import net.engio.mbassy.listener.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.lang.String.format;

/**
 * A Session
 */
public class Session implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(Session.class);
    private long sessionId;

    private final Connection connection;
    private final com.hierynomus.smbj.connection.LeaseManager leaseManager = new com.hierynomus.smbj.connection.LeaseManager();
    private final SmbConfig config;
    private SMBEventBus bus;
    private final PathResolver pathResolver;
    private Signatory signatory;
    private PacketEncryptor encryptor;
    private TreeConnectTable treeConnectTable = new TreeConnectTable();
    private Map<String, Session> nestedSessionsByHost = new HashMap<>();
    private ReentrantReadWriteLock nestedSessionsRwLock = new ReentrantReadWriteLock();
    private AuthenticationContext userCredentials;
    private SessionContext sessionContext;
    // CUSTOM ADDED: one session/tree/open namespace, independent physical channel credits and signing keys.
    private final java.util.concurrent.CopyOnWriteArrayList<Connection> channels = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final java.util.concurrent.ConcurrentMap<Connection, SecretKey> channelKeys = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.atomic.AtomicBoolean channelsFailed = new java.util.concurrent.atomic.AtomicBoolean();
    private final java.util.concurrent.atomic.AtomicInteger nextChannel = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicInteger channelSequence = new java.util.concurrent.atomic.AtomicInteger();
    private volatile boolean multichannel;
    private final java.util.Set<Connection> pendingChannels = new java.util.HashSet<>();
    private boolean closing;
    private volatile boolean closed;

    public Session(Connection connection, SmbConfig config, AuthenticationContext userCredentials, SMBEventBus bus, PathResolver pathResolver, Signatory signatory, PacketEncryptor encryptor) {
        this.connection = connection;
        if (connection != null) {
            channels.add(connection);
        }
        this.config = config;
        this.userCredentials = userCredentials;
        this.bus = bus;
        this.pathResolver = pathResolver;
        this.signatory = signatory;
        this.sessionContext = new SessionContext();
        this.encryptor = encryptor;
        if (bus != null) {
            bus.subscribe(this);
        }
    }

    public long getSessionId() {
        return sessionId;
    }

    public void setSessionId(long sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * Connect to a share on the remote machine over the authenticated session.
     * <p/>
     * [MS-SMB2] 3.2.4.2 Application Requests a Connection to a Share
     * [MS-SMB2] 3.2.4.2.4 Connecting to the Share
     * [MS-SMB2] 3.2.5.5 Receiving an SMB2 TREE_CONNECT Response
     *
     * @param shareName The name of the share to connect to.
     * @return the handle to the connected share.
     */
    public Share connectShare(String shareName) {
        if (shareName.contains("\\")) {
            throw new IllegalArgumentException(format("Share name (%s) cannot contain '\\' characters.", shareName));
        }
        Share connectedShare = treeConnectTable.getTreeConnect(shareName);
        if (connectedShare != null) {
            logger.debug("Returning cached Share {} for {}", connectedShare, shareName);
            return connectedShare;
        } else {
            return connectTree(shareName);
        }
    }

    private Share connectTree(final String shareName) {
        String remoteHostname = connection.getRemoteHostname();
        final SmbPath smbPath = new SmbPath(remoteHostname, shareName);
        logger.info("Connecting to {} on session {}", smbPath, sessionId);
        try {
            SMB2TreeConnectRequest smb2TreeConnectRequest = new SMB2TreeConnectRequest(connection.getNegotiatedProtocol().getDialect(), smbPath, sessionId);
            smb2TreeConnectRequest.getHeader().setCreditRequest(256);
            Future<SMB2TreeConnectResponse> send = this.send(smb2TreeConnectRequest);
            SMB2TreeConnectResponse response = Futures.get(send, config.getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
            try {
                Share share = pathResolver.resolve(this, response, smbPath, new PathResolver.ResolveAction<Share>() {
                    @Override
                    public Share apply(SmbPath target) {
                        Session session = Session.this;
                        if (!target.isOnSameHost(smbPath)) {
                            logger.info("Re-routing the connection to host {}", target.getHostname());
                            session = getNestedSession(target);
                        }
                        if (!target.isOnSameShare(smbPath)) {
                            return session.connectShare(target.getShareName());
                        }
                        return null;
                    }
                });

                if (share != null) {
                    return share;
                }
            } catch (PathResolveException ignored) {
                // Ignored
            }

            if (NtStatus.isError(response.getHeader().getStatusCode())) {
                logger.debug(response.getHeader().toString());
                throw new SMBApiException(response.getHeader(), "Could not connect to " + smbPath);
            }

            if (response.getCapabilities().contains(SMB2ShareCapabilities.SMB2_SHARE_CAP_ASYMMETRIC)) {
                throw new SMBRuntimeException("ASYMMETRIC capability unsupported");
            }

            long treeId = response.getHeader().getTreeId();
            TreeConnect treeConnect = new TreeConnect(treeId, smbPath, this, response.getCapabilities(), config, connection.getConnectionContext(), bus, response.getMaximalAccess(), response.getShareFlags());

            Share share;
            if (response.isDiskShare()) {
                share = new DiskShare(smbPath, treeConnect, pathResolver);
            } else if (response.isNamedPipe()) {
                share = new PipeShare(smbPath, treeConnect);
            } else if (response.isPrinterShare()) {
                share = new PrinterShare(smbPath, treeConnect);
            } else {
                throw new SMBRuntimeException("Unknown ShareType returned in the TREE_CONNECT Response");
            }

            treeConnectTable.register(share);
            return share;
        } catch (TransportException e) {
            throw new SMBRuntimeException(e);
        }
    }

    public Session getNestedSession(SmbPath resolvedSharePath) {
        nestedSessionsRwLock.readLock().lock();
        try {
            final Session existingSession = nestedSessionsByHost.get(resolvedSharePath.getHostname());
            if (existingSession != null) {
                return existingSession;
            }
        } finally {
            nestedSessionsRwLock.readLock().unlock();
        }

        Session session;
        nestedSessionsRwLock.writeLock().lock(); // update to write lock
        try {
            // re-check if other thread created the missing session in the meantime
            session = nestedSessionsByHost.get(resolvedSharePath.getHostname());

            if (session == null) {
                session = createNestedSession(resolvedSharePath);
                nestedSessionsByHost.put(resolvedSharePath.getHostname(), session);
            }
            nestedSessionsRwLock.readLock().lock();
        } finally {
            nestedSessionsRwLock.writeLock().unlock();
        }

        try {
            return session;
        } finally {
            nestedSessionsRwLock.readLock().unlock();
        }
    }

    private Session createNestedSession(SmbPath smbPath) {
        try {
            Connection connection = getConnection().getClient().connect(smbPath.getHostname());
            return connection.authenticate(getAuthenticationContext());
        } catch (IOException e) {
            throw new SMBApiException(NtStatus.STATUS_OTHER.getValue(), SMB2MessageCommandCode.SMB2_NEGOTIATE,
                "Could not connect to DFS root " + smbPath, e);
        }
    }

    @Handler
    @SuppressWarnings("unused")
    private void disconnectTree(TreeDisconnected disconnectEvent) {
        if (disconnectEvent.getSessionId() == sessionId) {
            logger.debug("Notified of TreeDisconnected <<{}>>", disconnectEvent.getTreeId());
            treeConnectTable.closed(disconnectEvent.getTreeId());
        }
    }

    public void logoff() throws TransportException {
        try {
            leaseManager.close();
            logger.info("Logging off session {} from host {}", sessionId, connection.getRemoteHostname());
            for (Share share : treeConnectTable.getOpenTreeConnects()) {
                try {
                    share.close();
                } catch (IOException e) {
                    logger.error("Caught exception while closing TreeConnect with id: {}", share.getTreeConnect().getTreeId(), e);
                }
            }

            nestedSessionsRwLock.writeLock().lock();
            try {
                for (Session nestedSession : nestedSessionsByHost.values()) {
                    logger.info("Logging off nested session {} for session {}", nestedSession.getSessionId(), sessionId);
                    try {
                        nestedSession.logoff();
                    } catch (TransportException te) {
                        logger.error("Caught exception while logging off nested session {}", nestedSession.getSessionId());
                    }
                }
            } finally {
                nestedSessionsRwLock.writeLock().unlock();
            }
            SMB2Logoff logoff = new SMB2Logoff(connection.getNegotiatedProtocol().getDialect(), sessionId);
            SMB2Logoff response = Futures.get(this.<SMB2Logoff>send(logoff), config.getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
            if (!NtStatus.isSuccess(response.getHeader().getStatusCode())) {
                throw new SMBApiException(response.getHeader(), "Could not logoff session <<" + sessionId + ">>");
            }
        } finally {
            bus.publish(new SessionLoggedOff(sessionId));
        }
    }

    public boolean isSigningRequired() {
        return sessionContext.isSigningRequired();
    }

    public boolean isGuest() {
        return sessionContext.isGuest();
    }

    public boolean isAnonymous() {
        return sessionContext.isAnonymous();
    }

    @Override
    public void close() throws IOException {
        java.util.List<Connection> pending;
        synchronized (channels) {
            if (closing) {
                return;
            }
            closing = true;
            pending = new java.util.ArrayList<>(pendingChannels);
            pendingChannels.removeIf(channel -> channel.getOwningSession() == this);
        }
        // Close pending transports before LOGOFF so authentication cannot publish a late channel.
        for (Connection channel : pending) {
            if (channel.getOwningSession() != this) {
                continue;
            }
            try {
                channel.close(true);
            } catch (IOException failure) {
                logger.warn("Could not close pending SMB channel", failure);
            }
        }
        try {
            logoff();
        } finally {
            for (Connection channel : channels) {
                if (channel != connection && channel.getOwningSession() == this) {
                    try {
                        channel.close(true);
                    } catch (IOException e) {
                        logger.warn("Could not close bound SMB channel", e);
                    }
                }
            }
            synchronized (channels) {
                closed = true;
                channels.clear();
                channelKeys.clear();
            }
            leaseManager.abort();
            if (bus != null) {
                bus.unsubscribe(this);
            }
        }
    }

    /** Checks that a channel can carry the requests sized by this session's existing and future Shares. */
    public void validateChannelLimits(com.hierynomus.smbj.connection.NegotiatedProtocol candidate) throws IOException {
        com.hierynomus.smbj.connection.NegotiatedProtocol original = connection.getNegotiatedProtocol();
        if (candidate.getMaxReadSize() < Math.min(config.getReadBufferSize(), original.getMaxReadSize())
                || candidate.getMaxWriteSize() < Math.min(config.getWriteBufferSize(), original.getMaxWriteSize())
                || candidate.getMaxTransactSize() < Math.min(config.getTransactBufferSize(), original.getMaxTransactSize())) {
            throw new IOException("SMB channel read/write/transaction limits cannot support the established session");
        }
    }

    public Connection getConnection() {
        return connection;
    }

    public com.hierynomus.smbj.connection.LeaseManager getLeaseManager() {
        return leaseManager;
    }

    /**
     * send a packet.  The packet will be signed or not depending on the session's flags.
     *
     * @param packet SMBPacket to send
     * @return a Future to be used to retrieve the response packet
     * @throws TransportException
     */
    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet) throws TransportException {
        return send(packet, selectChannel());
    }

    Connection selectChannel() throws TransportException {
        Connection selected;
        synchronized (channels) {
            selected = connection;
            if (multichannel) {
                retireClosedChannels();
                if (channels.isEmpty()) {
                    throw new TransportException("No authenticated SMB channels remain connected");
                }
                selected = channels.get(Math.floorMod(nextChannel.getAndIncrement(), channels.size()));
            }
        }
        return selected;
    }

    // CUSTOM ADDED: CANCEL must use the connection that allocated its MessageId.
    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet, Connection selected) throws TransportException {
        if (closed || channelsFailed.get()) {
            throw new TransportException("SMB session was invalidated after an uncertain write");
        }
        if (selected != connection && !channelKeys.containsKey(selected)) {
            throw new TransportException("Connection is not an authenticated channel of this session");
        }
        if (multichannel && selected.isClosed()) {
            throw new TransportException("Selected SMB channel is disconnected");
        }
        packet.getHeader().setChannelSequence(channelSequence.get() & 0xFFFF);
        SecretKey signingKey = getSigningKey(packet.getHeader(), true, selected);
        if (sessionContext.isSigningRequired() && signingKey == null) {
            throw new TransportException("Message signing is required, but no signing key is negotiated");
        }

        if (shouldEncryptData()) {
            return selected.send(encryptor.encrypt(packet, sessionContext.getEncryptionKey()));
        }

        if (!config.isOptionalWriteSigning() && !sessionContext.isSigningRequired()
                && packet.getHeader().getMessage() == com.hierynomus.mssmb2.SMB2MessageCommandCode.SMB2_WRITE) {
            return selected.send(packet);
        }
        return selected.send(signatory.sign(packet, signingKey));
    }

    /**
     * Sends a packet, optionally requiring encryption with this session's encryption key.
     *
     * @param packet SMBPacket to send
     * @param encrypt true to require encryption, false to use the session's normal send behaviour
     * @return a Future to be used to retrieve the response packet
     * @throws TransportException if encryption is required but no encryption key is available,
     *                           or a transport level error occurs
     */
    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet, boolean encrypt) throws TransportException {
        if (!encrypt) {
            return send(packet);
        }

        SecretKey encryptionKey = sessionContext.getEncryptionKey();
        if (encryptionKey == null) {
            throw new TransportException("Message encryption is required, but no encryption key is negotiated");
        }

        return connection.send(encryptor.encrypt(packet, encryptionKey));
    }

    public <T extends SMB2Packet> T processSendResponse(SMB2CreateRequest packet) throws TransportException {
        Future<T> responseFuture = send(packet);
        return Futures.get(responseFuture, SMBRuntimeException.Wrapper);
    }

    /**
     * If Connection.Dialect belongs to the SMB 3.x dialect family, and the received message is an SMB2 SESSION_SETUP
     * Response without a status code equal to STATUS_SUCCESS in the header, the client MUST verify the signature of
     * the message as specified in section 3.1.5.1, using Session.SigningKey as the signing key, and passing the
     * response message.
     * For all other messages, the client MUST look up the Channel in Session.ChannelList, where the Channel.Connection
     * matches the connection on which this message is received, and MUST use Channel.SigningKey for verifying the
     * signature as specified in section 3.1.5.1.
     *
     *  Otherwise, the client MUST verify the signature of the message as specified in section 3.1.5.1,
     * using Session.SessionKey as the signing key, and passing the response message.
     *
     *
     * @param signing If true, check for signing mode, else get for verification mode
     * @return
     */
    public void addChannel(Connection channel, SecretKey key) {
        if (channel.isClosed() || !channel.isConnected()) {
            throw new IllegalStateException("SMB channel disconnected before binding completed");
        }
        synchronized (channels) {
            if (closing || channelsFailed.get() || channel.isClosed()) {
                throw new IllegalStateException("SMB session or candidate channel is closing or closed");
            }
            channelKeys.put(channel, key);
            channels.addIfAbsent(channel);
            multichannel = true;
        }
    }

    public boolean beginBinding(Connection channel) throws IOException {
        synchronized (channels) {
            if (closing || channelsFailed.get() || (multichannel && getChannelCount() == 0)) {
                throw new IOException("SMB session is closing or has no surviving channels");
            }
            return pendingChannels.add(channel);
        }
    }

    public void endBinding(Connection channel) {
        synchronized (channels) {
            pendingChannels.remove(channel);
        }
    }

    public boolean isBindingInProgress(Connection channel) {
        synchronized (channels) {
            return pendingChannels.contains(channel) && !channels.contains(channel);
        }
    }

    // Like go-smb2 sessionChannels, retire transports without replaying their outstanding requests.
    private void retireClosedChannels() {
        for (int i = channels.size() - 1; i >= 0; i--) {
            Connection channel = channels.get(i);
            if (channel.isClosed()) {
                channels.remove(i);
                channelKeys.remove(channel);
                channelSequence.incrementAndGet();
            }
        }
        if (channels.isEmpty()) {
            channelsFailed.set(true);
            leaseManager.abort();
        }
    }

    @Handler
    private void channelClosed(com.hierynomus.smbj.event.ConnectionClosed event) {
        synchronized (channels) {
            if (channels.remove(event.getConnection())) {
                channelKeys.remove(event.getConnection());
                channelSequence.incrementAndGet();
            }
            if (channels.isEmpty()) {
                channelsFailed.set(true);
                leaseManager.abort();
            }
        }
    }

    // CUSTOM ADDED: abandon an uncertain write generation and release every outstanding request.
    public void failChannels(Throwable failure) {
        if (!channelsFailed.compareAndSet(false, true)) {
            return;
        }
        for (Connection channel : channels) {
            channel.handleError(failure);
        }
    }

    public int getChannelCount() {
        synchronized (channels) {
            if (multichannel) {
                retireClosedChannels();
            }
            return channels.size();
        }
    }

    public SecretKey getSigningKey(SMB2PacketHeader header, boolean signing) {
        return getSigningKey(header, signing, connection);
    }

    public SecretKey getSigningKey(SMB2PacketHeader header, boolean signing, Connection receivingConnection) {
        if (connection.getNegotiatedProtocol().getDialect().isSmb3x()) {
            if (header.getMessage() == SMB2MessageCommandCode.SMB2_SESSION_SETUP) {
                if (signing) {
                    return sessionContext.getSigningKey();
                }
                if (header.getStatusCode() != NtStatus.STATUS_SUCCESS.getValue()) {
                    return sessionContext.getSigningKey();
                }
            }
            SecretKey channelKey = receivingConnection == null ? null : channelKeys.get(receivingConnection);
            return channelKey == null ? sessionContext.getSigningKey() : channelKey;
        }

        return sessionContext.getSessionKey();
    }

    /**
     * Returns whether packets for this session should be encrypted.
     *
     * @return
     * @throws TransportException When encryption is required and encryption key is missing.
     */
    public boolean shouldEncryptData() throws TransportException {
        if (sessionContext.isEncryptData() && sessionContext.getEncryptionKey() == null) {
            throw new TransportException("Message encryption is required, but no encryption key is negotiated");
        }

        boolean encryptData = sessionContext.isEncryptData();
        encryptData |= (sessionContext.getEncryptionKey() != null && connection.getConnectionContext().clientPrefersEncryption());

        return encryptData;
    }

    public SessionContext getSessionContext() {
        return sessionContext;
    }

    public AuthenticationContext getAuthenticationContext() {
        return userCredentials;
    }
}
