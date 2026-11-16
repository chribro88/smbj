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

import static com.hierynomus.mssmb2.SMB2Packet.SINGLE_CREDIT_PAYLOAD_SIZE;
import static java.lang.String.format;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongPredicate;

import com.hierynomus.mssmb.SMB1PacketFactory;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2Cancel;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.concurrent.CancellableFuture;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.protocol.transport.PacketFactory;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.PacketReceiver;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.Pooled;
import com.hierynomus.smbj.connection.packet.DeadLetterPacketHandler;
import com.hierynomus.smbj.connection.packet.IncomingPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB1PacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2AsyncResponsePacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2CompoundedPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2CreditGrantingPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2LeaseBreakPacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2ProcessResponsePacketHandler;
import com.hierynomus.smbj.connection.packet.SMB3DecryptingPacketHandler;
import com.hierynomus.smbj.event.ConnectionClosed;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.paths.DFSPathResolver;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.paths.SymlinkPathResolver;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.engio.mbassy.listener.Handler;

/**
 * A connection to a server.
 */
public class Connection extends Pooled<Connection> implements Closeable, PacketReceiver<SMBPacketData<?>> {
    private static final int MAX_COLLISION_PROBES = 32;
    private static final Logger logger = LoggerFactory.getLogger(Connection.class);
    private static final DelegatingSMBMessageConverter converter = new DelegatingSMBMessageConverter(new SMB3EncryptedPacketFactory(), new SMB3CompressedPacketFactory(), new SMB2PacketFactory(), new SMB1PacketFactory());
    private IncomingPacketHandler packetHandlerChain;

    private ConnectionContext connectionContext;
    private InetSocketAddress remoteAddress;
    private final LeaseManager leaseManager = new LeaseManager();
    private SessionTable sessionTable = new SessionTable();
    private SessionTable preauthSessionTable = new SessionTable();
    OutstandingRequests outstandingRequests = new OutstandingRequests();
    SequenceWindow sequenceWindow;
    private SMB2MessageConverter messageConverter = new SMB2MessageConverter();
    private PathResolver pathResolver;

    private final SMBClient client;
    private final Session owningSession;
    final ServerList serverList;

    private final java.util.concurrent.atomic.AtomicLong writeRequests = new java.util.concurrent.atomic.AtomicLong();
    private Signatory signatory;
    private PacketEncryptor encryptor;

    public SMBClient getClient() {
        return client;
    }

    private SmbConfig config;
    TransportLayer<SMBPacket<?, ?>> transport;
    private final SMBEventBus bus;
    private final ReentrantLock lock = new ReentrantLock();
    private final AtomicReference<TransportException> error = new AtomicReference<>();
    private final AtomicBoolean closingGracefully = new AtomicBoolean();

    private final CountDownLatch teardownComplete = new CountDownLatch(1);
    private volatile Thread teardownThread;
    private volatile IOException teardownFailure;

    public Connection(SmbConfig config, SMBClient client, SMBEventBus bus, ServerList serverList) {
        this(config, client, bus, serverList, null);
    }

    /** Create an exclusively session-owned channel, or a caller-owned connection when owner is null. */
    public Connection(SmbConfig config, SMBClient client, SMBEventBus bus, ServerList serverList, Session owningSession) {
        this.config = config;
        this.client = client;
        this.owningSession = owningSession;
        this.transport = config.getTransportLayerFactory().createTransportLayer(new PacketHandlers<>(new SMBPacketSerializer(), this, converter), config);
        this.bus = bus;
        this.serverList = serverList;
        init();
    }

    private void init() {
        bus.subscribe(this);
        this.sequenceWindow = new SequenceWindow();
        if (config.isSigningEnabled()) {
            this.signatory = new PacketSignatory(config.getSecurityProvider());
        } else {
            logger.warn("Signing is disabled for this connection.");
            this.signatory = new NoSignatory();
        }
        this.encryptor = new PacketEncryptor(config.getSecurityProvider());

        this.packetHandlerChain = new SMB3DecryptingPacketHandler(sessionTable, encryptor).setNext(
            new SMB2CompoundedPacketHandler(outstandingRequests, sessionTable, signatory, this).setNext(
                new SMB2LeaseBreakPacketHandler(leaseManager, sessionTable).setNext(
                    new SMB2CreditGrantingPacketHandler(sequenceWindow).setNext(
                        new SMB2AsyncResponsePacketHandler(outstandingRequests).setNext(
                            new SMB2ProcessResponsePacketHandler(messageConverter, outstandingRequests).setNext(
                                new SMB1PacketHandler().setNext(new DeadLetterPacketHandler())))))));
    }

    public Connection(Connection connection) {
        this.client = connection.client;
        this.owningSession = connection.owningSession;
        this.config = connection.config;
        this.transport = connection.transport;
        this.bus = connection.bus;
        this.serverList = connection.serverList;
        init();
    }

    public void connect(String hostname, int port) throws IOException {
        connect(hostname, new InetSocketAddress(hostname, port));
    }

    // preserve the authentication hostname while selecting another server interface.
    public void connect(String hostname, InetSocketAddress address) throws IOException {
        final int port = address.getPort();
        if (isConnected()) {
            throw new IllegalStateException(format("This connection is already connected to %s", getRemoteHostname()));
        }
        TransportException failure = error.get();
        if (failure != null) {
            throw failure;
        }
        this.connectionContext = new ConnectionContext(config.getClientGuid(), hostname, port, config);
        this.remoteAddress = address;
        try {
            transport.connect(address);
            failure = error.get();
            if (failure != null) {
                // An abort can win before the transport has opened its socket.
                transport.disconnect();
                throw failure;
            }
            new SMBProtocolNegotiator(this, config, connectionContext).negotiateDialect();
            this.encryptor.init(connectionContext);

            this.pathResolver = new SymlinkPathResolver(PathResolver.LOCAL);
            if (config.isDfsEnabled() && connectionContext.supportsDFS()) {
                this.pathResolver = new DFSPathResolver(pathResolver, config.getTransactTimeout());
            }
        } catch (IOException | RuntimeException e) {
            handleError(e);
            throw e;
        }

        logger.info("Successfully connected to: {}", getRemoteHostname());
    }

    @Override
    public void close() throws IOException {
        close(false);
    }

    /**
     * Close the Connection. If {@code force} is set to true, it forgoes the
     * {@link Session#close()} operation on the open sessions, fails outstanding
     * requests and credit waiters, and disconnects the transport. Subsequent sends
     * fail with a {@link TransportException}.
     *
     * <p>
     * If {@code force} is set to false, the usage counter of the connection reduces with one. If the usage count drops to zero the connection will be closed.
     * </p>
     *
     * <p>
     * Closing is idempotent: once the connection is closed, further calls do not touch the transport again and do not
     * publish another {@link ConnectionClosed} event.
     * </p>
     *
     * @param force if set, does not nicely terminate the open sessions.
     * @throws IOException If any error occurred during close-ing.
     */
    public void close(boolean force) throws IOException {
        if (force) {
            try {
                abort(new TransportException("Connection closed"));
            } finally {
                awaitTeardown();
            }
            return;
        }
        if (error.get() != null) {
            awaitTeardown();
            return;
        }
        if (!release()) {
            return;
        }
        if (!closingGracefully.compareAndSet(false, true)) {
            awaitTeardown();
            return;
        }
        try {
            leaseManager.close();
            for (Session session : sessionTable.activeSessions()) {
                try {
                    session.close();
                } catch (IOException e) {
                    logger.warn("Exception while closing session {}", session.getSessionId(), e);
                }
            }
        } finally {
            try {
                abort(new TransportException("Connection closed"));
            } finally {
                awaitTeardown();
            }
        }
    }

    private void abort(TransportException failure) throws IOException {
        if (!error.compareAndSet(null, failure)) {
            return;
        }
        teardownThread = Thread.currentThread();
        try {
            performTeardown(failure);
        } catch (IOException e) {
            teardownFailure = e;
            throw e;
        } catch (RuntimeException | Error e) {
            teardownFailure = new IOException("Connection teardown failed", e);
            throw e;
        } finally {
            teardownComplete.countDown();
            teardownThread = null;
        }
    }

    private void awaitTeardown() throws IOException {
        // Error callbacks must not wait on another abort. Reentrant close on the
        // teardown thread cannot wait for itself either.
        if (Thread.currentThread() == teardownThread) {
            return;
        }
        boolean interrupted = false;
        try {
            while (true) {
                try {
                    teardownComplete.await();
                    break;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
        if (teardownFailure != null) throw teardownFailure;
    }

    private void performTeardown(TransportException failure) throws IOException {
        // Neither of these operations takes Connection.lock: a sender may hold it
        // while waiting for credits. Registration shares the request table's lock
        // with handleError, so a racing request is either drained or rejected.
        sequenceWindow.handleError(failure);
        outstandingRequests.handleError(failure);
        try {
            transport.disconnect();
        } finally {
            try {
                closeLeaseManagerIfUnused();
            } finally {
                bus.unsubscribe(this);
                if (connectionContext != null) {
                    logger.info("Closed connection to {}", getRemoteHostname());
                    bus.publish(new ConnectionClosed(connectionContext.getServer().getServerName(), connectionContext.getServer().getPort(), this));
                }
            }
        }
    }

    /**
     * Authenticate the user on this connection in order to start a (new) session.
     *
     * @return a (new) Session that is authenticated for the user.
     */
    public Session authenticate(AuthenticationContext authContext) {
        if (client != null && config.isSigningEnabled()
                && connectionContext.getSigningAlgorithm() == SMB3SigningAlgorithm.AES_GMAC
                && connectionContext.getServerCapabilities().contains(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL)) {
            try {
                return authenticateWithBootstrap(authContext);
            } catch (IOException failure) {
                throw new com.hierynomus.smbj.common.SMBRuntimeException(failure);
            }
        }
        return authenticateDirect(authContext);
    }

    private Session authenticateWithBootstrap(AuthenticationContext authContext) throws IOException {
        Connection bootstrap = new Connection(config, client, bus, serverList);
        Session session = null;
        Throwable primary = null;
        try {
            client.registerBootstrapConnection(bootstrap);
            bootstrap.connect(getRemoteHostname(), remoteAddress);
            session = bootstrap.authenticateDirect(authContext);
            session.prepareBootstrapChannel(this);
            bind(session);
            client.publishBootstrapChannel(session, bootstrap, this);
            bootstrap.close(true);
            return session;
        } catch (IOException | RuntimeException | Error failure) {
            primary = failure;
            if (session != null) {
                cleanupFailedBootstrap(session, bootstrap, failure);
            }
            throw failure;
        } finally {
            try { bootstrap.close(true); }
            catch (IOException cleanup) {
                if (primary == null) throw cleanup;
                if (cleanup != primary) primary.addSuppressed(cleanup);
            } finally {
                if (session != null) bootstrap.sessionTable.removeSession(session.getSessionId(), session);
                client.releaseBootstrapConnection(bootstrap);
            }
        }
    }

    private void cleanupFailedBootstrap(Session session, Connection bootstrap, Throwable failure) {
        Connection cleanupChannel = null;
        try {
            // After bind() unwinds, the caller retains the target only if its channel
            // was verified. Otherwise recover once if the private root died.
            if (!(failure instanceof Error) && session.getConnection() == bootstrap
                    && bootstrap.isClosed() && !isSessionEstablished(session) && isConnected()) {
                cleanupChannel = new Connection(config, client, bus, serverList);
                client.registerBootstrapConnection(cleanupChannel);
                cleanupChannel.connect(getRemoteHostname(), remoteAddress);
                cleanupChannel.bind(session, true);
            }
        } catch (IOException | RuntimeException cleanup) {
            if (cleanup != failure) failure.addSuppressed(cleanup);
        } finally {
            try {
                try { session.close(); }
                catch (IOException | RuntimeException cleanup) { if (cleanup != failure) failure.addSuppressed(cleanup); }
            } finally {
                if (cleanupChannel != null) {
                    try { cleanupChannel.close(true); }
                    catch (IOException | RuntimeException cleanup) { if (cleanup != failure) failure.addSuppressed(cleanup); }
                    finally {
                        cleanupChannel.sessionTable.removeSession(session.getSessionId(), session);
                        client.releaseBootstrapConnection(cleanupChannel);
                    }
                }
            }
        }
    }

    private Session authenticateDirect(AuthenticationContext authContext) {
        return new SMBSessionBuilder(this, config, new SMBSessionBuilder.SessionFactory() {
            @Override
            public Session createSession(AuthenticationContext context) {
                return new Session(Connection.this, config, context, bus, pathResolver, signatory, encryptor);
            }
        }).establish(authContext);
    }

    // bind this independent physical connection to an existing logical session.
    public Session bind(Session session) throws IOException {
        return bind(session, false);
    }

    public Session bind(Session session, boolean ownsTransport) throws IOException {
        if (ownsTransport && owningSession != null && owningSession != session) {
            throw new IOException("SMB channel belongs to a different session");
        }
        if (sessionTable.find(session.getSessionId()) != null) {
            throw new IOException("Connection already contains this SMB session");
        }
        SMBSessionBuilder builder = new SMBSessionBuilder(this, config, null);
        builder.validateBinding(session);
        boolean registered = session.beginBinding(this, ownsTransport);
        try {
            boolean gmac = connectionContext.getSigningAlgorithm() == SMB3SigningAlgorithm.AES_GMAC;
            // A real authenticated session keeps the connection eligible for collision ECHOs.
            Session auxiliary = gmac ? authenticateDirect(session.getAuthenticationContext()) : null;
            try {
                return builder.bind(session, signatory, ownsTransport, auxiliary);
            } catch (IOException | RuntimeException | Error failure) {
                // Successful binding closes the auxiliary before publication. A failed
                // send and its cleanup can throw the same cached connection error.
                if (auxiliary != null) {
                    try { auxiliary.close(); }
                    catch (IOException | RuntimeException | Error cleanup) {
                        if (cleanup != failure) failure.addSuppressed(cleanup);
                    }
                }
                throw failure;
            }
        } catch (com.hierynomus.smbj.common.SMBRuntimeException failure) {
            if (failure.getCause() instanceof IOException) {
                throw new IOException("SMB auxiliary authentication failed", failure);
            }
            throw failure;
        } finally {
            if (registered) {
                session.endBinding(this);
            }
        }
    }

    boolean hasIndependentSigningSession(Session target) {
        javax.crypto.SecretKey original = target.getSessionContext().getSigningKey();
        if (original == null) return false;
        for (Session established : sessionTable.activeSessions()) {
            javax.crypto.SecretKey key = established.getSessionContext().getSigningKey();
            if (established != target && key != null && !established.isGuest() && !established.isAnonymous()
                    && !java.security.MessageDigest.isEqual(original.getEncoded(), key.getEncoded())) {
                return true;
            }
        }
        return false;
    }

    /**
     * send a packet.
     *
     * @param packet SMBPacket to send
     * @return a Future to be used to retrieve the response packet
     * @throws TransportException When a transport level error occurred
     */
    public <T extends SMB2Packet> Future<T> send(SMB2Packet packet) throws TransportException {
        return send(packet, null);
    }

    public <T extends SMB2Packet> Future<T> sendOriginalKey(SMB2Packet packet, Session session) throws TransportException {
        return send(packet, messageId -> session.reserveOriginalKeyMessageId(this, messageId,
                packet.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_LOGOFF));
    }

    private <T extends SMB2Packet> Future<T> send(SMB2Packet packet, LongPredicate messageIdReservation) throws TransportException {
        List<Request> collisionRequests = null;
        try {
            while (true) {
                checkConnected();
                Future<T> future = null;
                SMB2Packet wirePacket = packet;
                boolean flushCollisions = false;
                if (!(packet.getPacket() instanceof SMB2Cancel)) {
                    // Need to lock around the sequence window calls to ensure no credits get stolen by another thread
                    try {
                        lock.lock();
                        try {
                            checkConnected();
                            int availableCredits = sequenceWindow.available();
                            if (collisionRequests != null && !collisionRequests.isEmpty() && availableCredits <= 1) {
                                // Leave a credit for unrelated traffic when a borrowed connection has several probes in flight.
                                flushCollisions = true;
                            } else {
                                int grantCredits = calculateGrantedCredits(packet, availableCredits);
                                if (availableCredits == 0) {
                                    logger.warn(
                                        "There are no credits left to send {}, will block until there are more credits available.",
                                        packet.getHeader().getMessage());
                                }
                                boolean collision = messageIdReservation != null && !messageIdReservation.test(sequenceWindow.nextMessageId());
                                int allocatedCredits = collision ? 1 : grantCredits;
                                long[] messageIds = sequenceWindow.get(allocatedCredits);
                                packet.getHeader().setMessageId(messageIds[0]);
                                packet.getHeader().setCreditRequest(Math.max(SequenceWindow.PREFERRED_MINIMUM_CREDITS - availableCredits - allocatedCredits,
                                        allocatedCredits));
                                logger.debug("Granted {} (out of {}) credits to {}", allocatedCredits, availableCredits, packet);
                                if (collision) {
                                    SMB2Echo echo = new SMB2Echo(connectionContext.getNegotiatedProtocol().getDialect());
                                    echo.getHeader().setMessageId(messageIds[0]);
                                    echo.getHeader().setCreditRequest(packet.getHeader().getCreditRequest());
                                    echo.setCreditsAssigned(1);
                                    wirePacket = echo;
                                }
                            }
                        } finally {
                            lock.unlock();
                        }
                    } catch (TransportException failure) {
                        handleError(failure);
                        throw failure;
                    }

                    if (flushCollisions) {
                        awaitCollisionRequests(collisionRequests);
                        continue;
                    }
                    if (wirePacket == packet && collisionRequests != null && !collisionRequests.isEmpty()) {
                        // The accepted MID/range is already allocated; another sender cannot consume its reservation while we wait.
                        awaitCollisionRequests(collisionRequests);
                    }
                    Session requestSession = sessionTable.find(wirePacket.getHeader().getSessionId());
                    Request request = new Request(wirePacket, wirePacket.getHeader().getMessageId(), UUID.randomUUID(),
                            requestSession != null && requestSession.isSigningRequired());
                    outstandingRequests.registerOutstanding(request);
                    if (wirePacket == packet) {
                        future = request.getFuture(new CancelRequest(request, packet.getHeader().getSessionId()));
                    } else {
                        if (collisionRequests == null) collisionRequests = new ArrayList<>(MAX_COLLISION_PROBES);
                        collisionRequests.add(request);
                    }
                }
                try {
                    checkConnected();
                    transport.write(wirePacket);
                } catch (TransportException | RuntimeException e) {
                    handleError(e);
                    throw e;
                }
                if (wirePacket != packet) {
                    if (collisionRequests.size() >= MAX_COLLISION_PROBES) awaitCollisionRequests(collisionRequests);
                    continue;
                }
                if (wirePacket.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_WRITE) {
                    writeRequests.incrementAndGet();
                }
                return future;
            }
        } catch (TransportException | RuntimeException | Error failure) {
            if (collisionRequests != null) {
                for (Request request : collisionRequests) {
                    outstandingRequests.remove(request.getMessageId());
                    request.getPromise().deliverError(failure);
                }
            }
            throw failure;
        }
    }

    private void awaitCollisionRequests(List<Request> requests) throws TransportException {
        for (Request request : requests) {
            Futures.get(request.getPromise().future(), config.getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
        }
        requests.clear();
    }

    private void checkConnected() throws TransportException {
        TransportException failure = error.get();
        if (failure != null) {
            throw failure;
        }
        if (!transport.isConnected()) {
            failure = new TransportException("Connection is disconnected");
            handleError(failure);
            throw failure;
        }
    }

    <T extends SMB2Packet> T sendAndReceive(SMB2Packet packet) throws TransportException {
        return sendAndReceive(packet, null);
    }

    <T extends SMB2Packet> T sendAndReceive(SMB2Packet packet, LongPredicate messageIdReservation) throws TransportException {
        return receive(packet, this.<T>send(packet, messageIdReservation));
    }

    <T extends SMB2Packet> T sendAndReceive(Session session, SMB2Packet packet) throws TransportException {
        return receive(packet, session.<T>send(packet, this));
    }

    private <T extends SMB2Packet> T receive(SMB2Packet packet, Future<T> response) throws TransportException {
        try {
            return Futures.get(response, config.getTransactTimeout(), TimeUnit.MILLISECONDS, TransportException.Wrapper);
        } catch (TransportException failure) {
            // A failed authentication or LOGOFF wait cannot consume a late reply.
            if (packet.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_SESSION_SETUP
                    || packet.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_LOGOFF) {
                abandonRequest(packet.getHeader().getMessageId(), failure);
            }
            throw failure;
        }
    }

    /** Release tracking for an exchange whose caller can no longer consume its response. */
    public void abandonRequest(long messageId, Throwable failure) {
        Request abandoned = outstandingRequests.remove(messageId);
        if (abandoned != null) abandoned.getPromise().deliverError(failure);
    }

    void sessionSetupAccepted(com.hierynomus.mssmb2.messages.SMB2SessionSetup response) {
        sequenceWindow.creditsGranted(response.getHeader().getCreditResponse());
    }

    long nextMessageId() {
        return sequenceWindow.nextMessageId();
    }

    private int calculateGrantedCredits(final SMB2Packet packet, final int availableCredits) {
        final int grantCredits;
        int maxPayloadSize = packet.getMaxPayloadSize();
        int creditsNeeded = creditsNeeded(maxPayloadSize);
        if (creditsNeeded > 1 && !connectionContext.supportsMultiCredit()) {
            logger.trace("Connection to {} does not support multi-credit requests.", getRemoteHostname());
            grantCredits = 1;
        } else if (creditsNeeded < availableCredits) { // Scale the credits dynamically
            grantCredits = creditsNeeded;
        } else if (creditsNeeded > 1 && availableCredits > 1) { // creditsNeeded >= availableCredits
            grantCredits = availableCredits - 1; // Keep 1 credit left for a simple request
        } else {
            grantCredits = 1;
        }
        packet.setCreditsAssigned(grantCredits);
        return grantCredits;
    }

    /**
     * [MS-SMB2] 3.1.5.2 Calculating the CreditCharge
     */
    private int creditsNeeded(int payloadSize) {
        return Math.abs((payloadSize - 1) / SINGLE_CREDIT_PAYLOAD_SIZE) + 1;
    }

    /**
     * Returns the negotiated protocol details for this connection.
     *
     * @return The negotiated protocol details
     */
    public NegotiatedProtocol getNegotiatedProtocol() {
        return connectionContext.getNegotiatedProtocol();
    }

    @Override
    public void handle(SMBPacketData<?> uncheckedPacket) throws TransportException {
        try {
            this.packetHandlerChain.handle(uncheckedPacket);
        } catch (TransportException e) {
            handleError(e);
            throw e;
        }
        // [MS-SMB2] 3.2.5.1.6 Handling Session Expiration
        // if (packet.getHeader().getStatus() == NtStatus.STATUS_NETWORK_SESSION_EXPIRED) {
        // TODO reauthenticate session!
        // }

    }


    /**
     * Called when the transport failed, either while reading or while writing. Nothing can be received on a failed
     * transport anymore, so the connection is dead: fail the outstanding requests and close the connection, so that
     * {@link SMBClient} stops handing it out. This does not depend on the number of leases that are still
     * outstanding, and it does not try to log off the sessions over the failed transport.
     */
    @Override
    public void handleError(Throwable t) {
        try {
            abort(TransportException.Wrapper.wrap(t));
        } catch (Exception e) {
            String exceptionClass = e.getClass().getSimpleName();
            logger.debug("{} while closing connection on error, ignoring: {}", exceptionClass, e.getMessage());
        }
    }

    public String getRemoteHostname() {
        return connectionContext.getServer().getServerName();
    }

    public long getWriteRequestCount() {
        return writeRequests.get();
    }

    /** Whether connection teardown has begun, without acquiring transport locks. */
    public boolean isClosed() { return error.get() != null; }

    public boolean isConnected() {
        return error.get() == null && transport.isConnected();
    }

    public ConnectionContext getConnectionContext() {
        return connectionContext;
    }

    public LeaseManager getLeaseManager() {
        return leaseManager;
    }

    public Session getOwningSession() {
        return owningSession;
    }

    /** Release a logical session's leases after its last channel or its owner closes. */
    public void releaseSessionLeases(Session session) {
        if (session.getChannelCount() != 0) return;
        sessionTable.removeSession(session.getSessionId(), session);
        if (session.getConnection() == this) leaseManager.releaseSession(session);
        closeLeaseManagerIfUnused();
    }

    private void closeLeaseManagerIfUnused() {
        if (!isClosed()) return;
        for (Session session : sessionTable.activeSessions()) {
            if (session.getConnection() == this && session.getChannelCount() > 0) return;
        }
        leaseManager.abort();
    }

    @Handler
    @SuppressWarnings("unused")
    private void sessionLogoff(SessionLoggedOff loggedOff) {
        Session session = sessionTable.find(loggedOff.getSessionId());
        if (loggedOff.matchesSession(session)) {
            sessionTable.removeSession(loggedOff.getSessionId(), session);
            if (session.getConnection() == this) leaseManager.releaseSession(session);
            closeLeaseManagerIfUnused();
        }
        logger.debug("Session << {} >> logged off", loggedOff.getSessionId());
    }

    private static class DelegatingSMBMessageConverter implements PacketFactory<SMBPacketData<?>> {
        private PacketFactory<?>[] packetFactories;

        public DelegatingSMBMessageConverter(PacketFactory<?>... packetFactories) {
            this.packetFactories = packetFactories;
        }

        @Override
        public SMBPacketData<?> read(byte[] data) throws Buffer.BufferException, IOException {
            for (PacketFactory<?> packetFactory : packetFactories) {
                if (packetFactory.canHandle(data)) {
                    return (SMBPacketData<?>) packetFactory.read(data);
                }
            }
            throw new IOException("Unknown packet format received.");
        }

        @Override
        public boolean canHandle(byte[] data) {
            for (PacketFactory<?> packetFactory : packetFactories) {
                if (packetFactory.canHandle(data)) {
                    return true;
                }
            }
            return false;
        }
    }

    private class CancelRequest implements CancellableFuture.CancelCallback {
        private Request request;
        private long sessionId;

        public CancelRequest(Request request, long sessionId) {
            this.request = request;
            this.sessionId = sessionId;
        }

        /**
         * [MS-SMB2] 3.2.4.24 Application Requests Canceling an Operation
         *
         * No status is returned to the application for the cancel request.
         */
        @Override
        @SuppressWarnings("FutureReturnValueIgnored")
        public void cancel() {
            SMB2Cancel cancel = request.newCancel(connectionContext.getNegotiatedProtocol().getDialect(), sessionId);
            if (cancel == null) {
                return;
            }
            try {
                Session session = sessionTable.find(sessionId);
                if (request.isEncrypted()) {
                    session.send(cancel, Connection.this, true);
                } else {
                    session.send(cancel, Connection.this);
                }
            } catch (TransportException e) {
                logger.error("Failed to send {}", cancel);
            }
        }
    }

    public boolean isSessionEstablished(Session session) {
        return sessionTable.find(session.getSessionId()) == session;
    }

    SessionTable getSessionTable() {
        return sessionTable;
    }

    SessionTable getPreauthSessionTable() {
        return preauthSessionTable;
    }

    public void setMessageConverter(SMB2MessageConverter smb2Converter) {
        this.messageConverter = smb2Converter;
    }
}
