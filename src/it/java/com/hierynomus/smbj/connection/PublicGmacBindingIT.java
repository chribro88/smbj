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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Timeout(60)
class PublicGmacBindingIT {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void publicBindingReplacementAndBorrowedSessionPreserveTheOpen(boolean borrowed) throws Exception {
        String portValue = System.getenv("SMB_TEST_PORTS");
        assumeTrue(portValue != null, "Dedicated GMAC fixture required");
        int port = Integer.parseInt(portValue);
        GmacBindingWireObserver observer = new GmacBindingWireObserver();
        Map<Long, byte[]> actualKeys = new ConcurrentHashMap<>();
        AtomicLong mainSession = new AtomicLong();
        AtomicInteger bindingStarts = new AtomicInteger();
        CountDownLatch concurrentBindings = new CountDownLatch(2);
        Field keyField = PacketSignatory.SignedPacketWrapper.class.getDeclaredField("secretKey");
        keyField.setAccessible(true);
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
                .withAuthenticators(new NtlmAuthenticator.Factory()).withSecurityProvider(new BCSecurityProvider())
                .withSocketFactory(observer).withTimeout(10, TimeUnit.SECONDS)
                .withTransportLayerFactory((handlers, settings) -> {
                    TransportLayer<SMBPacket<?, ?>> delegate = new DirectTcpTransport<>(
                            settings.getSocketFactory(), settings.getSoTimeout(), handlers);
                    return new TransportLayer<SMBPacket<?, ?>>() {
                        public void connect(InetSocketAddress address) throws IOException { delegate.connect(address); }
                        public void disconnect() throws IOException { delegate.disconnect(); }
                        public boolean isConnected() { return delegate.isConnected(); }
                        public void write(SMBPacket<?, ?> packet) throws TransportException {
                            if (packet instanceof PacketSignatory.SignedPacketWrapper) {
                                try {
                                    SecretKey key = (SecretKey) keyField.get(packet);
                                    actualKeys.putIfAbsent(((SMB2Packet) packet).getHeader().getSessionId(), key.getEncoded().clone());
                                } catch (IllegalAccessException failure) { throw new AssertionError(failure); }
                            }
                            SMB2Packet smb = (SMB2Packet) packet;
                            if (smb.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_SESSION_SETUP
                                    && mainSession.get() != 0 && smb.getHeader().getSessionId() == mainSession.get()
                                    && bindingStarts.getAndIncrement() < 2) {
                                concurrentBindings.countDown();
                                try { assertTrue(concurrentBindings.await(5, TimeUnit.SECONDS)); }
                                catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new AssertionError(failure); }
                            }
                            delegate.write(packet);
                        }
                    };
                }).build();
        SMBEventBus bus = new SMBEventBus();
        String run = borrowed ? "borrowed" : "owned";
        Connection shared = null;
        try (SMBClient client = new SMBClient(config, bus)) {
            Connection primary = client.connect("127.0.0.1", port); observer.register(primary);
            try (Session prior = borrowed ? primary.authenticate(authentication()) : null) {
                if (prior != null) {
                    observer.auxiliary(prior, primary);
                    for (int i = 0; i < 1024; i++) echo(prior);
                }
            try (Session main = primary.authenticate(authentication())) {
                observer.original(main, primary);
                observer.bound(main, primary);
                assertSame(primary, main.getConnection());
                mainSession.set(main.getSessionId());
                if (borrowed) for (int i = 0; i < 1024; i++) echo(main);
                int initialCatchUp = observer.unsignedEchoRequests();
                assertSame(client, main.getConnection().getClient());
                try (Connection lease = client.connect("127.0.0.1", port)) { assertSame(primary, lease); }
                assertEquals(SMB3SigningAlgorithm.AES_GMAC, primary.getConnectionContext().getSigningAlgorithm());
                Session older = null;
                Connection replacement;
                Connection companion;
                try (DiskShare share = (DiskShare) main.connectShare("share")) {
                    String name = "public-gmac-" + UUID.randomUUID() + ".bin";
                    try (File file = share.openFile(name, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
                            SMB2CreateDisposition.FILE_CREATE, EnumSet.noneOf(SMB2CreateOptions.class))) {
                        byte[] expected = new byte[131077]; new Random(51).nextBytes(expected);
                        verifyContents(file, expected);
                        Connection first;
                        ExecutorService workers = Executors.newFixedThreadPool(2);
                        try {
                            java.util.concurrent.Callable<Connection> bind = () -> {
                                Connection channel = client.openChannel(main, "127.0.0.1", port);
                                observer.register(channel); observer.bound(main, channel);
                                return channel;
                            };
                            Future<Connection> one = workers.submit(bind), two = workers.submit(bind);
                            first = one.get(15, TimeUnit.SECONDS); companion = two.get(15, TimeUnit.SECONDS);
                        } finally {
                            workers.shutdownNow(); assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
                        }
                        assertEquals(3, main.getChannelCount());
                        assertEquals(1, first.getSessionTable().activeSessions().size(), "Auxiliary session is logged off");
                        expected[0] ^= 1; verifyContents(file, expected);
                        if (borrowed) {
                            shared = new Connection(config, client, bus, client.getServerList());
                            shared.connect("127.0.0.1", port); observer.register(shared);
                            older = shared.authenticate(authentication()); observer.auxiliary(older, shared);
                            assertSame(main, shared.bind(main)); observer.bound(main, shared);
                            assertEquals(2, shared.getSessionTable().activeSessions().size());
                            expected[1] ^= 1; verifyContents(file, expected);
                        }
                        first.close(true);
                        replacement = client.openChannel(main, "127.0.0.1", port);
                        observer.register(replacement); observer.bound(main, replacement);
                        assertEquals(borrowed ? 4 : 3, main.getChannelCount());
                        expected[2] ^= 1; verifyContents(file, expected);
                    } finally { share.rm(name); }
                }
                main.close();
                assertTrue(replacement.isClosed());
                assertTrue(companion.isClosed());
                assertTrue(primary.isConnected());
                if (older != null) {
                    assertTrue(shared.isConnected(), "Main-session close preserves the borrowed transport");
                    SMB2Echo echo = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
                    echo.getHeader().setSessionId(older.getSessionId());
                    assertEquals(0, older.<SMB2Echo>send(echo).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
                    older.close();
                }
                int catchUp = observer.unsignedEchoRequests() - initialCatchUp;
                assertTrue(catchUp <= 32, "Application traffic and the busy initial caller cannot drive later catch-up: " + catchUp);
                System.out.printf("PUBLIC_GMAC_COMPLETE run=%s signing=AES_GMAC replacement=true concurrentBindings=2 borrowedPreserved=%s priorTraffic=%d applicationTraffic=%d collisionEchoes=%d%n",
                        run, borrowed, borrowed ? 1024 : 0, borrowed ? 1024 : 0, catchUp);
            }
            }
        } finally {
            if (shared != null) shared.close(true);
            observer.auxiliaryKeys(actualKeys);
            observer.verifyAndReport("public-" + run, 1, 8);
        }
    }

    @Test
    void failedAuxiliaryContinuationDiscardsOnlyTheAttemptAndCanRetry() throws Exception {
        String portValue = System.getenv("SMB_TEST_PORTS");
        assumeTrue(portValue != null, "Dedicated GMAC fixture required");
        int port = Integer.parseInt(portValue);
        AtomicBoolean failNext = new AtomicBoolean();
        AtomicInteger subscribers = new AtomicInteger();
        SMBEventBus bus = new SMBEventBus() {
            @Override public void subscribe(Object listener) {
                super.subscribe(listener);
                if (listener instanceof Session) subscribers.incrementAndGet();
            }
            @Override public boolean unsubscribe(Object listener) {
                boolean removed = super.unsubscribe(listener);
                if (removed && listener instanceof Session) subscribers.decrementAndGet();
                return removed;
            }
        };
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
                .withSecurityProvider(new BCSecurityProvider()).withTimeout(10, TimeUnit.SECONDS)
                .withAuthenticators(new NtlmAuthenticator.Factory() {
                    @Override public NtlmAuthenticator create() {
                        boolean reject = failNext.getAndSet(false);
                        return new NtlmAuthenticator() {
                            private int calls;
                            @Override public com.hierynomus.smbj.auth.AuthenticateResponse authenticate(
                                    AuthenticationContext auth, byte[] token, ConnectionContext context) throws IOException {
                                if (++calls == 2 && reject) throw new IOException("Injected auxiliary continuation failure");
                                return super.authenticate(auth, token, context);
                            }
                        };
                    }
                }).build();
        try (SMBClient client = new SMBClient(config, bus);
             Connection primary = client.connect("127.0.0.1", port);
             Session main = primary.authenticate(authentication())) {
            Connection shared = new Connection(config, client, bus, client.getServerList());
            try {
                shared.connect("127.0.0.1", port);
                try (Session older = shared.authenticate(authentication());
                     DiskShare share = (DiskShare) older.connectShare("share")) {
                    String name = "gmac-auth-failure-" + UUID.randomUUID() + ".bin";
                    try (File file = share.openFile(name, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
                            SMB2CreateDisposition.FILE_CREATE, EnumSet.noneOf(SMB2CreateOptions.class))) {
                        byte[] expected = new byte[131077]; new Random(53).nextBytes(expected);
                        verifyContents(file, expected);
                        int baselineSubscribers = subscribers.get();
                        failNext.set(true);
                        IOException failure = assertThrows(IOException.class, () -> shared.bind(main));
                        assertTrue(failure.getMessage().contains("auxiliary authentication"));
                        assertTrue(shared.getPreauthSessionTable().activeSessions().isEmpty());
                        assertEquals(1, shared.getSessionTable().activeSessions().size());
                        assertSame(older, shared.getSessionTable().find(older.getSessionId()));
                        assertTrue(shared.isConnected()); assertEquals(1, main.getChannelCount());
                        assertEquals(baselineSubscribers, subscribers.get(), "Failed attempt releases its event subscription");
                        expected[0] ^= 1; verifyContents(file, expected);
                        assertSame(main, shared.bind(main));
                        assertEquals(2, main.getChannelCount());
                        assertEquals(baselineSubscribers, subscribers.get(), "Successful auxiliary also releases its subscription");
                        main.close();
                        assertTrue(shared.isConnected());
                        expected[1] ^= 1; verifyContents(file, expected);
                    } finally { share.rm(name); }
                }
            } finally { shared.close(true); }
        }
        assertEquals(0, subscribers.get());
        System.out.println("PUBLIC_GMAC_COMPLETE run=auxiliary-auth-failure signing=AES_GMAC failedCandidatePublished=false borrowedPreserved=true retry=true");
    }

    @Test
    void rejectedBootstrapFinalUsesItsReservedLogoffWithoutClosingTheCaller() throws Exception {
        String portValue = System.getenv("SMB_TEST_PORTS");
        assumeTrue(portValue != null, "Dedicated GMAC fixture required");
        int port = Integer.parseInt(portValue);
        AtomicBoolean rejecting = new AtomicBoolean();
        AtomicLong failedSession = new AtomicLong();
        AtomicReference<byte[]> originalKey = new AtomicReference<>();
        List<Long> bindingMids = new ArrayList<>(), abortMids = new ArrayList<>();
        List<TransportLayer<SMBPacket<?, ?>>> transports = new ArrayList<>();
        Field keyField = PacketSignatory.SignedPacketWrapper.class.getDeclaredField("secretKey"); keyField.setAccessible(true);
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
                .withSecurityProvider(new BCSecurityProvider()).withTimeout(10, TimeUnit.SECONDS)
                .withAuthenticators(new NtlmAuthenticator.Factory()).withTransportLayerFactory((handlers, settings) -> {
                    TransportLayer<SMBPacket<?, ?>> delegate = new DirectTcpTransport<>(settings.getSocketFactory(), settings.getSoTimeout(), handlers);
                    transports.add(delegate);
                    return new TransportLayer<SMBPacket<?, ?>>() {
                        public void connect(InetSocketAddress address) throws IOException { delegate.connect(address); }
                        public void disconnect() throws IOException { delegate.disconnect(); }
                        public boolean isConnected() { return delegate.isConnected(); }
                        public void write(SMBPacket<?, ?> packet) throws TransportException {
                            if (rejecting.get() && packet instanceof PacketSignatory.SignedPacketWrapper) {
                                SMB2Packet smb = (SMB2Packet) packet;
                                try {
                                    byte[] key = ((SecretKey) keyField.get(packet)).getEncoded();
                                    if (smb.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_SESSION_SETUP) {
                                        failedSession.compareAndSet(0, smb.getHeader().getSessionId());
                                        originalKey.compareAndSet(null, key.clone());
                                        bindingMids.add(smb.getHeader().getMessageId());
                                    } else if (smb.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_LOGOFF
                                            && smb.getHeader().getSessionId() == failedSession.get()) {
                                        assertTrue(java.security.MessageDigest.isEqual(originalKey.get(), key), "Abort must use the original signing key");
                                        abortMids.add(smb.getHeader().getMessageId());
                                    }
                                } catch (IllegalAccessException failure) { throw new AssertionError(failure); }
                            }
                            delegate.write(packet);
                        }
                    };
                }).build();
        try (SMBClient client = new SMBClient(SmbConfig.builder(config)
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_CMAC).build());
             Connection caller = new Connection(config, client, new SMBEventBus(), client.getServerList())) {
            caller.connect("127.0.0.1", port);
            try (Session older = caller.authenticate(authentication());
                 DiskShare share = (DiskShare) older.connectShare("share")) {
            String name = "bootstrap-abort-" + UUID.randomUUID() + ".bin";
            try (File file = share.openFile(name, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_CREATE, EnumSet.noneOf(SMB2CreateOptions.class))) {
                byte[] expected = new byte[131077]; new Random(57).nextBytes(expected); verifyContents(file, expected);
                int before = transports.size();
                Field signerField = Connection.class.getDeclaredField("signatory"); signerField.setAccessible(true);
                Signatory actualSigner = (Signatory) signerField.get(caller);
                signerField.set(caller, new Signatory() {
                    public SMB2Packet sign(SMB2Packet packet, SecretKey key) { return actualSigner.sign(packet, key); }
                    public boolean verify(SMB2PacketData packet, SecretKey key) {
                        if (rejecting.get() && packet.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_SESSION_SETUP
                                && packet.getHeader().getSessionId() == failedSession.get() && packet.getHeader().getStatusCode() == 0) {
                            assertTrue(actualSigner.verify(packet, key), "Genuine final binding reply must verify before client-input corruption");
                            byte[] corrupted = Arrays.copyOfRange(packet.getDataBuffer().array(),
                                    packet.getHeader().getHeaderStartPosition(), packet.getHeader().getMessageEndPosition());
                            corrupted[48] ^= 1;
                            try { return actualSigner.verify(new SMB2PacketData(corrupted), key); }
                            catch (com.hierynomus.protocol.commons.buffer.Buffer.BufferException failure) { throw new AssertionError(failure); }
                        }
                        return actualSigner.verify(packet, key);
                    }
                });
                rejecting.set(true);
                com.hierynomus.smbj.common.SMBRuntimeException failure = assertThrows(
                        com.hierynomus.smbj.common.SMBRuntimeException.class, () -> caller.authenticate(authentication()));
                assertNotNull(failure.getCause(), failure.getClass().getSimpleName() + ": " + failure.getMessage());
                assertTrue(failure.getCause().getMessage().contains("response signature is invalid"));
                assertEquals(before + 1, transports.size());
                assertFalse(transports.get(before).isConnected());
                assertEquals(Arrays.asList(3L), abortMids);
                assertEquals(2, bindingMids.size()); assertFalse(bindingMids.contains(3L));
                assertTrue(caller.isConnected()); assertEquals(1, caller.getSessionTable().activeSessions().size());
                assertSame(older, caller.getSessionTable().find(older.getSessionId()));
                expected[0] ^= 1; verifyContents(file, expected);
                rejecting.set(false);
                try (Session retried = caller.authenticate(authentication())) { assertSame(caller, retried.getConnection()); }
                expected[1] ^= 1; verifyContents(file, expected);
            } finally { share.rm(name); }
            }
        }
        assertTrue(transports.stream().noneMatch(TransportLayer::isConnected));
        System.out.println("PUBLIC_GMAC_COMPLETE run=bootstrap-final-signature-failure signing=AES_GMAC abortMID=3 privateRootClosed=true callerPreserved=true retry=true");
    }

    private static void echo(Session session) throws Exception {
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        request.getHeader().setSessionId(session.getSessionId());
        assertEquals(0, session.<SMB2Echo>send(request).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
    }

    private static AuthenticationContext authentication() {
        return new AuthenticationContext(System.getenv("SMB_TEST_USERNAME"),
                System.getenv("SMB_TEST_PASSWORD").toCharArray(), System.getenv("SMB_TEST_DOMAIN"));
    }

    private static void verifyContents(File file, byte[] expected) {
        assertEquals(expected.length, file.write(expected, 0));
        byte[] actual = new byte[expected.length];
        assertEquals(actual.length, file.read(actual, 0)); assertArrayEquals(expected, actual);
    }
}
