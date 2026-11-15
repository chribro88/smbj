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

import com.github.dockerjava.api.model.*;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.PacketReceiver;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import java.net.InetSocketAddress;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;
import com.hierynomus.smbj.auth.*;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.session.SessionContext;
import com.hierynomus.smbj.share.*;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.MountableFile;
import org.testcontainers.utility.DockerImageName;

import javax.crypto.SecretKey;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Principal;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;
import java.io.IOException;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Native public-path acceptance using the existing isolated Samba AD fixture. */
@Timeout(120)
class PublicGmacKerberosIT {
    private final List<SpnegoAuthenticator> authenticators = new CopyOnWriteArrayList<>();
    private final Map<SpnegoAuthenticator, Integer> exportedKeyLengths = new ConcurrentHashMap<>();
    private final AtomicBoolean failNextDisposal = new AtomicBoolean();

    @ParameterizedTest
    @CsvSource({"16,false", "16,true", "32,false", "32,true"})
    void authenticateBindAndReplacePublicChannels(int keyBytes, boolean borrowed) throws Exception {
        exerciseServer(keyBytes, borrowed, false);
    }

    @ParameterizedTest
    @CsvSource({"16,false", "16,true", "32,false", "32,true"})
    void encryptedAuthenticateBindAndReplacePublicChannels(int keyBytes, boolean borrowed) throws Exception {
        exerciseServer(keyBytes, borrowed, true);
    }

    private void exerciseServer(int keyBytes, boolean borrowed, boolean encryption) throws Exception {
        assumeTrue(System.getenv("SMBJ_AD_IMAGE") != null, "Dedicated native Kerberos fixture required");
        String mode = "public-" + keyBytes + "-" + borrowed + "-" + encryption;
        String owner = "smbj-kerberos-native-" + UUID.randomUUID();
        String password = "Aa0!" + UUID.randomUUID();
        String cid;
        StringBuffer serverLog = new StringBuffer();
        Map<String, String> temporaryFilesystems = new HashMap<>();
        temporaryFilesystems.put("/shared", "rw,size=64m,mode=1777");
        temporaryFilesystems.put("/state", "rw,size=256m,mode=0755");
        try (GenericContainer<?> peer = new GenericContainer<>(DockerImageName.parse(
                System.getenv("SMBJ_AD_IMAGE")))
                .withLabel("org.smbj.test-owner", owner).withExposedPorts(445, 88).withCreateContainerCmdModifier(command -> command.withHostName("server.smbj.test"))
                .withEnv("SMBJ_DC_PASSWORD", password)
                .withLogConsumer(frame -> { if (serverLog.length() < 262144) serverLog.append(frame.getUtf8String()); })
                .withCopyFileToContainer(MountableFile.forHostPath(System.getenv("SMBJ_AD_FIXTURE") + "/samba-command.py"), "/fixture/samba-command.py")
                .withCopyFileToContainer(MountableFile.forHostPath(System.getenv("SMBJ_AD_FIXTURE") + "/bootstrap.sh"), "/fixture/bootstrap.sh")
                .withCommand("/fixture/bootstrap.sh")
                .withCreateContainerCmdModifier(command -> {
                    command.withEntrypoint("/bin/sh");
                    command.getHostConfig().withMemory(768L * 1024 * 1024).withNanoCPUs(1000000000L)
                            .withTmpFs(temporaryFilesystems)
                            .withPortBindings(new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(445)),
                                    new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(88)));
                }).waitingFor(new WaitAllStrategy().withStrategy(Wait.forLogMessage(".*SMBJ_DOMAIN_READY.*\\n", 1))
                        .withStrategy(Wait.forListeningPort())).withStartupTimeout(Duration.ofSeconds(30))) {
            try { peer.start(); }
            catch (Exception failure) {
                Files.write(Paths.get(System.getenv("SMBJ_AD_OUTPUT"), "startup-diagnostic-" + mode + ".log"),
                        serverLog.toString().replace(password, "<private-fixture-secret>").getBytes(StandardCharsets.UTF_8));
                throw failure;
            }
            cid = peer.getContainerId();
            assertEquals(System.getenv("SMBJ_AD_IMAGE_ID"), peer.getContainerInfo().getImageId());
            int port = peer.getMappedPort(445), kdcPort = peer.getMappedPort(88);
            Path directory = Files.createTempDirectory("smbj-native-kerberos-");
            String oldKrbConfig = System.getProperty("java.security.krb5.conf");
            LoginContext login = null, otherLogin = null;
            try {
                String enctype = keyBytes == 16 ? "aes128-cts-hmac-sha1-96" : "aes256-cts-hmac-sha1-96";
                Path krbConfig = directory.resolve("krb5.conf");
                String configuration = "[libdefaults]\n default_realm = SMBJ.TEST\n dns_lookup_realm = false\n dns_lookup_kdc = false\n udp_preference_limit = 1\n rdns = false\n default_tkt_enctypes = " + enctype
                        + "\n default_tgs_enctypes = " + enctype + "\n permitted_enctypes = " + enctype
                        + "\n[realms]\n SMBJ.TEST = {\n  kdc = 127.0.0.1:" + kdcPort + "\n }\n";
                Files.write(krbConfig, configuration.getBytes(StandardCharsets.UTF_8));
                System.setProperty("java.security.krb5.conf", krbConfig.toString());
                System.out.printf("KERBEROS_READY mode=%s id=%s smbPort=%d kdcPort=%d%n", mode, cid, port, kdcPort);
                try {
                    login = login("smbtest@SMBJ.TEST", password);
                    otherLogin = login("Administrator@SMBJ.TEST", password);
                }
                catch (Exception failure) {
                    Path diagnostics = Paths.get(System.getenv("SMBJ_AD_OUTPUT"), "fixture-" + mode + ".log");
                    Files.write(diagnostics, peer.getLogs().replace(password, "<private-fixture-secret>").getBytes(StandardCharsets.UTF_8));
                    try {
                        String info = peer.getDockerClient().inspectContainerCmd(cid).exec().getState().toString();
                        if (peer.isRunning()) info += "\n" + peer.execInContainer("sh", "-c", "netstat -lnt; cat /state/etc/smb.conf; ps").getStdout();
                        Files.write(diagnostics, info.getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);
                    } catch (Exception diagnosticFailure) { failure.addSuppressed(diagnosticFailure); }
                    throw failure;
                }
                System.out.printf("KERBEROS_LOGIN mode=%s keyBytes=%d kdcPort=%d success=true%n", mode, keyBytes, kdcPort);
            System.out.printf("KERBEROS_FIXTURE mode=%s owner=%s id=%s port=%d version=%s%n", mode, owner, cid, port,
                    peer.execInContainer("smbd", "--version").getStdout().trim());
            exercisePublicChannels(port, keyBytes, borrowed, encryption, login.getSubject(), otherLogin.getSubject());
            int disposed = 0;
            for (SpnegoAuthenticator authenticator : authenticators) {
                assertNull(context(authenticator), "Production must dispose initial, auxiliary, binding and reauthentication GSS contexts");
                disposed++;
            }
            assertTrue(exportedKeyLengths.size() >= 15);
            assertEquals(authenticators.size(), exportedKeyLengths.size() + 2,
                    "Expired-cache and rejected-principal attempts fail before exporting keys");
            for (int length : exportedKeyLengths.values()) assertEquals(keyBytes, length);
            System.out.printf("KERBEROS_CONTEXTS mode=%s created=%d established=%d failedBeforeKey=2 rawKeyBytes=%d kerberos=true disposed=%d live=0%n",
                    mode, authenticators.size(), exportedKeyLengths.size(), keyBytes, disposed);
            } finally {
                try {
                    for (SpnegoAuthenticator authenticator : authenticators) {
                        if (context(authenticator) != null) authenticator.close();
                    }
                } finally {
                    try {
                        try { if (otherLogin != null) otherLogin.logout(); }
                        finally { if (login != null) login.logout(); }
                    }
                    finally {
                        if (oldKrbConfig == null) System.clearProperty("java.security.krb5.conf");
                        else System.setProperty("java.security.krb5.conf", oldKrbConfig);
                        Files.deleteIfExists(directory.resolve("krb5.conf")); Files.deleteIfExists(directory);
                    }
                }
            }
        }
        System.out.printf("PUBLIC_KRB_COMPLETE mode=%s rawKeyBytes=%d borrowed=%s encrypt=%s id=%s image=%s removed=true java=%s%n",
                mode, keyBytes, borrowed, encryption, cid, System.getenv("SMBJ_AD_IMAGE_ID"), System.getProperty("java.version"));
    }

    private void exercisePublicChannels(int port, int keyBytes, boolean borrowed, boolean encryption,
                                        Subject subject, Subject otherSubject) throws Exception {
        GmacBindingWireObserver observer = new GmacBindingWireObserver("server.smbj.test", port);
        Map<Long, byte[]> actualKeys = new ConcurrentHashMap<>();
        AtomicLong target = new AtomicLong();
        AtomicInteger bindingStarts = new AtomicInteger();
        AtomicInteger setupRequests = new AtomicInteger();
        AtomicReference<SMB2PacketData> rejectedSetup = new AtomicReference<>();
        AtomicBoolean bindingBarrier = new AtomicBoolean();
        List<Long> logoffs = new CopyOnWriteArrayList<>();
        AtomicBoolean holdNextLogoff = new AtomicBoolean();
        AtomicReference<SMBPacketData<?>> delayedLogoff = new AtomicReference<>();
        AtomicReference<SMB2PacketData> delayedPlaintext = new AtomicReference<>();
        AtomicReference<Request> delayedRequest = new AtomicReference<>();
        AtomicReference<PacketReceiver<SMBPacketData<?>>> delayedReceiver = new AtomicReference<>();
        Map<Connection, Throwable> readerFailures = new ConcurrentHashMap<>();
        CountDownLatch entered = new CountDownLatch(2), release = new CountDownLatch(1);
        Field keyField = PacketSignatory.SignedPacketWrapper.class.getDeclaredField("secretKey"); keyField.setAccessible(true);
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
                .withEncryptData(encryption)
                .withSecurityProvider(new BCSecurityProvider()).withSocketFactory(observer)
                .withTimeout(10, TimeUnit.SECONDS).withTransactTimeout(1, TimeUnit.SECONDS)
                .withAuthenticators(new SpnegoAuthenticator.Factory() {
                    @Override public SpnegoAuthenticator create() {
                        SpnegoAuthenticator auth = new SpnegoAuthenticator() {
                            @Override public AuthenticateResponse authenticate(AuthenticationContext auth, byte[] token, ConnectionContext connection) throws IOException {
                                AuthenticateResponse response = super.authenticate(auth, token, connection);
                                try {
                                    GSSContext context = context(this);
                                    if (context != null && context.isEstablished()) {
                                        Key key = (Key) ((ExtendedGSSContext) context).inquireSecContext(InquireType.KRB5_GET_SESSION_KEY);
                                        assertNotNull(key);
                                        exportedKeyLengths.put(this, key.getEncoded().length);
                                    }
                                } catch (ReflectiveOperationException | org.ietf.jgss.GSSException failure) {
                                    throw new IOException("Could not observe native GSS key length", failure);
                                }
                                return response;
                            }
                            @Override public void close() throws IOException {
                                super.close();
                                if (failNextDisposal.compareAndSet(true, false)) {
                                    throw new IOException("Injected GSS disposal failure after authentication");
                                }
                            }
                        };
                        authenticators.add(auth); return auth;
                    }
                }).withTransportLayerFactory((handlers, settings) -> {
                    PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> filtered = new PacketHandlers<>(handlers.getSerializer(),
                            new PacketReceiver<SMBPacketData<?>>() {
                                public void handle(SMBPacketData<?> packet) throws TransportException {
                                    if (packet instanceof SMB2PacketData) {
                                        SMB2PacketData response = (SMB2PacketData) packet;
                                        if (target.get() != 0 && response.getHeader().getSessionId() == target.get()
                                                && response.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_SESSION_SETUP
                                                && response.getHeader().getStatusCode() != NtStatus.STATUS_SUCCESS.getValue()
                                                && response.getHeader().getStatusCode() != NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue()) {
                                            rejectedSetup.set(response);
                                        }
                                    }
                                    Request pending = delayedRequest.get();
                                    if (holdNextLogoff.get() && pending != null) {
                                        SMB2PacketData reply = packet instanceof SMB2PacketData ? (SMB2PacketData) packet : null;
                                        if (packet instanceof SMB3EncryptedPacketData
                                                && ((SMB3EncryptedPacketData) packet).getHeader().getSessionId()
                                                == ((SMB2Packet) pending.getPacket()).getHeader().getSessionId()) {
                                            try {
                                                reply = new SMB2PacketData(observer.decryptTransform(Arrays.copyOf(
                                                        packet.getDataBuffer().array(), packet.getDataBuffer().wpos()), true));
                                            } catch (Exception failure) { throw new TransportException(failure); }
                                        }
                                        if (reply != null && reply.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_LOGOFF
                                                && reply.getHeader().getMessageId() == pending.getMessageId()
                                                && holdNextLogoff.compareAndSet(true, false)) {
                                            assertEquals(encryption, packet instanceof SMB3EncryptedPacketData);
                                            delayedReceiver.set(handlers.getReceiver()); delayedLogoff.set(packet); delayedPlaintext.set(reply);
                                            return;
                                        }
                                    }
                                    handlers.getReceiver().handle(packet);
                                }
                                public void handleError(Throwable failure) {
                                    readerFailures.putIfAbsent((Connection) handlers.getReceiver(), failure);
                                    handlers.getReceiver().handleError(failure);
                                }
                            }, handlers.getPacketFactory());
                    TransportLayer<SMBPacket<?, ?>> delegate = new DirectTcpTransport<>(settings.getSocketFactory(), settings.getSoTimeout(), filtered);
                    return new TransportLayer<SMBPacket<?, ?>>() {
                        public void connect(InetSocketAddress address) throws IOException { delegate.connect(address); }
                        public void disconnect() throws IOException { delegate.disconnect(); }
                        public boolean isConnected() { return delegate.isConnected(); }
                        public void write(SMBPacket<?, ?> packet) throws TransportException {
                            if (packet instanceof SMB2Packet && ((SMB2Packet) packet).getHeader().getMessage()
                                    == SMB2MessageCommandCode.SMB2_SESSION_SETUP) setupRequests.incrementAndGet();
                            if (packet instanceof PacketEncryptor.EncryptedPacketWrapper) {
                                SMB2Packet smb = (SMB2Packet) packet;
                                Session owner = ((Connection) handlers.getReceiver()).getSessionTable().find(smb.getHeader().getSessionId());
                                observer.encryption(owner);
                                actualKeys.putIfAbsent(owner.getSessionId(), owner.getSessionContext().getSigningKey().getEncoded().clone());
                            }
                            if (packet instanceof SMB2Packet && ((SMB2Packet) packet).getHeader().getMessage() == SMB2MessageCommandCode.SMB2_LOGOFF) {
                                SMB2Packet smb = (SMB2Packet) packet;
                                logoffs.add(smb.getHeader().getSessionId());
                                if (holdNextLogoff.get()) delayedRequest.set(((Connection) handlers.getReceiver()).outstandingRequests
                                        .getRequestByMessageId(smb.getHeader().getMessageId()));
                            }
                            if (packet instanceof PacketSignatory.SignedPacketWrapper) {
                                SMB2Packet smb = (SMB2Packet) packet;
                                try { actualKeys.putIfAbsent(smb.getHeader().getSessionId(), ((SecretKey) keyField.get(packet)).getEncoded().clone()); }
                                catch (IllegalAccessException failure) { throw new AssertionError(failure); }
                                if (bindingBarrier.get() && target.get() != 0 && smb.getHeader().getSessionId() == target.get()
                                        && smb.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_SESSION_SETUP
                                        && bindingStarts.incrementAndGet() <= 2) {
                                    entered.countDown();
                                    try {
                                        if (!release.await(5, TimeUnit.SECONDS)) throw new TransportException("Concurrent binding barrier timed out");
                                    } catch (InterruptedException failure) {
                                        Thread.currentThread().interrupt(); throw new TransportException(failure);
                                    }
                                }
                            }
                            delegate.write(packet);
                        }
                    };
                }).build();
        AuthenticationContext identity = new GSSAuthenticationContext("smbtest", "SMBJ.TEST", subject, null);
        com.hierynomus.smbj.event.SMBEventBus bus = new com.hierynomus.smbj.event.SMBEventBus();
        try (SMBClient client = new SMBClient(config, bus); Connection caller = client.connect("server.smbj.test", port)) {
            observer.register(caller);
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, caller.getConnectionContext().getSigningAlgorithm());
            if (encryption) assertEquals(SMB3EncryptionCipher.AES_128_GCM, caller.getConnectionContext().getCipherId());
            try (Session older = borrowed ? caller.authenticate(identity) : null) {
                if (older != null) observer.auxiliary(older, caller);
                try (Session main = caller.authenticate(identity)) {
                    assertSame(caller, main.getConnection());
                    assertTrue(caller.isConnected()); assertEquals(1, main.getChannelCount());
                    observer.original(main, caller); observer.bound(main, caller); target.set(main.getSessionId());
                    try (DiskShare share = (DiskShare) main.connectShare("share")) {
                        String name = "public-kerberos-" + UUID.randomUUID() + ".bin";
                        try (com.hierynomus.smbj.share.File file = share.openFile(name,
                                EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE), null,
                                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                            byte[] data = new byte[131077]; new Random(67).nextBytes(data); verifyContents(file, data);
                            Connection shared = new Connection(config, client, bus, client.getServerList());
                            try {
                                shared.connect("server.smbj.test", port); observer.register(shared);
                                try (Session prior = shared.authenticate(identity);
                                     DiskShare priorShare = (DiskShare) prior.connectShare("share")) {
                                    observer.auxiliary(prior, shared);
                                    String priorName = "kerberos-prior-" + UUID.randomUUID() + ".bin";
                                    try (com.hierynomus.smbj.share.File priorFile = priorShare.openFile(priorName,
                                            EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE), null,
                                            SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                                        byte[] priorData = new byte[65539]; new Random(71).nextBytes(priorData); verifyContents(priorFile, priorData);
                                        int before = logoffs.size();
                                        byte[][] retained = snapshot(main);
                                        failNextDisposal.set(true);
                                        IOException failure = assertThrows(IOException.class, () -> shared.bind(main));
                                        assertNull(readerFailures.get(shared), "The shared candidate's reader must remain healthy");
                                        Throwable cause = failure;
                                        while (cause.getCause() != null) cause = cause.getCause();
                                        assertEquals("Injected GSS disposal failure after authentication", cause.getMessage());
                                        assertEquals(0, cause.getSuppressed().length, "Verified-session cleanup must receive a successful LOGOFF");
                                        assertFalse(failNextDisposal.get());
                                        assertEquals(before + 1, logoffs.size(), "The authenticated unpublished auxiliary must LOGOFF");
                                        long retired = logoffs.get(before);
                                        assertNotEquals(prior.getSessionId(), retired); assertNotEquals(main.getSessionId(), retired);
                                        assertTrue(shared.isConnected()); assertEquals(1, main.getChannelCount());
                                        assertEquals(1, shared.getSessionTable().activeSessions().size());
                                        assertSame(prior, shared.getSessionTable().find(prior.getSessionId()));
                                        assertTrue(shared.getPreauthSessionTable().activeSessions().isEmpty());
                                        assertSnapshot(retained, main);
                                        priorData[0] ^= 1; verifyContents(priorFile, priorData);
                                        data[0] ^= 1; verifyContents(file, data);
                                        holdNextLogoff.set(true); failNextDisposal.set(true);
                                        IOException timedOut = assertThrows(IOException.class, () -> shared.bind(main));
                                        assertNull(readerFailures.get(shared), "Holding a cleanup reply must not break its reader");
                                        Throwable timeoutCause = timedOut;
                                        while (timeoutCause.getCause() != null) timeoutCause = timeoutCause.getCause();
                                        assertEquals("Injected GSS disposal failure after authentication", timeoutCause.getMessage());
                                        assertEquals(1, timeoutCause.getSuppressed().length);
                                        assertInstanceOf(TransportException.class, timeoutCause.getSuppressed()[0]);
                                        SMBPacketData<?> late = delayedLogoff.getAndSet(null);
                                        SMB2PacketData decoded = delayedPlaintext.getAndSet(null);
                                        Request abandoned = delayedRequest.getAndSet(null);
                                        assertNotNull(late); assertNotNull(abandoned); assertNotNull(decoded);
                                        assertEquals(0, decoded.getHeader().getStatusCode(), "The real peer accepted the cleanup LOGOFF");
                                        assertNull(shared.getSessionTable().find(decoded.getHeader().getSessionId()));
                                        assertFalse(shared.outstandingRequests.isOutstanding(abandoned.getMessageId()));
                                        assertNull(shared.outstandingRequests.getRequestByCancelId(abandoned.getCancelId()));
                                        assertTrue(abandoned.getPromise().isFulfilled());
                                        assertEquals(before + 2, logoffs.size());
                                        assertTrue(shared.getPreauthSessionTable().activeSessions().isEmpty());
                                        assertEquals(1, shared.getSessionTable().activeSessions().size());
                                        int credits = shared.sequenceWindow.available();
                                        delayedReceiver.getAndSet(null).handle(late);
                                        assertEquals(credits, shared.sequenceWindow.available(), "A retired late reply cannot grant credits");
                                        assertTrue(shared.isConnected()); assertSame(prior, shared.getSessionTable().find(prior.getSessionId()));
                                        assertSnapshot(retained, main);
                                        priorData[1] ^= 1; verifyContents(priorFile, priorData);
                                        data[1] ^= 1; verifyContents(file, data);
                                        assertSame(main, shared.bind(main)); observer.bound(main, shared);
                                        assertEquals(2, main.getChannelCount()); echo(main, shared);
                                        priorData[1] ^= 1; verifyContents(priorFile, priorData);
                                    } finally { if (shared.isConnected()) priorShare.rm(priorName); }
                                }
                            } finally { shared.close(true); }
                            assertEquals(1, main.getChannelCount());
                            System.out.printf("KERBEROS_DISPOSAL_ABORT rawKeyBytes=%d borrowed=%s encrypt=%s confirmedLogoffs=1 timedOutLogoffs=1 lateIgnored=true injectedAfterDispose=true%n",
                                    keyBytes, borrowed, encryption);
                            bindingBarrier.set(true);
                            ExecutorService workers = Executors.newFixedThreadPool(2);
                            Connection first, second;
                            try {
                                Future<Connection> a = workers.submit(() -> open(client, main, port, observer));
                                Future<Connection> b = workers.submit(() -> open(client, main, port, observer));
                                assertTrue(entered.await(5, TimeUnit.SECONDS));
                                data[0] ^= 1; verifyContents(file, data); release.countDown();
                                first = a.get(10, TimeUnit.SECONDS); second = b.get(10, TimeUnit.SECONDS);
                            } finally {
                                release.countDown(); workers.shutdownNow(); assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
                            }
                            assertEquals(3, main.getChannelCount());
                            byte[][] retained = snapshot(main);
                            for (int channel = 0; channel < 3; channel++) main.reauthenticate();
                            assertSnapshot(retained, main);
                            int beforeExpiry = setupRequests.get();
                            rejectsExpiredSubjectTicket(main, subject);
                            assertEquals(beforeExpiry, setupRequests.get(), "Expired client credentials must fail before sending SESSION_SETUP");
                            assertSnapshot(retained, main);
                            data[1] ^= 1; verifyContents(file, data);
                            main.reauthenticate();
                            assertSnapshot(retained, main);
                            System.out.printf("KERBEROS_CACHE_EXPIRY rawKeyBytes=%d borrowed=%s encrypt=%s noCredential=true setupRequests=0 existingOpen=true freshRetry=true%n",
                                    keyBytes, borrowed, encryption);
                            int beforeRejection = setupRequests.get();
                            rejectedSetup.set(null);
                            rejectsDifferentPrincipal(main, subject, otherSubject);
                            assertEquals(beforeRejection + 1, setupRequests.get());
                            SMB2PacketData rejection = rejectedSetup.get();
                            assertNotNull(rejection, "The rejection must come from the peer");
                            assertEquals(NtStatus.STATUS_ACCESS_DENIED.getValue(), rejection.getHeader().getStatusCode());
                            assertTrue(rejection.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SIGNED));
                            assertSnapshot(retained, main);
                            assertEquals(3, main.getChannelCount());
                            data[2] ^= 1; verifyContents(file, data);
                            main.reauthenticate();
                            assertSnapshot(retained, main);
                            System.out.printf("KERBEROS_PEER_REJECTION rawKeyBytes=%d borrowed=%s encrypt=%s status=STATUS_ACCESS_DENIED setupRequests=1 signed=true existingOpen=true freshRetry=true%n",
                                    keyBytes, borrowed, encryption);
                            data[1] ^= 1; verifyContents(file, data);
                            first.close(true);
                            Connection replacement = open(client, main, port, observer);
                            assertEquals(3, main.getChannelCount());
                            for (int channel = 0; channel < 3; channel++) main.reauthenticate();
                            assertSnapshot(retained, main);
                            data[2] ^= 1; verifyContents(file, data);
                            echo(main, caller); echo(main, second); echo(main, replacement);
                        } finally { share.rm(name); }
                    }
                    main.close(); assertTrue(caller.isConnected());
                    if (older != null) echo(older, caller);
                }
            }
        }
        observer.auxiliaryKeys(actualKeys);
        observer.verifyAndReport("public-kerberos-" + keyBytes + "-" + borrowed + "-" + encryption, 1, 8);
    }

    private static Connection open(SMBClient client, Session session, int port, GmacBindingWireObserver observer) throws Exception {
        Connection channel = client.openChannel(session, "127.0.0.1", port);
        observer.register(channel); observer.bound(session, channel); return channel;
    }

    private static byte[][] snapshot(Session session) {
        SessionContext context = session.getSessionContext();
        SecretKey[] keys = {context.getSessionKey(), context.getSigningKey(), context.getEncryptionKey(),
                context.getDecryptionKey(), context.getApplicationKey()};
        byte[][] values = new byte[6][];
        for (int i = 0; i < keys.length; i++) values[i] = keys[i] == null ? null : keys[i].getEncoded().clone();
        values[5] = context.getPreauthIntegrityHashValue().clone(); return values;
    }

    private static void assertSnapshot(byte[][] expected, Session session) {
        byte[][] actual = snapshot(session);
        for (int i = 0; i < expected.length; i++) assertArrayEquals(expected[i], actual[i]);
    }

    private static void rejectsExpiredSubjectTicket(Session session, Subject subject) throws Exception {
        assertTrue(Boolean.parseBoolean(System.getProperty("javax.security.auth.useSubjectCredsOnly", "true")));
        KerberosTicket tgt = subject.getPrivateCredentials(KerberosTicket.class).stream()
                .filter(ticket -> ticket.getServer().getName().startsWith("krbtgt/"))
                .findFirst().orElseThrow(() -> new AssertionError("Native login did not supply a TGT"));
        Date start = new Date(System.currentTimeMillis() - 120000), end = new Date(System.currentTimeMillis() - 60000);
        // Expire only the client's cache metadata; the encoded server ticket is never sent.
        KerberosTicket expired = new KerberosTicket(tgt.getEncoded(), tgt.getClient(), tgt.getServer(),
                tgt.getSessionKey().getEncoded(), tgt.getSessionKeyType(), tgt.getFlags(), start, start, end, end, tgt.getClientAddresses());
        Set<Object> credentials = new HashSet<>(subject.getPrivateCredentials());
        try {
            subject.getPrivateCredentials().clear();
            subject.getPrivateCredentials().add(expired);
            assertFalse(expired.isCurrent());
            Throwable failure = assertThrows(IOException.class, session::reauthenticate);
            assertEquals(0, failure.getSuppressed().length, "Failed GSS context disposal must not be hidden by NO_CRED");
            while (!(failure instanceof GSSException) && failure.getCause() != null) failure = failure.getCause();
            assertInstanceOf(GSSException.class, failure);
            assertEquals(GSSException.NO_CRED, ((GSSException) failure).getMajor());
        } finally {
            subject.getPrivateCredentials().clear();
            subject.getPrivateCredentials().addAll(credentials);
            if (!expired.isDestroyed()) expired.destroy();
        }
    }

    private static void rejectsDifferentPrincipal(Session session, Subject subject, Subject other) throws Exception {
        Set<Principal> principals = new HashSet<>(subject.getPrincipals());
        Set<Object> credentials = new HashSet<>(subject.getPrivateCredentials());
        assertFalse(principals.equals(other.getPrincipals()));
        try {
            subject.getPrincipals().clear(); subject.getPrincipals().addAll(other.getPrincipals());
            subject.getPrivateCredentials().clear(); subject.getPrivateCredentials().addAll(other.getPrivateCredentials());
            SMBApiException failure = assertThrows(SMBApiException.class, session::reauthenticate);
            assertEquals(NtStatus.STATUS_ACCESS_DENIED, failure.getStatus());
            assertEquals(0, failure.getSuppressed().length, "Rejected authentication must dispose its GSS context cleanly");
        } finally {
            subject.getPrincipals().clear(); subject.getPrincipals().addAll(principals);
            subject.getPrivateCredentials().clear(); subject.getPrivateCredentials().addAll(credentials);
        }
    }

    private static LoginContext login(String principal, String password) throws Exception {
        Map<String, String> options = new HashMap<>();
        options.put("principal", principal); options.put("useTicketCache", "false");
        options.put("storeKey", "true"); options.put("isInitiator", "true"); options.put("refreshKrb5Config", "true");
        LoginContext login = new LoginContext("smbj-native", null, callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) ((NameCallback) callback).setName(principal);
                else if (callback instanceof PasswordCallback) ((PasswordCallback) callback).setPassword(password.toCharArray());
                else throw new UnsupportedCallbackException(callback);
            }
        }, new Configuration() {
            @Override public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[]{new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)};
            }
        });
        login.login(); return login;
    }

    private static GSSContext context(SpnegoAuthenticator authenticator) throws ReflectiveOperationException {
        Field field = SpnegoAuthenticator.class.getDeclaredField("gssContext"); field.setAccessible(true);
        return (GSSContext) field.get(authenticator);
    }

    private static void verifyContents(com.hierynomus.smbj.share.File file, byte[] data) {
        assertEquals(data.length, file.write(data, 0));
        byte[] actual = new byte[data.length]; assertEquals(data.length, file.read(actual, 0)); assertArrayEquals(data, actual);
    }

    private static void echo(Session session, Connection connection) throws Exception {
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1); request.getHeader().setSessionId(session.getSessionId());
        assertEquals(0, session.<SMB2Echo>send(request, connection).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
    }

}
