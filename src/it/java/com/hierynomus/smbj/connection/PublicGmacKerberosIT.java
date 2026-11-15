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
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import java.net.InetSocketAddress;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.auth.Subject;
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
import org.ietf.jgss.GSSContext;
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

    @ParameterizedTest
    @CsvSource({"16,false", "16,true", "32,false", "32,true"})
    void authenticateBindAndReplacePublicChannels(int keyBytes, boolean borrowed) throws Exception {
        assumeTrue(System.getenv("SMBJ_AD_IMAGE") != null, "Dedicated native Kerberos fixture required");
        String mode = "public-" + keyBytes + "-" + borrowed;
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
            LoginContext login = null;
            try {
                String enctype = keyBytes == 16 ? "aes128-cts-hmac-sha1-96" : "aes256-cts-hmac-sha1-96";
                Path krbConfig = directory.resolve("krb5.conf");
                String configuration = "[libdefaults]\n default_realm = SMBJ.TEST\n dns_lookup_realm = false\n dns_lookup_kdc = false\n udp_preference_limit = 1\n rdns = false\n default_tkt_enctypes = " + enctype
                        + "\n default_tgs_enctypes = " + enctype + "\n permitted_enctypes = " + enctype
                        + "\n[realms]\n SMBJ.TEST = {\n  kdc = 127.0.0.1:" + kdcPort + "\n }\n";
                Files.write(krbConfig, configuration.getBytes(StandardCharsets.UTF_8));
                System.setProperty("java.security.krb5.conf", krbConfig.toString());
                System.out.printf("KERBEROS_READY mode=%s id=%s smbPort=%d kdcPort=%d%n", mode, cid, port, kdcPort);
                try { login = login(password); }
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
            exercisePublicChannels(port, keyBytes, borrowed, login.getSubject());
            int established = 0, disposed = 0;
            for (SpnegoAuthenticator authenticator : authenticators) {
                GSSContext context = context(authenticator);
                if (context == null) disposed++;
                if (context != null && context.isEstablished()) {
                    Key exported = (Key) ((ExtendedGSSContext) context).inquireSecContext(InquireType.KRB5_GET_SESSION_KEY);
                    assertEquals(keyBytes, exported.getEncoded().length);
                    established++;
                }
            }
            assertTrue(established >= 9); assertTrue(disposed >= 6, "Reauthentication disposes each fresh GSS context");
            System.out.printf("KERBEROS_CONTEXTS mode=%s established=%d rawKeyBytes=%d kerberos=true disposed=%d%n", mode, established, keyBytes, disposed);
            } finally {
                try {
                    for (SpnegoAuthenticator authenticator : authenticators) {
                        GSSContext context = context(authenticator); if (context != null) context.dispose();
                    }
                } finally {
                    try { if (login != null) login.logout(); }
                    finally {
                        if (oldKrbConfig == null) System.clearProperty("java.security.krb5.conf");
                        else System.setProperty("java.security.krb5.conf", oldKrbConfig);
                        Files.deleteIfExists(directory.resolve("krb5.conf")); Files.deleteIfExists(directory);
                    }
                }
            }
        }
        System.out.printf("PUBLIC_KRB_COMPLETE mode=%s rawKeyBytes=%d borrowed=%s id=%s image=%s removed=true java=%s%n",
                mode, keyBytes, borrowed, cid, System.getenv("SMBJ_AD_IMAGE_ID"), System.getProperty("java.version"));
    }

    private void exercisePublicChannels(int port, int keyBytes, boolean borrowed, Subject subject) throws Exception {
        GmacBindingWireObserver observer = new GmacBindingWireObserver("server.smbj.test", port);
        Map<Long, byte[]> actualKeys = new ConcurrentHashMap<>();
        AtomicLong target = new AtomicLong();
        AtomicInteger bindingStarts = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(2), release = new CountDownLatch(1);
        Field keyField = PacketSignatory.SignedPacketWrapper.class.getDeclaredField("secretKey"); keyField.setAccessible(true);
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
                .withSecurityProvider(new BCSecurityProvider()).withSocketFactory(observer)
                .withTimeout(10, TimeUnit.SECONDS).withAuthenticators(new SpnegoAuthenticator.Factory() {
                    @Override public SpnegoAuthenticator create() {
                        SpnegoAuthenticator auth = super.create(); authenticators.add(auth); return auth;
                    }
                }).withTransportLayerFactory((handlers, settings) -> {
                    TransportLayer<SMBPacket<?, ?>> delegate = new DirectTcpTransport<>(settings.getSocketFactory(), settings.getSoTimeout(), handlers);
                    return new TransportLayer<SMBPacket<?, ?>>() {
                        public void connect(InetSocketAddress address) throws IOException { delegate.connect(address); }
                        public void disconnect() throws IOException { delegate.disconnect(); }
                        public boolean isConnected() { return delegate.isConnected(); }
                        public void write(SMBPacket<?, ?> packet) throws TransportException {
                            if (packet instanceof PacketSignatory.SignedPacketWrapper) {
                                SMB2Packet smb = (SMB2Packet) packet;
                                try { actualKeys.putIfAbsent(smb.getHeader().getSessionId(), ((SecretKey) keyField.get(packet)).getEncoded().clone()); }
                                catch (IllegalAccessException failure) { throw new AssertionError(failure); }
                                if (target.get() != 0 && smb.getHeader().getSessionId() == target.get()
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
        try (SMBClient client = new SMBClient(config); Connection caller = client.connect("server.smbj.test", port)) {
            observer.register(caller);
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, caller.getConnectionContext().getSigningAlgorithm());
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
        observer.verifyAndReport("public-kerberos-" + keyBytes + "-" + borrowed, 1, 8);
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

    private static LoginContext login(String password) throws Exception {
        Map<String, String> options = new HashMap<>();
        options.put("principal", "smbtest@SMBJ.TEST"); options.put("useTicketCache", "false");
        options.put("storeKey", "true"); options.put("isInitiator", "true"); options.put("refreshKrb5Config", "true");
        LoginContext login = new LoginContext("smbj-native", null, callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) ((NameCallback) callback).setName("smbtest@SMBJ.TEST");
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

    private static GSSContext context(SpnegoAuthenticator authenticator) throws Exception {
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
