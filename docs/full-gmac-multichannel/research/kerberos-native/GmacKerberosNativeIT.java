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
import com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smb.Packets;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.*;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.session.SessionContext;
import com.hierynomus.smbj.share.*;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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

/** Detached research only; never removes the production feature's binding guard. */
@Timeout(90)
class GmacKerberosNativeIT {
    private final List<SpnegoAuthenticator> authenticators = new ArrayList<>();
    @ParameterizedTest
    @ValueSource(strings = {"original", "bound", "wrong-original"})
    void observeReauthenticationKeysWithoutResettingTheSession(String mode) throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Explicit isolated research only");
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
            int keyBytes = Integer.parseInt(System.getenv().getOrDefault("SMBJ_KRB_KEY_BYTES", "16"));
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
            GmacWireObserver observer = new GmacWireObserver(port, mode.equals("original"));
            SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
                    .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
                    .withSecurityProvider(new BCSecurityProvider()).withSocketFactory(observer)
                    .withAuthenticators(new SpnegoAuthenticator.Factory() {
                        @Override public SpnegoAuthenticator create() {
                            SpnegoAuthenticator authenticator = super.create(); authenticators.add(authenticator); return authenticator;
                        }
                    }).withTimeout(5, TimeUnit.SECONDS).build();
            AuthenticationContext identity = new GSSAuthenticationContext("smbtest", "SMBJ.TEST", login.getSubject(), null);
            List<Connection> connections = new ArrayList<>();
            SMBEventBus bus = new SMBEventBus(); ServerList servers = new ServerList();
            try {
                Connection original = connect(config, port, observer, connections, bus, servers);
                try (Session main = original.authenticate(identity)) {
                    observer.original(main, original);
                    SecretKey originalKey = main.getSessionContext().getSigningKey();
                    Connection active = original;
                    if (!mode.equals("original")) {
                        active = connect(config, port, observer, connections, bus, servers);
                        bindAt(main, active, identity, observer, nextMid(original));
                        original.close(true);
                        assertFalse(main.getConnection().isConnected(), "API migration remains unresolved research work");
                    }
                    SecretKey activeKey = main.getSigningKey(new SMB2Echo(SMB2Dialect.SMB_3_1_1).getHeader(), false, active);
                    if (!mode.equals("original")) assertFalse(Arrays.equals(originalKey.getEncoded(), activeKey.getEncoded()));
                    byte[][] retained = snapshot(main);
                    if (mode.equals("wrong-original")) {
                        long status = reauthenticate(main, active, config, identity, originalKey, activeKey, true, mode, 0);
                        assertEquals(NtStatus.STATUS_ACCESS_DENIED.getValue(), status);
                        echo(main, active);
                        System.out.printf("REAUTH_NEGATIVE status=%08x originalKeyRequestRefused=true activeChannelStillUsable=true%n", status);
                    } else {
                        String name = "reauth-" + UUID.randomUUID() + ".bin";
                        try (DiskShare share = (DiskShare) main.connectShare("share")) {
                            try (com.hierynomus.smbj.share.File file = share.openFile(name,
                                    EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE), null,
                                    SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                                byte[] data = new byte[131077]; new Random(47).nextBytes(data);
                                verifyContents(file, data);
                                for (int attempt = 0; attempt < 2; attempt++) {
                                    assertEquals(0, reauthenticate(main, active, config, identity, activeKey, activeKey, false, mode, attempt));
                                    byte[][] after = snapshot(main);
                                    for (int i = 0; i < retained.length; i++) assertArrayEquals(retained[i], after[i]);
                                    assertArrayEquals(activeKey.getEncoded(), main.getSigningKey(
                                            new SMB2Echo(SMB2Dialect.SMB_3_1_1).getHeader(), false, active).getEncoded());
                                    data[attempt] ^= 1; verifyContents(file, data);
                                    for (int i = 0; i < 32; i++) echo(main, active);
                                }
                                int authentications = 2, readbacks = 3;
                                if (mode.equals("bound")) {
                                    Connection added = connect(config, port, observer, connections, bus, servers);
                                    long first = nextMid(original) + 16;
                                    assertTrue(nextMid(active) > first, "Later binding stays below the existing operational MID cursor");
                                    int padding = bindAt(main, added, identity, observer, first);
                                    SecretKey addedKey = main.getSigningKey(new SMB2Echo(SMB2Dialect.SMB_3_1_1).getHeader(), false, added);
                                    assertFalse(Arrays.equals(activeKey.getEncoded(), addedKey.getEncoded()));
                                    assertEquals(2, main.getChannelCount());
                                    assertEquals(0, reauthenticate(main, added, config, identity, addedKey, addedKey, false, mode, 2));
                                    byte[][] after = snapshot(main);
                                    for (int i = 0; i < retained.length; i++) assertArrayEquals(retained[i], after[i]);
                                    data[2] ^= 1; verifyContents(file, data);
                                    echo(main, active); echo(main, added);
                                    authentications++; readbacks++;
                                    System.out.printf("REAUTH_LATER_BIND firstMID=%d padding=%d originalKeyHighWaterIndependentOfOperationalMIDs=true channels=2%n", first, padding);
                                }
                                System.out.printf("REAUTH_COMPLETE mode=%s successfulReauthentications=%d retainedKeys=true sameOpenReadbackBytes=%d%n",
                                        mode, authentications, data.length * readbacks);
                            } finally { share.rm(name); }
                        }
                    }
                }
            } finally {
                for (Connection connection : connections) connection.close(true);
            }
            if (mode.equals("wrong-original")) {
                AssertionError failure = assertThrows(AssertionError.class, () -> observer.verifyAndReport(mode, 0, 0));
                assertTrue(failure.getMessage().contains("Independent tag verification failed"));
            } else observer.verifyAndReport(mode, 0, mode.equals("original") ? 0 : 64);
            int established = 0;
            for (SpnegoAuthenticator authenticator : authenticators) {
                GSSContext context = context(authenticator);
                if (context != null && context.isEstablished()) {
                    Key exported = (Key) ((ExtendedGSSContext) context).inquireSecContext(InquireType.KRB5_GET_SESSION_KEY);
                    assertEquals(keyBytes, exported.getEncoded().length);
                    established++;
                }
            }
            assertTrue(established >= 3);
            System.out.printf("KERBEROS_CONTEXTS mode=%s established=%d rawKeyBytes=%d kerberos=true%n", mode, established, keyBytes);
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
        System.out.printf("KERBEROS_FIXTURE_STOPPED owner=%s id=%s%n", owner, cid);
    }

    private static Connection connect(SmbConfig config, int port, GmacWireObserver observer,
            List<Connection> connections, SMBEventBus bus, ServerList servers) throws Exception {
        Connection connection = new Connection(config, null, bus, servers);
        connections.add(connection); connection.connect("server.smbj.test", port); observer.register(connection);
        assertEquals(SMB3SigningAlgorithm.AES_GMAC, connection.getConnectionContext().getSigningAlgorithm());
        return connection;
    }

    private static int bindAt(Session main, Connection candidate, AuthenticationContext identity,
            GmacWireObserver observer, long first) throws Exception {
        int padding = 0;
        try (Session auxiliary = candidate.authenticate(identity)) {
            observer.auxiliary(auxiliary, candidate);
            assertFalse(Arrays.equals(main.getSessionContext().getSigningKey().getEncoded(),
                    auxiliary.getSessionContext().getSigningKey().getEncoded()));
            while (nextMid(candidate) < first) {
                assertTrue(padding++ < 16, "Bounded two-binding research only");
                echo(auxiliary, candidate);
            }
            assertEquals(first, nextMid(candidate));
            observer.reservation(candidate, first, 16);
            assertSame(main, candidate.bind(main)); observer.bound(main, candidate);
        }
        return padding;
    }

    private long reauthenticate(Session session, Connection connection, SmbConfig config, AuthenticationContext identity,
            SecretKey requestKey, SecretKey responseKey, boolean refusal, String mode, int attempt) throws Exception {
        SpnegoAuthenticator auth = new SpnegoAuthenticator(); authenticators.add(auth);
        auth.init(config);
        AuthenticateResponse token = auth.authenticate(identity, connection.getConnectionContext().getGssNegotiateToken(), connection.getConnectionContext());
        byte[] exported = null;
        PacketSignatory signatory = new PacketSignatory(config.getSecurityProvider());
        for (int round = 0; round < 16; round++) {
            if (token.getSessionKey() != null) exported = token.getSessionKey();
            Buffer.PlainBuffer output = new Buffer.PlainBuffer(Endian.LE); token.getNegToken().write(output);
            SMB2SessionSetup request = new SMB2SessionSetup(SMB2Dialect.SMB_3_1_1,
                    EnumSet.of(SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED), connection.getConnectionContext().getClientCapabilities());
            request.getHeader().setSessionId(session.getSessionId()); request.setSecurityBuffer(output.getCompactData());
            if (!refusal) assertArrayEquals(requestKey.getEncoded(), session.getSigningKey(request.getHeader(), true, connection).getEncoded());
            SMB2Packet raw = (refusal ? connection.<SMB2Packet>send(signatory.sign(request, requestKey))
                    : session.<SMB2Packet>send(request, connection)).get(5, TimeUnit.SECONDS);
            long status = raw.getHeader().getStatusCode();
            if (refusal) return status;
            assertTrue(status == 0 || status == NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue());
            assertEquals(session.getSessionId(), raw.getHeader().getSessionId());
            assertTrue(raw.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SIGNED));
            assertTrue(signatory.verify(new SMB2PacketData(Packets.getPacketBytes(raw)), responseKey));
            if (!Arrays.equals(responseKey.getEncoded(), session.getSessionContext().getSigningKey().getEncoded()))
                assertFalse(signatory.verify(new SMB2PacketData(Packets.getPacketBytes(raw)), session.getSessionContext().getSigningKey()));
            SMB2SessionSetup reply = (SMB2SessionSetup) raw;
            token = auth.authenticate(identity, reply.getSecurityBuffer(), connection.getConnectionContext());
            if (token != null && token.getSessionKey() != null) exported = token.getSessionKey();
            connection.sessionSetupAccepted(reply);
            System.out.printf("REAUTH_PHASE mode=%s attempt=%d round=%d mid=%d status=%08x selectedKeyVerified=true%n", mode, attempt, round, request.getHeader().getMessageId(), status);
            if (status == 0) {
                assertNotNull(exported);
                assertFalse(Arrays.equals(Arrays.copyOf(exported, 16), session.getSessionContext().getSessionKey().getEncoded()));
                return 0;
            }
            assertNotNull(token);
        }
        throw new IOException("Bounded reauthentication exchange limit reached");
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

    private static byte[][] snapshot(Session session) {
        SessionContext context = session.getSessionContext();
        SecretKey[] keys = {context.getSessionKey(), context.getSigningKey(), context.getEncryptionKey(), context.getDecryptionKey(), context.getApplicationKey()};
        byte[][] result = new byte[6][];
        for (int i = 0; i < keys.length; i++) result[i] = keys[i] == null ? null : keys[i].getEncoded().clone();
        result[5] = context.getPreauthIntegrityHashValue().clone(); return result;
    }

    private static void verifyContents(com.hierynomus.smbj.share.File file, byte[] data) {
        assertEquals(data.length, file.write(data, 0));
        byte[] actual = new byte[data.length]; assertEquals(data.length, file.read(actual, 0)); assertArrayEquals(data, actual);
    }

    private static void echo(Session session, Connection connection) throws Exception {
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1); request.getHeader().setSessionId(session.getSessionId());
        assertEquals(0, session.<SMB2Echo>send(request, connection).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
    }

    private static long nextMid(Connection connection) throws Exception {
        Field field = SequenceWindow.class.getDeclaredField("lowestAvailable"); field.setAccessible(true);
        return ((AtomicLong) field.get(connection.sequenceWindow)).get();
    }
}
