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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.connection.ConnectionContext;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.SequenceWindow;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Bounded ownership research; not the public authentication implementation. */
@Timeout(90)
class GmacPublicAnchorIT {
    private final GmacWireObserver observer = new GmacWireObserver();
    private final SMBEventBus bus = new SMBEventBus();
    private final List<Connection> owned = new ArrayList<>();
    private final GateFactory authenticators = new GateFactory();
    private final SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
            .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
            .withSecurityProvider(new BCSecurityProvider()).withSocketFactory(observer)
            .withAuthenticators(authenticators).withTimeout(10, TimeUnit.SECONDS).build();
    private final int port = Integer.parseInt(System.getenv("SMB_TEST_PORTS"));

    @ParameterizedTest
    @ValueSource(ints = {0, 1024})
    void callerConnectionAndOlderOpenSurviveBootstrapAndNewSessionClose(int priorEchoes) throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Detached research opt-in required");
        String run = "public-anchor-" + priorEchoes;
        Throwable primary = null;
        try (SMBClient client = new SMBClient(config, bus)) {
            Connection caller = client.connect("127.0.0.1", port); observer.register(caller);
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, caller.getConnectionContext().getSigningAlgorithm());
            try (Session older = caller.authenticate(authentication())) {
                observer.auxiliary(older, caller);
                try (DiskShare oldShare = (DiskShare) older.connectShare("share")) {
                    String oldName = "older-" + UUID.randomUUID() + ".bin";
                    try (File oldFile = open(oldShare, oldName)) {
                        byte[] oldBytes = new byte[131077]; new Random(87).nextBytes(oldBytes);
                        verifyContents(oldFile, oldBytes);
                        for (int i = 0; i < priorEchoes; i++) echo(older, caller);
                        Connection bootstrap = connect(client);
                        try (Session main = bootstrap.authenticate(authentication())) {
                            observer.original(main, bootstrap);
                            byte[] originalKey = main.getSessionContext().getSigningKey().getEncoded().clone();
                            long originalEnd = nextMessageId(bootstrap);
                            Set<Long> anchorMids;
                            try (Session auxiliary = caller.authenticate(authentication())) {
                                observer.auxiliary(auxiliary, caller);
                                assertDistinct(main, auxiliary);
                                assertTrue(nextMessageId(caller) >= originalEnd);
                                CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
                                authenticators.next.set(new CountDownLatch[] {entered, release});
                                ExecutorService worker = Executors.newSingleThreadExecutor();
                                try {
                                    Future<Session> binding = worker.submit(() -> caller.bind(main));
                                    assertTrue(entered.await(5, TimeUnit.SECONDS));
                                    oldBytes[0] ^= 1; verifyContents(oldFile, oldBytes);
                                    System.out.printf("PUBLIC_ANCHOR_OVERLAP run=%s olderOpenReadbackBytes=%d authenticationRoundHeld=true%n", run, oldBytes.length);
                                    release.countDown();
                                    assertSame(main, binding.get(10, TimeUnit.SECONDS));
                                } finally {
                                    release.countDown(); worker.shutdownNow();
                                    assertTrue(worker.awaitTermination(10, TimeUnit.SECONDS));
                                }
                                observer.bound(main, caller);
                                anchorMids = observer.bindingMids(caller);
                                assertEquals(2, anchorMids.size());
                                assertTrue(Collections.max(anchorMids) - Collections.min(anchorMids) > 1,
                                        "Older-session I/O interleaves the two original-key binding inputs");
                                for (long mid : anchorMids) assertTrue(mid >= originalEnd);
                                main.adoptBootstrapChannel(bootstrap, caller);
                                bootstrap.close(true);
                            }
                            assertTrue(bootstrap.isClosed());
                            assertSame(caller, main.getConnection());
                            assertSame(client, main.getConnection().getClient());
                            assertEquals(1, main.getChannelCount());
                            assertTrue(caller.isConnected());
                            verifyContents(oldFile, oldBytes);
                            echo(main, caller);
                            assertPooled(client, caller);

                            try (DiskShare share = (DiskShare) main.connectShare("share")) {
                                String name = "new-" + UUID.randomUUID() + ".bin";
                                try (File file = open(share, name)) {
                                    byte[] bytes = new byte[131077]; new Random(91).nextBytes(bytes);
                                    verifyContents(file, bytes);
                                    Connection candidate = connect(client);
                                    long first;
                                    int padded = 0;
                                    try (Session auxiliary = candidate.authenticate(authentication())) {
                                        observer.auxiliary(auxiliary, candidate);
                                        assertDistinct(main, auxiliary);
                                        first = reserve(originalEnd, nextMessageId(candidate), anchorMids);
                                        while (nextMessageId(candidate) < first) { echo(auxiliary, candidate); padded++; }
                                        observer.reservation(candidate, first, 16);
                                        assertSame(main, candidate.bind(main));
                                        observer.bound(main, candidate);
                                    }
                                    for (long mid : observer.bindingMids(candidate)) assertFalse(anchorMids.contains(mid));
                                    assertEquals(2, main.getChannelCount());
                                    if (priorEchoes > 0) {
                                        assertEquals(originalEnd, first, "Busy caller must not raise fresh-candidate padding cursor");
                                        assertEquals(0, padded);
                                        assertTrue(first + 16 <= Collections.min(anchorMids));
                                    }
                                    // Round-robin must send both reads and writes over both operational channels.
                                    for (int i = 0; i < 8; i++) { bytes[i] ^= 1; verifyContents(file, bytes); echo(main); }
                                    verifyContents(oldFile, oldBytes);
                                    assertArrayEquals(originalKey, main.getSessionContext().getSigningKey().getEncoded());
                                    System.out.printf("PUBLIC_ANCHOR_BOUND run=%s originalPrefixEnd=%d anchorMids=%s freshReservationFirst=%d freshReservationEnd=%d padding=%d sameOpenReadbackBytes=%d%n",
                                            run, originalEnd, new TreeSet<>(anchorMids), first, first + 16, padded, bytes.length * 9);
                                } finally { share.rm(name); }
                            }
                        }
                        assertTrue(caller.isConnected(), "Closing new session preserves the caller's older session");
                        assertEquals(1, older.getChannelCount());
                        oldBytes[1] ^= 1; verifyContents(oldFile, oldBytes);
                        echo(older, caller);
                        assertPooled(client, caller);
                        System.out.printf("PUBLIC_ANCHOR_COMPLETE run=%s canonicalConnectionLive=true clientIdentityPreserved=true pooledIdentityPreserved=true olderSessionSurvives=true signing=AES_GMAC olderOpenReadbackBytes=%d%n", run, oldBytes.length * 5);
                    } finally { oldShare.rm(oldName); }
                }
            }
        } catch (Exception | Error failure) {
            primary = failure; throw failure;
        } finally {
            try {
                for (Connection connection : owned) connection.close(true);
                observer.verifyAndReport(run, 1, 20);
            } catch (Exception | Error cleanup) {
                if (primary == null) throw cleanup;
                if (primary != cleanup) primary.addSuppressed(cleanup);
            }
        }
    }

    private static final class GateFactory extends NtlmAuthenticator.Factory {
        private final AtomicReference<CountDownLatch[]> next = new AtomicReference<>();

        @Override public NtlmAuthenticator create() {
            CountDownLatch[] gate = next.getAndSet(null);
            return new NtlmAuthenticator() {
                private int rounds;
                @Override public AuthenticateResponse authenticate(AuthenticationContext context, byte[] token,
                        ConnectionContext connection) throws IOException {
                    if (++rounds == 2 && gate != null) {
                        gate[0].countDown();
                        try {
                            if (!gate[1].await(10, TimeUnit.SECONDS)) throw new IOException("Authentication-round gate expired");
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt(); throw new IOException(interrupted);
                        }
                    }
                    return super.authenticate(context, token, connection);
                }
            };
        }
    }

    private Connection connect(SMBClient client) throws IOException {
        Connection connection = new Connection(config, client, bus, client.getServerList());
        owned.add(connection); connection.connect("127.0.0.1", port); observer.register(connection);
        assertEquals(SMB3SigningAlgorithm.AES_GMAC, connection.getConnectionContext().getSigningAlgorithm());
        return connection;
    }

    private static long reserve(long originalEnd, long cursor, Set<Long> anchorMids) {
        long first = Math.max(originalEnd, cursor);
        boolean intersects;
        do {
            intersects = false;
            for (long mid : anchorMids) {
                if (mid >= first && mid < first + 16) {
                    first = mid + 1; intersects = true; break;
                }
            }
        } while (intersects);
        assertTrue(first >= 0 && first - cursor <= 256, "Bounded one-candidate experiment");
        return first;
    }

    private void assertPooled(SMBClient client, Connection caller) throws IOException {
        try (Connection lease = client.connect("127.0.0.1", port)) {
            assertSame(caller, lease, "Private-bootstrap closure must not evict the caller's pooled connection");
        }
        assertTrue(caller.isConnected());
    }

    private static void assertDistinct(Session main, Session auxiliary) {
        assertFalse(Arrays.equals(main.getSessionContext().getSigningKey().getEncoded(), auxiliary.getSessionContext().getSigningKey().getEncoded()));
    }

    private static AuthenticationContext authentication() {
        return new AuthenticationContext(System.getenv("SMB_TEST_USERNAME"), System.getenv("SMB_TEST_PASSWORD").toCharArray(), System.getenv("SMB_TEST_DOMAIN"));
    }

    private static File open(DiskShare share, String name) {
        return share.openFile(name, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_CREATE, EnumSet.noneOf(SMB2CreateOptions.class));
    }

    private static void verifyContents(File file, byte[] expected) {
        assertEquals(expected.length, file.write(expected, 0));
        byte[] actual = new byte[expected.length]; assertEquals(actual.length, file.read(actual, 0)); assertArrayEquals(expected, actual);
    }

    private static void echo(Session session) throws Exception {
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1); packet.getHeader().setSessionId(session.getSessionId());
        assertEquals(0, session.<SMB2Echo>send(packet).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
    }

    private static void echo(Session session, Connection connection) throws Exception {
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1); packet.getHeader().setSessionId(session.getSessionId());
        assertEquals(0, session.<SMB2Echo>send(packet, connection).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
    }

    private static long nextMessageId(Connection connection) throws ReflectiveOperationException {
        // Research-only observation: never mutate the native sequence or credits.
        Field sequence = Connection.class.getDeclaredField("sequenceWindow"); sequence.setAccessible(true);
        Field cursor = SequenceWindow.class.getDeclaredField("lowestAvailable"); cursor.setAccessible(true);
        return ((AtomicLong) cursor.get(sequence.get(connection))).get();
    }
}
