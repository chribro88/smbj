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
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Research only: bounded original-key reservations, never production binding orchestration. */
@Timeout(90)
class GmacConcurrentBootstrapIT {
    private static final int AUTHENTICATION_SLOTS = 16;
    private final List<Connection> owned = new ArrayList<>();
    private final AtomicLong reservationCursor = new AtomicLong();
    private final AtomicInteger reservations = new AtomicInteger(), bindings = new AtomicInteger(), pumpRequests = new AtomicInteger();
    private final SMBEventBus bus = new SMBEventBus();
    private final ServerList servers = new ServerList();
    private final GmacWireObserver observer = new GmacWireObserver();
    private final SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
            .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
            .withSecurityProvider(new BCSecurityProvider()).withSocketFactory(observer)
            .withAuthenticators(new NtlmAuthenticator.Factory()).withTimeout(10, TimeUnit.SECONDS).build();
    private String run;

    @ParameterizedTest
    @ValueSource(strings = {"none", "complete", "partial"})
    void concurrentReservationsSurviveLossWhileAnExistingOpenRemainsUsable(String fault) throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Explicit detached research only");
        run = "concurrent-" + fault;
        try {
            Connection anchor = connect(), original = connect();
            try (Session main = original.authenticate(authentication())) {
                observer.original(main, original);
                byte[] originalKey = main.getSessionContext().getSigningKey().getEncoded().clone();
                long initialCursor = nextMessageId(original);
                reservationCursor.set(initialCursor);
                bind(main, anchor, "none", null, null);
                original.close(true);
                assertEquals(1, main.getChannelCount());
                assertFalse(main.getConnection().isConnected(), "Public connection ownership remains unresolved research work");
                Connection[] candidates = {connect(), connect(), connect()};
                String name = "concurrent-auxiliary-" + UUID.randomUUID() + ".bin";
                try (DiskShare share = (DiskShare) main.connectShare("share")) {
                    try (File file = share.openFile(name, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
                            SMB2CreateDisposition.FILE_CREATE, EnumSet.noneOf(SMB2CreateOptions.class))) {
                        byte[] expected = new byte[131072]; new Random(47).nextBytes(expected);
                        verifyContents(file, expected);
                        CountDownLatch ready = new CountDownLatch(4), start = new CountDownLatch(1);
                        CountDownLatch entered = new CountDownLatch(3), release = new CountDownLatch(1);
                        AtomicInteger failed = new AtomicInteger();
                        ExecutorService workers = Executors.newFixedThreadPool(4);
                        try {
                            List<Future<?>> tasks = new ArrayList<>();
                            for (int i = 0; i < candidates.length; i++) {
                                final int index = i;
                                tasks.add(workers.submit(() -> {
                                    ready.countDown(); start.await();
                                    try {
                                        bind(main, candidates[index], index == 0 ? fault : "none", entered, release);
                                        assertTrue(index != 0 || "none".equals(fault), "Injected binding must fail");
                                    } catch (IOException failure) {
                                        if (index != 0 || "none".equals(fault) || !observer.faultTriggered(candidates[index])) throw failure;
                                        assertTrue(candidates[index].isClosed());
                                        failed.incrementAndGet();
                                    }
                                    return null;
                                }));
                            }
                            tasks.add(workers.submit(() -> {
                                ready.countDown(); start.await();
                                try {
                                    assertTrue(entered.await(5, TimeUnit.SECONDS), "Every concurrent binding reaches its first write");
                                    expected[0] ^= 1;
                                    verifyContents(file, expected);
                                    System.out.printf("AUXCON_OVERLAP run=%s originalKeyBindingWrites=3 heldOpenReadbackBytes=%d success=true%n", run, expected.length);
                                } finally { release.countDown(); }
                                for (int i = 0; i < 8; i++) { expected[1] ^= 1; verifyContents(file, expected); }
                                for (int i = 0; i < 256; i++) echo(main);
                                return null;
                            }));
                            assertTrue(ready.await(5, TimeUnit.SECONDS));
                            start.countDown();
                            for (Future<?> task : tasks) task.get(30, TimeUnit.SECONDS);
                        } finally {
                            release.countDown(); start.countDown(); workers.shutdownNow();
                            assertTrue(workers.awaitTermination(10, TimeUnit.SECONDS));
                        }
                        assertEquals("none".equals(fault) ? 0 : 1, failed.get());
                        assertEquals("none".equals(fault) ? 4 : 3, main.getChannelCount());
                        if (!"none".equals(fault)) {
                            long burned = reservationCursor.get();
                            bind(main, connect(), "none", null, null);
                            assertEquals(burned + AUTHENTICATION_SLOTS, reservationCursor.get(), "Retry never releases or reuses a failed interval");
                        }
                        assertEquals(4, main.getChannelCount());
                        assertEquals(4, bindings.get());
                        int count = "none".equals(fault) ? 4 : 5;
                        assertEquals(count, reservations.get());
                        assertEquals(initialCursor + count * AUTHENTICATION_SLOTS, reservationCursor.get());
                        assertEquals(AUTHENTICATION_SLOTS * count * (count - 1) / 2, pumpRequests.get());
                        assertEquals("partial".equals(fault) ? 76 : 0, observer.partialClientBytes(candidates[0]));
                        assertArrayEquals(originalKey, main.getSessionContext().getSigningKey().getEncoded());
                        verifyContents(file, expected);
                        System.out.printf("AUXCON_COMPLETE run=%s successfulBindings=%d reservations=%d pumpRequests=%d reservedEnd=%d originalConnectionClosed=true heldOpenVerifiedBytes=%d%n",
                                run, bindings.get(), reservations.get(), pumpRequests.get(), reservationCursor.get(), expected.length * 11);
                    } finally { share.rm(name); }
                }
            }
        } finally {
            closeOwned();
            observer.verifyAndReport(run, 3);
        }
    }

    @Test
    void observerStillRejectsOrdinaryUnsafeBindings() throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Explicit detached research only");
        try {
            Connection original = connect();
            try (Session main = original.authenticate(authentication())) {
                observer.original(main, original);
                for (int i = 0; i < 2; i++) {
                    Connection candidate = connect();
                    assertSame(main, candidate.bind(main)); observer.bound(main, candidate);
                }
            }
        } finally { closeOwned(); }
        AssertionError rejected = assertThrows(AssertionError.class, () -> observer.verifyAndReport("concurrent-unsafe-control", -1));
        assertTrue(rejected.getMessage().contains("Different authenticated bytes reused actual key/nonce"));
        System.out.println("AUXCON_NEGATIVE_CONTROL successfulLegitimateBindings=2 result=expected_nonce_reuse_detected");
    }

    @ParameterizedTest
    @ValueSource(strings = {"complete", "partial"})
    void failedBootstrapForcesCloseWithoutLogoff(String fault) throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Explicit detached research only");
        run = "bootstrap-abort-" + fault;
        Session main = null;
        try {
            Connection candidate = connect(), original = connect();
            main = original.authenticate(authentication()); observer.original(main, original);
            reservationCursor.set(nextMessageId(original));
            Session session = main;
            assertThrows(IOException.class, () -> bind(session, candidate, fault, new CountDownLatch(1), new CountDownLatch(0)));
            assertTrue(observer.faultTriggered(candidate));
            assertEquals(1, main.getChannelCount(), "Failed candidate is never published");
            assertEquals(0, bindings.get());
            assertEquals(1, reservations.get());
            assertEquals(19, reservationCursor.get());
            assertEquals("partial".equals(fault) ? 76 : 0, observer.partialClientBytes(candidate));
            // LOGOFF on the original connection would reuse a reserved original-key nonce.
            main.failChannels(new IOException("Unpublished bootstrap aborted"));
            original.close(true);
            assertTrue(original.isClosed());
            System.out.printf("AUXCON_BOOTSTRAP_ABORT run=%s logoffSent=false originalConnectionClosed=true failedReservationBurned=true%n", run);
        } finally {
            if (main != null) main.failChannels(new IOException("Research complete"));
            closeOwned();
            observer.verifyAndReport(run, 0, 0);
        }
    }

    @Test
    void observerRejectsBootstrapLogoffAfterPartialBinding() throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Explicit detached research only");
        Session main = null;
        try {
            Connection candidate = connect(), original = connect();
            main = original.authenticate(authentication()); observer.original(main, original);
            reservationCursor.set(nextMessageId(original));
            Session session = main;
            assertThrows(IOException.class, () -> bind(session, candidate, "partial", new CountDownLatch(1), new CountDownLatch(0)));
            assertTrue(observer.faultTriggered(candidate));
            main.close();
        } finally {
            if (main != null) main.failChannels(new IOException("Research complete"));
            closeOwned();
        }
        AssertionError rejected = assertThrows(AssertionError.class, () -> observer.verifyAndReport("unsafe-bootstrap-logoff", 0, 0));
        assertTrue(rejected.getMessage().contains("Different authenticated bytes reused actual key/nonce"));
        System.out.println("AUXCON_BOOTSTRAP_NEGATIVE_CONTROL result=expected_logoff_nonce_reuse_detected");
    }

    private void bind(Session main, Connection candidate, String fault, CountDownLatch entered, CountDownLatch release) throws Exception {
        long started = System.nanoTime();
        Session auxiliary = candidate.authenticate(authentication());
        Throwable primary = null;
        try {
            observer.auxiliary(auxiliary, candidate);
            assertFalse(Arrays.equals(main.getSessionContext().getSigningKey().getEncoded(), auxiliary.getSessionContext().getSigningKey().getEncoded()));
            long cursor = nextMessageId(candidate), first = reserve(cursor);
            int pumped = 0;
            while (nextMessageId(candidate) < first) { echo(auxiliary); pumped++; pumpRequests.incrementAndGet(); }
            assertEquals(first, nextMessageId(candidate), "Native MID allocation must reach the reserved interval without skipping");
            observer.reservation(candidate, first, AUTHENTICATION_SLOTS);
            System.out.printf("AUXCON_RESERVE run=%s firstMID=%d reservedEnd=%d padding=%d fault=%s%n", run, first, first + AUTHENTICATION_SLOTS, pumped, fault);
            if (entered != null) observer.gateBinding(candidate, entered, release, "partial".equals(fault));
            if ("complete".equals(fault)) observer.failNextBinding(candidate);
            assertSame(main, candidate.bind(main));
            observer.bound(main, candidate);
            // Successful intervals stay burned too; no global I/O lock or cursor-based tail release.
            bindings.incrementAndGet();
            echo(main, candidate);
            System.out.printf("AUXCON_BIND run=%s firstMID=%d reservedEnd=%d elapsedMicros=%d%n", run, first, first + AUTHENTICATION_SLOTS,
                    TimeUnit.NANOSECONDS.toMicros(System.nanoTime() - started));
        } catch (Exception | Error failure) { primary = failure; throw failure; }
        finally {
            try { auxiliary.close(); }
            catch (IOException | RuntimeException | Error cleanup) {
                if (primary == null) throw cleanup;
                if (cleanup != primary) primary.addSuppressed(cleanup);
            }
        }
        assertTrue(candidate.isConnected());
        echo(main, candidate);
    }

    private long reserve(long nativeCursor) {
        while (true) {
            long current = reservationCursor.get(), first = Math.max(current, nativeCursor);
            assertTrue(first >= 0 && first - nativeCursor <= 256, "Bounded research prefix, not an arbitrary lifetime allocator");
            if (reservationCursor.compareAndSet(current, first + AUTHENTICATION_SLOTS)) {
                reservations.incrementAndGet(); return first;
            }
        }
    }

    private Connection connect() throws IOException {
        // Setup and observer registration stay sequential; only authentication/binding/application traffic races.
        Connection connection = new Connection(config, null, bus, servers);
        owned.add(connection); connection.connect("127.0.0.1", 36535); observer.register(connection);
        assertEquals(SMB3SigningAlgorithm.AES_GMAC, connection.getConnectionContext().getSigningAlgorithm());
        return connection;
    }

    private static AuthenticationContext authentication() {
        return new AuthenticationContext("smbtest", "TestOnly123!".toCharArray(), "WORKGROUP");
    }

    private static void echo(Session session) throws Exception {
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1); packet.getHeader().setSessionId(session.getSessionId());
        assertEquals(0, session.<SMB2Echo>send(packet).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
    }

    private static void echo(Session session, Connection connection) throws Exception {
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1); packet.getHeader().setSessionId(session.getSessionId());
        assertEquals(0, session.<SMB2Echo>send(packet, connection).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
    }

    private static void verifyContents(File file, byte[] expected) {
        assertEquals(expected.length, file.write(expected, 0));
        byte[] actual = new byte[expected.length]; assertEquals(actual.length, file.read(actual, 0)); assertArrayEquals(expected, actual);
    }

    private static long nextMessageId(Connection connection) throws ReflectiveOperationException {
        Field field = SequenceWindow.class.getDeclaredField("lowestAvailable"); field.setAccessible(true);
        return ((AtomicLong) field.get(connection.sequenceWindow)).get();
    }

    private void closeOwned() {
        List<IOException> failures = new ArrayList<>();
        for (Connection connection : owned) try { connection.close(true); } catch (IOException failure) { failures.add(failure); }
        assertTrue(failures.isEmpty(), "Every research transport must close: " + failures);
    }
}
