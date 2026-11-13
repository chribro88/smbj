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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Research only. Overlay into the detached experiment, never into production. */
class GmacAuxiliaryBootstrapIT {
    private static final int AUTHENTICATION_SLOTS = 16;
    private final List<Connection> owned = new ArrayList<>();
    private final SortedSet<Long> originalKeySlots = new TreeSet<>();
    private final SMBEventBus bus = new SMBEventBus();
    private final ServerList servers = new ServerList();
    private final GmacWireObserver observer = new GmacWireObserver();
    private final SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
            .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
            .withSecurityProvider(new BCSecurityProvider()).withSocketFactory(observer).withAuthenticators(new NtlmAuthenticator.Factory())
            .withTimeout(5, TimeUnit.SECONDS).build();
    private int bindings;
    private int pumpRequests;
    private String run;

    @ParameterizedTest
    @CsvSource({"0,false", "3,false", "7,false", "3,true"})
    void auxiliarySessionConsumesOccupiedSlotsAndOriginalKeyConnectionRetires(int replacements, boolean lostBinding) throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Explicit detached research run only");
        run = replacements + "-" + lostBinding;
        try {
            Connection publicConnection = connect();
            Connection originalKeyConnection = connect();
            try (Session main = originalKeyConnection.authenticate(authentication())) {
                byte[] originalKey = main.getSessionContext().getSigningKey().getEncoded().clone();
                observer.original(main, originalKeyConnection);
                originalKeySlots.add(nextMessageId(originalKeyConnection) - 1);
                bind(main, publicConnection);
                originalKeyConnection.close(true);
                assertTrue(publicConnection.isConnected());
                assertEquals(1, main.getChannelCount());
                // This API/lifecycle consequence must be resolved before selecting the construction.
                assertFalse(main.getConnection().isConnected());
                for (int i = 0; i < 256; i++) echo(main);
                String name = "auxiliary-research-" + UUID.randomUUID() + ".bin";
                try (DiskShare share = (DiskShare) main.connectShare("share")) {
                    try (File file = share.openFile(name, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
                            SMB2CreateDisposition.FILE_CREATE, EnumSet.noneOf(SMB2CreateOptions.class))) {
                        byte[] expected = new byte[131072];
                        new Random(47).nextBytes(expected);
                        verifyContents(file, expected);
                        if (lostBinding) {
                            int occupied = originalKeySlots.size();
                            Connection failed = connect();
                            assertThrows(IOException.class, () -> bind(main, failed, true));
                            assertTrue(observer.faultTriggered(failed));
                            assertEquals(occupied + AUTHENTICATION_SLOTS, originalKeySlots.size(), "Failed reservation stays burned");
                            assertEquals(1, main.getChannelCount());
                            verifyContents(file, expected);
                        }
                        Connection active = publicConnection;
                        for (int i = 0; i < replacements; i++) {
                            Connection replacement = connect();
                            bind(main, replacement);
                            active.close(true);
                            active = replacement;
                            assertEquals(1, main.getChannelCount());
                            expected[0] ^= 1;
                            verifyContents(file, expected);
                            assertArrayEquals(originalKey, main.getSessionContext().getSigningKey().getEncoded());
                        }
                        assertEquals(replacements + 1, bindings);
                        assertEquals(replacements * (replacements + 1) + (lostBinding ? AUTHENTICATION_SLOTS * replacements + 2 : 0), pumpRequests);
                        System.out.printf("AUXPROTO_COMPLETE run=%s replacements=%d lostBinding=%s bindings=%d pumpRequests=%d initialApplicationEchos=256 verifiedBytes=%d originalKeyUnchanged=true originalConnectionClosed=true%n",
                                run, replacements, lostBinding, bindings, pumpRequests, expected.length * (replacements + 1 + (lostBinding ? 1 : 0)));
                    } finally {
                        share.rm(name);
                    }
                }
            }
        } finally {
            closeOwned();
            observer.verifyAndReport(run, replacements);
        }
    }

    @Test
    void independentObserverRejectsOrdinaryUnsafeBindings() throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Explicit detached research run only");
        try {
            Connection original = connect();
            try (Session main = original.authenticate(authentication())) {
                observer.original(main, original);
                for (int i = 0; i < 2; i++) {
                    Connection candidate = connect();
                    assertSame(main, candidate.bind(main));
                    observer.bound(main, candidate);
                }
            }
        } finally {
            closeOwned();
        }
        AssertionError rejected = assertThrows(AssertionError.class, () -> observer.verifyAndReport("unsafe-control", -1));
        assertTrue(rejected.getMessage().contains("Different authenticated bytes reused actual key/nonce"));
        System.out.println("AUXWIRE_NEGATIVE_CONTROL successfulLegitimateBindings=2 result=expected_nonce_reuse_detected");
    }

    private void closeOwned() {
        List<IOException> failures = new ArrayList<>();
        for (Connection connection : owned) {
            try { connection.close(true); }
            catch (IOException failure) { failures.add(failure); }
        }
        assertTrue(failures.isEmpty(), "Every research transport must close: " + failures);
    }

    private void bind(Session main, Connection candidate) throws Exception {
        bind(main, candidate, false);
    }

    private void bind(Session main, Connection candidate, boolean loseRequest) throws Exception {
        long started = System.nanoTime();
        Session auxiliary = candidate.authenticate(authentication());
        Throwable primary = null;
        try {
            observer.auxiliary(auxiliary, candidate);
            assertFalse(Arrays.equals(main.getSessionContext().getSigningKey().getEncoded(),
                    auxiliary.getSessionContext().getSigningKey().getEncoded()));
            int pumped = 0;
            long first;
            while (true) {
                first = nextMessageId(candidate);
                boolean available = true;
                for (int i = 0; i < AUTHENTICATION_SLOTS; i++) available &= !originalKeySlots.contains(first + i);
                if (available) break;
                echo(auxiliary);
                pumped++;
                pumpRequests++;
                assertTrue(pumped <= 256, "This bounded prototype does not qualify arbitrary lifetime cost");
            }
            for (int i = 0; i < AUTHENTICATION_SLOTS; i++) assertTrue(originalKeySlots.add(first + i));
            if (loseRequest) observer.failNextBinding(candidate);
            // Native send allocates every MID. The cursor is read, never assigned or skipped.
            assertSame(main, candidate.bind(main));
            observer.bound(main, candidate);
            long after = nextMessageId(candidate);
            assertTrue(after > first && after <= first + AUTHENTICATION_SLOTS);
            for (long unused = after; unused < first + AUTHENTICATION_SLOTS; unused++) originalKeySlots.remove(unused);
            bindings++;
            System.out.printf("AUXPROTO_BIND run=%s binding=%d firstMID=%d originalKeyRequests=%d pumpRequests=%d elapsedMicros=%d%n",
                    run, bindings, first, after - first, pumped, TimeUnit.NANOSECONDS.toMicros(System.nanoTime() - started));
            echo(main, candidate);
            System.out.println("AUXPROTO_PINNED_ECHO phase=before-auxiliary-logoff success=true");
        } catch (Exception | Error failure) {
            primary = failure;
            throw failure;
        } finally {
            try { auxiliary.close(); }
            catch (IOException | RuntimeException | Error cleanup) {
                if (primary == null) throw cleanup;
                // A connection's cached terminal error can be returned by both calls.
                if (cleanup != primary) primary.addSuppressed(cleanup);
            }
        }
        assertTrue(candidate.isConnected(), "Auxiliary LOGOFF must leave the bound physical channel usable");
        echo(main, candidate);
        System.out.println("AUXPROTO_PINNED_ECHO phase=after-auxiliary-logoff success=true");
    }

    private Connection connect() throws IOException {
        Connection connection = new Connection(config, null, bus, servers);
        owned.add(connection);
        connection.connect("127.0.0.1", 36532);
        observer.register(connection);
        assertEquals(SMB3SigningAlgorithm.AES_GMAC, connection.getConnectionContext().getSigningAlgorithm());
        return connection;
    }

    private static AuthenticationContext authentication() {
        return new AuthenticationContext("smbtest", "TestOnly123!".toCharArray(), "WORKGROUP");
    }

    private static void echo(Session session) throws Exception {
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        request.getHeader().setSessionId(session.getSessionId());
        SMB2Echo response = session.<SMB2Echo>send(request).get(5, TimeUnit.SECONDS);
        assertEquals(0, response.getHeader().getStatusCode());
    }

    private static void echo(Session session, Connection connection) throws Exception {
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        request.getHeader().setSessionId(session.getSessionId());
        SMB2Echo response = session.<SMB2Echo>send(request, connection).get(5, TimeUnit.SECONDS);
        assertEquals(0, response.getHeader().getStatusCode());
    }

    private static void verifyContents(File file, byte[] expected) {
        assertEquals(expected.length, file.write(expected, 0));
        byte[] actual = new byte[expected.length];
        assertEquals(actual.length, file.read(actual, 0));
        assertArrayEquals(expected, actual);
    }

    private static long nextMessageId(Connection connection) throws ReflectiveOperationException {
        // Observe the native allocation cursor without consuming an unsent credit/MID.
        Field field = SequenceWindow.class.getDeclaredField("lowestAvailable");
        field.setAccessible(true);
        return ((AtomicLong) field.get(connection.sequenceWindow)).get();
    }
}
