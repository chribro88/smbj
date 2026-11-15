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
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.session.Session;
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

/** Detached native research: an original-key nonce reserved for unpublished-session abort. */
@Timeout(60)
class GmacBootstrapAbortIT {
    private final GmacWireObserver observer = new GmacWireObserver();
    private final SMBEventBus bus = new SMBEventBus();
    private final RecordingFactory authenticators = new RecordingFactory();
    private final SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
            .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withSigningRequired(true)
            .withSecurityProvider(new BCSecurityProvider()).withSocketFactory(observer)
            .withAuthenticators(authenticators).withTimeout(10, TimeUnit.SECONDS)
            .withTransactTimeout(2, TimeUnit.SECONDS).build();
    private final int port = Integer.parseInt(System.getenv("SMB_TEST_PORTS"));
    private final List<Connection> owned = new ArrayList<>();

    @ParameterizedTest
    @ValueSource(strings = {"bad-final/fresh", "bad-final/open", "lost-final/fresh", "lost-final/open",
            "bad-final/root-loss", "bad-final/root-loss/open", "lost-final/root-loss", "lost-final/root-loss/open"})
    void reservedLogoffAbortsUnpublishedBindingAndPreservesBorrowedConnection(String scenario) throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Explicit detached research opt-in required");
        String mode = scenario.split("/")[0];
        boolean existingOpen = scenario.endsWith("/open");
        boolean rootLoss = scenario.contains("/root-loss");
        String run = scenario.replace('/', '-');
        Throwable primary = null;
        try (SMBClient client = new SMBClient(config, bus)) {
            Connection caller = client.connect("127.0.0.1", port); observer.register(caller);
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, caller.getConnectionContext().getSigningAlgorithm());
            try (Session older = caller.authenticate(authentication())) {
                observer.auxiliary(older, caller);
                String name = "abort-older-" + UUID.randomUUID() + ".bin";
                byte[] bytes = new byte[131077]; new Random(49).nextBytes(bytes);
                try (DiskShare before = existingOpen ? (DiskShare) older.connectShare("share") : null) {
                    try (File file = before == null ? null : open(before, name)) {
                        if (file != null) verifyContents(file, bytes);
                        Connection bootstrap = connect(client);
                        try (Session main = bootstrap.authenticate(authentication())) {
                            observer.original(main, bootstrap);
                            long abortMid = nextMessageId(bootstrap);
                            assertEquals(3, abortMid);
                            observer.reserveAbort(abortMid);
                            byte[] originalKey = main.getSessionContext().getSigningKey().getEncoded().clone();
                            int padding = 0;
                            while (nextMessageId(caller) <= abortMid) { echo(older); padding++; }
                            assertEquals(existingOpen ? 0 : 1, padding);
                            long first = nextMessageId(caller);
                            observer.reservation(caller, first, 16);
                            byte[] negotiateHash = caller.getConnectionContext().getPreauthIntegrityHashValue().clone();
                            CountDownLatch fault = observer.faultFinal(caller, mode);
                            ExecutorService worker = Executors.newSingleThreadExecutor();
                            try {
                                Future<Session> binding = worker.submit(() -> caller.bind(main));
                                assertTrue(fault.await(5, TimeUnit.SECONDS), "Peer completes binding before client input fault");
                                long finalMid = observer.finalMid(caller);
                                Request abandoned = "lost-final".equals(mode)
                                        ? caller.outstandingRequests.getRequestByMessageId(finalMid) : null;
                                if ("lost-final".equals(mode)) {
                                    assertNotNull(abandoned); assertFalse(abandoned.getPromise().isFulfilled());
                                    assertFalse(binding.isDone(), "Missing-final wait remains pending while older traffic progresses");
                                }
                                echo(older);
                                if (file != null) { bytes[0] ^= 1; verifyContents(file, bytes); }
                                if ("lost-final".equals(mode)) assertFalse(binding.isDone(),
                                        "Older-session work finishes while the missing-final wait is still pending");
                                ExecutionException rejected = assertThrows(ExecutionException.class,
                                        () -> binding.get(10, TimeUnit.SECONDS));
                                assertTrue(rejected.getCause() instanceof IOException);
                                if ("lost-final".equals(mode)) {
                                    assertTrue(hasCause(rejected, TimeoutException.class));
                                    assertTrue(abandoned.getPromise().isFulfilled());
                                    assertNull(caller.outstandingRequests.getRequestByCancelId(abandoned.getCancelId()));
                                    assertThrows(ExecutionException.class, () -> abandoned.getFuture(() -> { }).get(1, TimeUnit.SECONDS));
                                } else {
                                    assertTrue(rejected.getCause().getMessage().contains("response signature is invalid"));
                                }
                                assertFalse(caller.outstandingRequests.isOutstanding(finalMid));
                                assertNull(caller.getSessionTable().find(main.getSessionId()), "No provisional session table entry survives");
                                assertEquals(1, main.getChannelCount(), "Failed binding never publishes a channel");
                                observer.provisionalBinding(caller, authenticators.exported.get(), negotiateHash);
                                Set<Long> used = observer.bindingMids(caller);
                                assertEquals(2, used.size()); assertFalse(used.contains(abortMid));
                                assertEquals(abortMid, nextMessageId(bootstrap), "Private bootstrap stays quiescent for its abort");
                                assertArrayEquals(originalKey, main.getSessionContext().getSigningKey().getEncoded());
                                assertTrue(caller.isConnected());
                                assertSame(older, caller.getSessionTable().find(older.getSessionId()));
                                if (rootLoss) {
                                    observer.expectAbortLogoff(false);
                                    bootstrap.close(true);
                                    assertTrue(bootstrap.isClosed());
                                    assertThrows(IOException.class, main::close);
                                    assertEquals(abortMid, nextMessageId(bootstrap), "Lost bootstrap cannot allocate the abort nonce");
                                } else {
                                    main.close();
                                    assertEquals(abortMid + 1, nextMessageId(bootstrap));
                                }
                                assertEquals(0, main.getChannelCount());
                                bootstrap.close(true); assertTrue(bootstrap.isClosed());
                                assertTrue(caller.isConnected());
                                echo(older);
                                if (file != null) { bytes[1] ^= 1; verifyContents(file, bytes); }
                                try (Connection pooled = client.connect("127.0.0.1", port)) { assertSame(caller, pooled); }
                                assertTrue(caller.isConnected());
                                System.out.printf("BOOTSTRAP_ABORT_COMPLETE run=%s fault=%s rootLoss=%s bindingMids=%s abortMID=%d padding=%d olderOpenBeforeBinding=%s olderSessionLive=true pooledIdentityPreserved=true bootstrapTransportClosed=true unpublishedChannels=0 signing=AES_GMAC%n",
                                        run, mode, rootLoss, used, abortMid, padding, existingOpen);
                            } finally {
                                worker.shutdownNow(); assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS));
                            }
                        }
                    }
                    if (before != null) before.rm(name);
                }
                // The older session can also establish a fresh share/open after abort cleanup.
                try (DiskShare after = (DiskShare) older.connectShare("share")) {
                    try (File file = open(after, name)) { bytes[2] ^= 1; verifyContents(file, bytes); }
                    finally { after.rm(name); }
                }
                System.out.printf("BOOTSTRAP_ABORT_IO run=%s heldOpenReadbackBytes=%d freshOpenReadbackBytes=%d%n",
                        run, existingOpen ? bytes.length * 3 : 0, bytes.length);
            }
        } catch (Exception | Error failure) { primary = failure; throw failure; }
        finally {
            try {
                for (Connection connection : owned) connection.close(true);
                observer.verifyAndReport(run, 0, 0);
            } catch (Exception | Error cleanup) {
                if (primary == null) throw cleanup;
                if (primary != cleanup) primary.addSuppressed(cleanup);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"bad-final", "lost-final"})
    void observerRejectsAbortWithoutTheReservedNonce(String mode) throws Exception {
        assumeTrue("true".equals(System.getenv("SMBJ_GMAC_AUX_RESEARCH")), "Explicit detached research opt-in required");
        try (SMBClient client = new SMBClient(config, bus)) {
            Connection caller = client.connect("127.0.0.1", port); observer.register(caller);
            try (Session older = caller.authenticate(authentication())) {
                observer.auxiliary(older, caller);
                Connection bootstrap = connect(client);
                try (Session main = bootstrap.authenticate(authentication())) {
                    observer.original(main, bootstrap); observer.reserveAbort(nextMessageId(bootstrap));
                    assertEquals(3, nextMessageId(caller));
                    observer.reservation(caller, 3, 16);
                    byte[] negotiate = caller.getConnectionContext().getPreauthIntegrityHashValue().clone();
                    CountDownLatch fault = observer.faultFinal(caller, mode);
                    assertThrows(IOException.class, () -> caller.bind(main));
                    assertEquals(0, fault.getCount());
                    observer.provisionalBinding(caller, authenticators.exported.get(), negotiate);
                    // Deliberately unsafe: binding used K/MID 3; native LOGOFF now uses K/MID 3 too.
                    main.close(); bootstrap.close(true);
                    echo(older);
                }
            }
        } finally {
            for (Connection connection : owned) connection.close(true);
        }
        AssertionError rejected = assertThrows(AssertionError.class,
                () -> observer.verifyAndReport("unsafe-abort-" + mode, 0, 0));
        assertTrue(rejected.getMessage().contains("Different authenticated bytes reused actual key/nonce"));
        System.out.printf("BOOTSTRAP_ABORT_UNSAFE_CONTROL fault=%s result=expected_nonce_reuse_detected%n", mode);
    }

    private static boolean hasCause(Throwable error, Class<? extends Throwable> type) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) if (type.isInstance(cause)) return true;
        return false;
    }

    private Connection connect(SMBClient client) throws IOException {
        Connection connection = new Connection(config, client, bus, client.getServerList());
        owned.add(connection); connection.connect("127.0.0.1", port); observer.register(connection);
        return connection;
    }

    private static final class RecordingFactory extends NtlmAuthenticator.Factory {
        private final AtomicReference<byte[]> exported = new AtomicReference<>();
        @Override public NtlmAuthenticator create() {
            exported.set(null);
            return new NtlmAuthenticator() {
                @Override public AuthenticateResponse authenticate(AuthenticationContext context, byte[] token,
                        ConnectionContext connection) throws IOException {
                    AuthenticateResponse response = super.authenticate(context, token, connection);
                    if (response != null && response.getSessionKey() != null) exported.set(response.getSessionKey().clone());
                    return response;
                }
            };
        }
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

    private static long nextMessageId(Connection connection) throws ReflectiveOperationException {
        // Read-only research observation; no native MID or credit mutation.
        Field field = SequenceWindow.class.getDeclaredField("lowestAvailable"); field.setAccessible(true);
        return ((AtomicLong) field.get(connection.sequenceWindow)).get();
    }
}
