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
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.transport.*;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransportFactory;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransportFactory;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.*;

import static com.hierynomus.smbj.testing.MultichannelTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Timeout(60)
class GmacAsyncCancellationIT {
    @ParameterizedTest
    @CsvSource({"false,false,false", "false,true,false", "true,false,false", "true,true,false",
            "false,false,true", "false,true,true", "true,false,true", "true,true,true"})
    void pendingCancelAndFinalResponsesUseDistinctNonces(boolean async, boolean jce, boolean encryption) throws Exception {
        String ports = System.getenv().getOrDefault("SMB_TEST_PORTS", System.getenv("SMB_TEST_PORT"));
        assumeTrue(ports != null, "SMB_TEST_PORT enables dedicated server tests");
        Observer observer = new Observer(encryption);
        SmbConfig settings = SmbConfig.builder(config(encryption))
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC)
                .withDirectoryLeasingEnabled(false)
                .withSecurityProvider(jce ? new JceSecurityProvider() : new BCSecurityProvider())
                .withAuthenticators(new NtlmAuthenticator.Factory())
                .withTransportLayerFactory((handlers, configuration) -> {
                    PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> observed = observer.wrap(handlers);
                    return async ? new AsyncDirectTcpTransportFactory().createTransportLayer(observed, configuration)
                            : new DirectTcpTransportFactory().createTransportLayer(observed, configuration);
                }).build();
        String directoryName = "async-gmac-" + UUID.randomUUID();
        try (SMBClient client = new SMBClient(settings);
             Connection connection = client.connect(hostname(), Integer.parseInt(ports.split(",")[0].trim()));
             Session session = connection.authenticate(authentication());
             DiskShare share = (DiskShare) session.connectShare(shareName())) {
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, connection.getConnectionContext().getSigningAlgorithm());
            if (encryption) assertEquals(SMB3EncryptionCipher.AES_128_GCM, connection.getConnectionContext().getCipherId());
            assertEquals(1, session.getChannelCount());
            observer.bound(session, connection);
            Connection secondary = client.openChannel(session, hostname(), Integer.parseInt(ports.split(",")[0].trim()));
            observer.bound(session, secondary);
            assertEquals(2, session.getChannelCount());
            share.mkdir(directoryName);
            try {
                for (int cycle = 0; cycle < 2; cycle++) {
                    String watchedDirectory = directoryName + "/" + cycle;
                    share.mkdir(watchedDirectory);
                    try (Directory directory = share.openDirectory(watchedDirectory, EnumSet.of(AccessMask.GENERIC_READ),
                            null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                        for (int phase = 0; phase < 4; phase++) {
                            observer.arm(phase == 0);
                            Future<SMB2ChangeNotifyResponse> watch = directory.watchAsync(
                                    EnumSet.of(SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME), false);
                            if (phase == 0) {
                                try {
                                    assertTrue(observer.receivedPending.await(5, TimeUnit.SECONDS));
                                    advanceScheduler(session, observer);
                                    if (cycle == 1) {
                                        observer.echoOwner.close(true);
                                        Connection replacement = client.openChannel(session, hostname(), Integer.parseInt(ports.split(",")[0].trim()));
                                        observer.bound(session, replacement);
                                        assertEquals(2, session.getChannelCount());
                                    }
                                    assertFalse(watch.isDone());
                                    assertTrue(watch.cancel(true), "CANCEL snapshots sync identity before pending publication");
                                } finally { observer.releasePending.countDown(); }
                            }
                            assertTrue(observer.pending.await(5, TimeUnit.SECONDS), "Native STATUS_PENDING must reach Request");
                            if (phase > 0) {
                                assertFalse(watch.isDone());
                                advanceScheduler(session, observer);
                            }
                            if (phase < 3) {
                                if (phase == 1) assertTrue(watch.cancel(true));
                                if (phase == 2) cancelConcurrently(watch);
                                assertFalse(watch.cancel(true), "A second cancel must not emit another GMAC input");
                                assertThrows(CancellationException.class, () -> watch.get(5, TimeUnit.SECONDS));
                            } else {
                                String name = watchedDirectory + "/event.bin";
                                try (File ignored = share.openFile(name, EnumSet.of(AccessMask.GENERIC_WRITE), null,
                                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                                    SMB2ChangeNotifyResponse response = watch.get(5, TimeUnit.SECONDS);
                                    assertEquals(1, response.getFileNotifyInfoList().size());
                                    assertEquals("event.bin", response.getFileNotifyInfoList().get(0).getFileName());
                                } finally { share.rm(name); }
                                assertFalse(watch.cancel(true), "A completed notification cannot emit CANCEL");
                            }
                            assertTrue(observer.finished.await(5, TimeUnit.SECONDS), "Final peer response must be processed");
                            assertSame(observer.requestOwner, observer.completedOwner, "Final response stays on the request owner");
                            assertNull(observer.completedOwner.outstandingRequests.getRequestByMessageId(observer.completedMid),
                                    "Final response retires the request even when its Future was cancelled");
                            echo(session);
                        }
                        assertTrue(observer.completedOwner.isConnected());
                        assertEquals(2, session.getChannelCount());
                    }
                }
                String watchedDirectory = directoryName + "/owner-loss";
                share.mkdir(watchedDirectory);
                try (Directory directory = share.openDirectory(watchedDirectory, EnumSet.of(AccessMask.GENERIC_READ),
                        null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                    observer.arm(false);
                    Future<SMB2ChangeNotifyResponse> lostWatch = directory.watchAsync(
                            EnumSet.of(SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME), false);
                    assertTrue(observer.pending.await(5, TimeUnit.SECONDS));
                    advanceScheduler(session, observer);
                    Connection lostOwner = observer.requestOwner;
                    Request lostRequest = lostOwner.outstandingRequests.getRequestByMessageId(observer.requestMid);
                    assertNotNull(lostRequest);
                    observer.abandon();
                    lostOwner.close(true);
                    ExecutionException failure = assertThrows(ExecutionException.class, () -> lostWatch.get(5, TimeUnit.SECONDS));
                    assertTrue(failure.getCause().getCause() instanceof TransportException, "Owner loss must report the transport failure");
                    assertFalse(lostWatch.cancel(true), "A failed request cannot publish CANCEL on a surviving channel");
                    assertNull(lostOwner.outstandingRequests.getRequestByMessageId(lostRequest.getMessageId()));
                    assertNull(lostOwner.outstandingRequests.getRequestByCancelId(lostRequest.getCancelId()));
                    assertEquals(1, session.getChannelCount());
                    echo(session);
                    assertNotNull(directory.list(), "The failed watch does not invalidate ordinary same-handle directory queries");
                }
                Connection replacement = client.openChannel(session, hostname(), Integer.parseInt(ports.split(",")[0].trim()));
                observer.bound(session, replacement);
                assertEquals(2, session.getChannelCount());
                // Close the failed subscription's handle before explicitly starting a new watch.
                try (Directory recoveredDirectory = share.openDirectory(watchedDirectory, EnumSet.of(AccessMask.GENERIC_READ),
                        null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                    echo(session);
                    if (observer.echoOwner == replacement) echo(session);
                    observer.arm(false);
                    Future<SMB2ChangeNotifyResponse> recoveredWatch = recoveredDirectory.watchAsync(
                            EnumSet.of(SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME), false);
                    assertTrue(observer.pending.await(5, TimeUnit.SECONDS));
                    assertSame(replacement, observer.requestOwner, "The fresh subscription watches on the replacement");
                    String name = watchedDirectory + "/recovered.bin";
                    try {
                        try (File ignored = share.openFile(name, EnumSet.of(AccessMask.GENERIC_WRITE), null,
                                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) { }
                        SMB2ChangeNotifyResponse response = recoveredWatch.get(5, TimeUnit.SECONDS);
                        assertEquals(1, response.getFileNotifyInfoList().size());
                        assertEquals("recovered.bin", response.getFileNotifyInfoList().get(0).getFileName());
                    } finally { share.rm(name); }
                    assertTrue(observer.finished.await(5, TimeUnit.SECONDS));
                    assertSame(replacement, observer.completedOwner);
                    assertNull(replacement.outstandingRequests.getRequestByMessageId(observer.completedMid));
                    assertFalse(recoveredWatch.cancel(true));
                }
            } finally { share.rmdir(directoryName, true); }
        }
        observer.verify();
        System.out.printf("GMAC_ASYNC java=%s provider=%s transport=%s signing=AES_GMAC encrypt=%s cipher=%s channels=2 replacements=2 ownerLosses=1 pending=10 cancels=6 syncCancels=2 asyncCancels=4 cancelledFinals=6 successFinals=3 verifiedTags=%d verifiedGcmTransforms=%d encryptedOperationFrames=%d nonceReuses=0%n",
                System.getProperty("java.version"), jce ? "default-JCE" : "BC", async ? "async" : "direct", encryption,
                encryption ? SMB3EncryptionCipher.AES_128_GCM : null, encryption ? 0 : 25,
                observer.verifiedTransforms, observer.encryptedOperationFrames);
    }

    private static void advanceScheduler(Session session, Observer observer) throws Exception {
        echo(session);
        assertNotSame(observer.requestOwner, observer.echoOwner, "Round robin moved ordinary traffic off the pending request owner");
    }

    private static void echo(Session session) throws Exception {
        SMB2Echo echo = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        echo.getHeader().setSessionId(session.getSessionId());
        assertEquals(0, session.<SMB2Echo>send(echo).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
    }

    private static void cancelConcurrently(Future<?> watch) throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(8);
        CountDownLatch ready = new CountDownLatch(8), start = new CountDownLatch(1);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 8; i++) results.add(workers.submit(() -> {
                ready.countDown();
                assertTrue(start.await(5, TimeUnit.SECONDS));
                return watch.cancel(true);
            }));
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            int accepted = 0;
            for (Future<Boolean> result : results) if (result.get(5, TimeUnit.SECONDS)) accepted++;
            assertEquals(1, accepted);
        } finally {
            start.countDown();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    /** Captures serializer inputs and incoming frames without using SMBJ's signer or nonce builder. */
    private static final class Observer {
        private final List<byte[]> messages = new ArrayList<>();
        private final Set<byte[]> incoming = new HashSet<>();
        private final Map<byte[], Connection> owners = new IdentityHashMap<>();
        private final Map<Connection, byte[]> keys = new IdentityHashMap<>();
        private final Map<Connection, Long> nextMessageId = new IdentityHashMap<>();
        private final Map<Connection, Integer> connectionIds = new IdentityHashMap<>();
        private final Set<byte[]> encryptedMessages = Collections.newSetFromMap(new IdentityHashMap<byte[], Boolean>());
        private final Set<String> encryptionNonces = new HashSet<>();
        private final boolean encryption;
        private int verifiedTransforms, encryptedOperationFrames;
        private volatile CountDownLatch pending, finished, receivedPending, releasePending;
        private volatile Connection requestOwner, completedOwner, echoOwner;
        private long requestMid, completedMid;
        private String abandonedRequest;

        Observer(boolean encryption) { this.encryption = encryption; }

        synchronized void abandon() {
            assertNull(abandonedRequest);
            abandonedRequest = connectionIds.get(requestOwner) + ":" + Long.toUnsignedString(requestMid);
        }

        synchronized void bound(Session session, Connection connection) {
            byte[] key = session.getSigningKey(new SMB2Echo(SMB2Dialect.SMB_3_1_1).getHeader(), false, connection).getEncoded().clone();
            assertFalse(Arrays.equals(session.getSessionContext().getSigningKey().getEncoded(), key), "Notifications use bound key D, not original K");
            keys.put(connection, key);
        }

        void arm(boolean holdPending) {
            pending = new CountDownLatch(1);
            finished = new CountDownLatch(1);
            receivedPending = new CountDownLatch(1);
            releasePending = new CountDownLatch(holdPending ? 1 : 0);
        }

        PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> wrap(PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> handlers) {
            Connection owner = (Connection) handlers.getReceiver();
            connectionIds.put(owner, connectionIds.size());
            PacketSerializer<SMBPacket<?, ?>, SMBBuffer> serializer = packet -> {
                SMBBuffer buffer = (SMBBuffer) handlers.getSerializer().write(packet);
                capture(buffer, false, owner);
                return buffer;
            };
            return new PacketHandlers<>(serializer, new PacketReceiver<SMBPacketData<?>>() {
                @Override
                public void handle(SMBPacketData<?> packet) throws TransportException {
                    byte[] message = capture(packet.getDataBuffer(), true, owner);
                    if (message != null && status(message) == 0x103) {
                        receivedPending.countDown();
                        try {
                            assertTrue(releasePending.await(5, TimeUnit.SECONDS), "Release native pending response");
                        } catch (InterruptedException failure) {
                            Thread.currentThread().interrupt();
                            throw new TransportException(failure);
                        }
                    }
                    handlers.getReceiver().handle(packet);
                    if (message != null && command(message) == 15) {
                        if (status(message) == 0x103) pending.countDown();
                        else {
                            completedMid = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN).getLong(24);
                            completedOwner = owner;
                            finished.countDown();
                        }
                    }
                }

                @Override
                public void handleError(Throwable failure) { handlers.getReceiver().handleError(failure); }
            }, handlers.getPacketFactory());
        }

        private synchronized byte[] capture(Buffer<?> buffer, boolean server, Connection owner) {
            byte[] data = buffer.array();
            int end = buffer.wpos();
            boolean encrypted = end >= 52 && data[0] == (byte) 0xfd;
            if (encrypted) {
                data = decrypt(data, end, server, owner);
                end = data.length;
            }
            if (end < 64 || data[0] != (byte) 0xfe) return null;
            if (!server && command(data) != 12) {
                ByteBuffer header = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
                long expected = nextMessageId.getOrDefault(owner, 0L);
                assertEquals(expected, header.getLong(24), "Ordinary requests consume the lowest native MID; CANCEL consumes none");
                nextMessageId.put(owner, expected + Math.max(1, header.getShort(6) & 0xffff));
                if (command(data) == 13) echoOwner = owner;
            }
            if (command(data) != 15 && command(data) != 12) return null;
            assertTrue(messages.size() < 64, "Bounded observation");
            byte[] copy = Arrays.copyOf(data, end);
            messages.add(copy);
            if (encrypted) encryptedMessages.add(copy);
            owners.put(copy, owner);
            if (server) incoming.add(copy);
            else if (command(data) == 15) {
                requestOwner = owner;
                requestMid = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getLong(24);
            }
            return copy;
        }

        private byte[] decrypt(byte[] wire, int end, boolean server, Connection owner) {
            assertTrue(encryption, "Signing-only profile cannot silently become encrypted");
            assertEquals(SMB3EncryptionCipher.AES_128_GCM, owner.getConnectionContext().getCipherId());
            ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
            assertEquals(end - 52, header.getInt(36), "Exact transform extent");
            assertEquals(0, header.getShort(40));
            assertEquals(1, header.getShort(42));
            long sessionId = header.getLong(44);
            Session session = owner.getSessionTable().find(sessionId);
            assertNotNull(session, "Transform keys belong to the receiving connection's active/provisional session");
            SecretKey key = server ? session.getSessionContext().getDecryptionKey() : session.getSessionContext().getEncryptionKey();
            assertNotNull(key);
            byte[] nonce = Arrays.copyOfRange(wire, 20, 32);
            byte[] ciphertextAndTag = Arrays.copyOfRange(wire, 52, end + 16);
            System.arraycopy(wire, 4, ciphertextAndTag, end - 52, 16);
            try {
                Cipher oracle = Cipher.getInstance("AES/GCM/NoPadding");
                SecretKeySpec aes = new SecretKeySpec(key.getEncoded(), "AES");
                oracle.init(Cipher.DECRYPT_MODE, aes, new GCMParameterSpec(128, nonce));
                oracle.updateAAD(wire, 20, 32);
                byte[] plaintext = oracle.doFinal(ciphertextAndTag);
                assertArrayEquals(new byte[]{(byte) 0xfe, 'S', 'M', 'B'}, Arrays.copyOf(plaintext, 4));
                assertEquals(sessionId, ByteBuffer.wrap(plaintext).order(ByteOrder.LITTLE_ENDIAN).getLong(40));
                assertTrue(encryptionNonces.add(nonceDomain(key.getEncoded(), nonce)), "No encryption key/nonce repeats across channels or sessions");
                if (verifiedTransforms == 0) {
                    ciphertextAndTag[0] ^= 1;
                    oracle.init(Cipher.DECRYPT_MODE, aes, new GCMParameterSpec(128, nonce));
                    oracle.updateAAD(wire, 20, 32);
                    assertThrows(AEADBadTagException.class, () -> oracle.doFinal(ciphertextAndTag));
                }
                assertTrue(++verifiedTransforms < 4096, "Bounded transform observation");
                return plaintext;
            } catch (GeneralSecurityException failure) {
                throw new AssertionError("Independent GCM transform verification failed", failure);
            }
        }

        private String nonceDomain(byte[] key, byte[] nonce) throws GeneralSecurityException {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(key))
                    + ":" + Arrays.toString(nonce);
        }

        synchronized void verify() throws Exception {
            assertEquals(35, messages.size(), "Ten requests/interim, nine finals and six CANCELs; owner loss has no final");
            Map<String, byte[]> requests = new HashMap<>(), interim = new HashMap<>(), finals = new HashMap<>(), cancels = new HashMap<>();
            Set<String> nonces = new HashSet<>(encryptionNonces);
            int verified = 0;
            for (byte[] message : messages) {
                ByteBuffer header = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN);
                long mid = header.getLong(24);
                Connection owner = owners.get(message);
                byte[] key = keys.get(owner);
                assertNotNull(key, "Every notification has an authenticated channel key");
                int flags = header.getInt(16);
                boolean server = incoming.contains(message);
                assertEquals(server ? 1 : 0, flags & 1, "Header role must match the observed transport direction");
                boolean cancel = command(message) == 12;
                assertEquals(0, header.getInt(20), "Standalone exact message extents");
                Map<String, byte[]> kind = cancel ? cancels : !server ? requests : status(message) == 0x103 ? interim : finals;
                String identity = connectionIds.get(owner) + ":" + Long.toUnsignedString(mid);
                assertNull(kind.put(identity, message), "Each owner/request has only one input of each phase");
                boolean encrypted = encryptedMessages.contains(message);
                if (encrypted) encryptedOperationFrames++;
                if (server) assertEquals(2, flags & 2, "Native async responses carry AsyncId");
                if (server && status(message) == 0x103) {
                    assertEquals(0, flags & 8, "Interim response must not consume the final response nonce");
                    System.out.printf("GMAC_ASYNC_WIRE sender=server command=15 status=00000103 mid=%d async=true signed=false%n", mid);
                    continue;
                }
                if (encryption) {
                    assertTrue(encrypted, "Every non-interim notification request, CANCEL and final must be encrypted");
                    assertEquals(0, flags & 8, "Encrypted operations do not require a second GMAC tag");
                    continue;
                }
                assertEquals(8, flags & 8, "Requests, CANCELs and finals must be signed");
                byte[] nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
                        .putLong(mid).putInt((server ? 1 : 0) | (cancel ? 2 : 0)).array();
                assertTrue(nonces.add(nonceDomain(key, nonce)), "No actual key/nonce repeats across channels or duplicate CANCEL");
                byte[] input = message.clone();
                Arrays.fill(input, 48, 64, (byte) 0);
                Cipher oracle = Cipher.getInstance("AES/GCM/NoPadding");
                oracle.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
                oracle.updateAAD(input);
                assertTrue(MessageDigest.isEqual(oracle.doFinal(), Arrays.copyOfRange(message, 48, 64)), "Independent GMAC tag");
                if (cancel) {
                    nonce[8] &= ~2;
                    oracle.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
                    oracle.updateAAD(input);
                    assertFalse(MessageDigest.isEqual(oracle.doFinal(), Arrays.copyOfRange(message, 48, 64)),
                            "CANCEL tag must reject the ordinary-request nonce");
                }
                System.out.printf("GMAC_ASYNC_WIRE sender=%s command=%d status=%08x mid=%d async=%s signed=true nonceSuffix=%d%n",
                        server ? "server" : "client", command(message), server ? status(message) : 0, mid, (flags & 2) != 0,
                        (server ? 1 : 0) | (cancel ? 2 : 0));
                verified++;
            }
            assertEquals(10, requests.size());
            Set<Connection> notificationOwners = Collections.newSetFromMap(new IdentityHashMap<Connection, Boolean>());
            for (byte[] request : requests.values()) notificationOwners.add(owners.get(request));
            assertEquals(4, notificationOwners.size(), "Both original channels and both replacements carry notifications");
            assertEquals(requests.keySet(), interim.keySet());
            Set<String> completed = new HashSet<>(requests.keySet());
            assertTrue(completed.remove(abandonedRequest));
            assertEquals(completed, finals.keySet());
            assertFalse(cancels.containsKey(abandonedRequest), "Owner loss must not reroute CANCEL");
            assertEquals(6, cancels.size());
            int syncCancels = 0;
            for (Map.Entry<String, byte[]> entry : finals.entrySet()) {
                String mid = entry.getKey();
                byte[] result = entry.getValue();
                long asyncId = ByteBuffer.wrap(interim.get(mid)).order(ByteOrder.LITTLE_ENDIAN).getLong(32);
                assertNotEquals(0, asyncId);
                assertEquals(asyncId, ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).getLong(32));
                if (cancels.containsKey(mid)) {
                    byte[] cancel = cancels.get(mid);
                    if ((ByteBuffer.wrap(cancel).order(ByteOrder.LITTLE_ENDIAN).getInt(16) & 2) != 0) {
                        assertEquals(asyncId, ByteBuffer.wrap(cancel).order(ByteOrder.LITTLE_ENDIAN).getLong(32));
                    } else syncCancels++;
                    assertEquals(0xc0000120L, status(result));
                } else assertEquals(0, status(result));
            }
            assertEquals(2, syncCancels);
            assertEquals(encryption ? 0 : 25, verified);
            if (encryption) {
                assertTrue(verifiedTransforms >= 25);
                assertTrue(encryptedOperationFrames >= 25);
            } else assertEquals(0, verifiedTransforms);
        }

        private static int command(byte[] message) {
            return ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN).getShort(12) & 0xffff;
        }

        private static long status(byte[] message) {
            return ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN).getInt(8) & 0xffffffffL;
        }
    }
}
