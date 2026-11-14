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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

import static com.hierynomus.smbj.testing.MultichannelTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Timeout(45)
class GmacAsyncCancellationIT {
    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void pendingCancelAndFinalResponsesUseDistinctNonces(boolean async, boolean jce) throws Exception {
        String ports = System.getenv().getOrDefault("SMB_TEST_PORTS", System.getenv("SMB_TEST_PORT"));
        assumeTrue(ports != null, "SMB_TEST_PORT enables dedicated server tests");
        Observer observer = new Observer();
        SmbConfig settings = SmbConfig.builder(config(false))
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC)
                .withSecurityProvider(jce ? new JceSecurityProvider() : new BCSecurityProvider())
                .withAuthenticators(new NtlmAuthenticator.Factory())
                .withTransportLayerFactory((handlers, configuration) -> {
                    PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> observed = observer.wrap(handlers);
                    return async ? new AsyncDirectTcpTransportFactory().createTransportLayer(observed, configuration)
                            : new DirectTcpTransportFactory().createTransportLayer(observed, configuration);
                }).build();
        String directoryName = "async-gmac-" + UUID.randomUUID();
        byte[] key;
        try (SMBClient client = new SMBClient(settings);
             Connection connection = client.connect(hostname(), Integer.parseInt(ports.split(",")[0].trim()));
             Session session = connection.authenticate(authentication());
             DiskShare share = (DiskShare) session.connectShare(shareName())) {
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, connection.getConnectionContext().getSigningAlgorithm());
            assertEquals(1, session.getChannelCount());
            key = session.getSessionContext().getSigningKey().getEncoded().clone();
            share.mkdir(directoryName);
            try (Directory directory = share.openDirectory(directoryName, EnumSet.of(AccessMask.GENERIC_READ),
                    null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                for (int round = 0; round < 4; round++) {
                    observer.arm(round == 0);
                    Future<SMB2ChangeNotifyResponse> watch = directory.watchAsync(
                            EnumSet.of(SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME), false);
                    if (round == 0) {
                        try {
                            assertTrue(observer.receivedPending.await(5, TimeUnit.SECONDS));
                            assertFalse(watch.isDone());
                            assertTrue(watch.cancel(true), "CANCEL snapshots sync identity before pending publication");
                        } finally { observer.releasePending.countDown(); }
                    }
                    assertTrue(observer.pending.await(5, TimeUnit.SECONDS), "Native STATUS_PENDING must reach Request");
                    if (round > 0) assertFalse(watch.isDone());
                    if (round < 3) {
                        if (round == 1) assertTrue(watch.cancel(true));
                        if (round == 2) cancelConcurrently(watch);
                        assertFalse(watch.cancel(true), "A second cancel must not emit another GMAC input");
                        assertThrows(CancellationException.class, () -> watch.get(5, TimeUnit.SECONDS));
                    } else {
                        String name = directoryName + "/event.bin";
                        try (File ignored = share.openFile(name, EnumSet.of(AccessMask.GENERIC_WRITE), null,
                                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                            SMB2ChangeNotifyResponse response = watch.get(5, TimeUnit.SECONDS);
                            assertEquals(1, response.getFileNotifyInfoList().size());
                            assertEquals("event.bin", response.getFileNotifyInfoList().get(0).getFileName());
                        } finally { share.rm(name); }
                        assertFalse(watch.cancel(true), "A completed notification cannot emit CANCEL");
                    }
                    assertTrue(observer.finished.await(5, TimeUnit.SECONDS), "Final peer response must be processed");
                    assertNull(connection.outstandingRequests.getRequestByMessageId(observer.completedMid),
                            "Final response retires the request even when its Future was cancelled");
                }
                assertTrue(connection.isConnected());
            } finally { share.rmdir(directoryName, true); }
        }
        observer.verify(key);
        System.out.printf("GMAC_ASYNC java=%s provider=%s transport=%s signing=AES_GMAC encrypt=false pending=4 cancels=3 syncCancels=1 asyncCancels=2 cancelledFinals=3 successFinals=1 verifiedTags=11 distinctNonces=11%n",
                System.getProperty("java.version"), jce ? "default-JCE" : "BC", async ? "async" : "direct");
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
        private volatile CountDownLatch pending, finished, receivedPending, releasePending;
        private long completedMid;

        void arm(boolean holdPending) {
            pending = new CountDownLatch(1);
            finished = new CountDownLatch(1);
            receivedPending = new CountDownLatch(1);
            releasePending = new CountDownLatch(holdPending ? 1 : 0);
        }

        PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> wrap(PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> handlers) {
            PacketSerializer<SMBPacket<?, ?>, SMBBuffer> serializer = packet -> {
                SMBBuffer buffer = (SMBBuffer) handlers.getSerializer().write(packet);
                capture(buffer, false);
                return buffer;
            };
            return new PacketHandlers<>(serializer, new PacketReceiver<SMBPacketData<?>>() {
                @Override
                public void handle(SMBPacketData<?> packet) throws TransportException {
                    byte[] message = capture(packet.getDataBuffer(), true);
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
                            finished.countDown();
                        }
                    }
                }

                @Override
                public void handleError(Throwable failure) { handlers.getReceiver().handleError(failure); }
            }, handlers.getPacketFactory());
        }

        private synchronized byte[] capture(Buffer<?> buffer, boolean server) {
            byte[] data = buffer.array();
            int end = buffer.wpos();
            if (end < 64 || data[0] != (byte) 0xfe || (command(data) != 15 && command(data) != 12)) return null;
            assertTrue(messages.size() < 32, "Bounded observation");
            byte[] copy = Arrays.copyOf(data, end);
            messages.add(copy);
            if (server) incoming.add(copy);
            return copy;
        }

        synchronized void verify(byte[] key) throws Exception {
            assertEquals(15, messages.size(), "Four requests, four interim, four finals, three CANCELs");
            Map<Long, byte[]> requests = new HashMap<>(), interim = new HashMap<>(), finals = new HashMap<>(), cancels = new HashMap<>();
            Set<String> nonces = new HashSet<>();
            int verified = 0;
            for (byte[] message : messages) {
                ByteBuffer header = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN);
                long mid = header.getLong(24);
                int flags = header.getInt(16);
                boolean server = incoming.contains(message);
                assertEquals(server ? 1 : 0, flags & 1, "Header role must match the observed transport direction");
                boolean cancel = command(message) == 12;
                assertEquals(0, header.getInt(20), "Standalone exact message extents");
                Map<Long, byte[]> kind = cancel ? cancels : !server ? requests : status(message) == 0x103 ? interim : finals;
                assertNull(kind.put(mid, message), "Each request has only one input of each phase");
                if (server) assertEquals(2, flags & 2, "Native async responses carry AsyncId");
                if (server && status(message) == 0x103) {
                    assertEquals(0, flags & 8, "Interim response must not consume the final response nonce");
                    System.out.printf("GMAC_ASYNC_WIRE sender=server command=15 status=00000103 mid=%d async=true signed=false%n", mid);
                    continue;
                }
                assertEquals(8, flags & 8, "Requests, CANCELs and finals must be signed");
                byte[] nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
                        .putLong(mid).putInt((server ? 1 : 0) | (cancel ? 2 : 0)).array();
                assertTrue(nonces.add(Arrays.toString(nonce)), "No actual key/nonce repeats, including duplicate CANCEL");
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
            assertEquals(4, requests.size());
            assertEquals(requests.keySet(), interim.keySet());
            assertEquals(requests.keySet(), finals.keySet());
            assertEquals(3, cancels.size());
            List<Long> ordered = new ArrayList<>(requests.keySet());
            Collections.sort(ordered);
            for (int i = 1; i < ordered.size(); i++) {
                long previous = ordered.get(i - 1);
                int charge = ByteBuffer.wrap(requests.get(previous)).order(ByteOrder.LITTLE_ENDIAN).getShort(6) & 0xffff;
                assertEquals(previous + Math.max(1, charge), (long) ordered.get(i), "CANCEL consumes no new MID range");
            }
            int syncCancels = 0;
            for (Map.Entry<Long, byte[]> entry : finals.entrySet()) {
                long mid = entry.getKey();
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
            assertEquals(1, syncCancels);
            assertEquals(11, verified);
        }

        private static int command(byte[] message) {
            return ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN).getShort(12) & 0xffff;
        }

        private static long status(byte[] message) {
            return ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN).getInt(8) & 0xffffffffL;
        }
    }
}
