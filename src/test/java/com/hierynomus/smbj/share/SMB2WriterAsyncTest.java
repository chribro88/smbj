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
package com.hierynomus.smbj.share;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.mssmb2.messages.SMB2Close;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.io.ByteChunkProvider;
import com.hierynomus.protocol.commons.concurrent.CancellableFuture;
import com.hierynomus.protocol.commons.concurrent.Promise;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@Timeout(30)
class SMB2WriterAsyncTest {
    private static final SMB2FileId ID = new SMB2FileId(new byte[8], new byte[8]);

    @Test
    void repeatedShortWritesCompleteWithoutGetAndNeverRepeatAcknowledgedBytes() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            f.respond = request -> CompletableFuture.completedFuture(acknowledge(1));
            Future<Long> result = f.writer.writeAsync(new byte[]{1, 2, 3}, 7, 0, 3);
            assertTrue(f.finished.await(3, TimeUnit.SECONDS));
            assertTrue(result.isDone());
            assertEquals(3L, result.get());
            assertEquals(3L, result.get());
            assertEquals(3, f.requests.size());
            assertEquals(Arrays.asList(7L, 8L, 9L), Arrays.asList(f.requests.get(0).offset, f.requests.get(1).offset, f.requests.get(2).offset));
            assertArrayEquals(new byte[]{1, 2, 3}, f.requests.get(0).bytes);
            assertArrayEquals(new byte[]{2, 3}, f.requests.get(1).bytes);
            assertArrayEquals(new byte[]{3}, f.requests.get(2).bytes);
        }
    }

    @Test
    void pendingWindowBoundsSourceConsumptionAndCancellationStopsEveryRequest() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            CountDownLatch window = new CountDownLatch(64);
            List<CompletableFuture<SMB2WriteResponse>> replies = Collections.synchronizedList(new ArrayList<>());
            f.respond = request -> {
                CompletableFuture<SMB2WriteResponse> reply = new CompletableFuture<>();
                replies.add(reply); window.countDown(); return reply;
            };
            ByteChunkProvider source = generated((1L << 31) + 1);
            ExecutorService producer = Executors.newSingleThreadExecutor();
            try {
                Future<Future<Long>> submission = producer.submit(() -> f.writer.writeAsync(source));
                assertTrue(window.await(3, TimeUnit.SECONDS));
                assertEquals(4L * 1024 * 1024, source.getOffset());
                assertFalse(submission.isDone());
                f.writer.cancelAsyncWrites();
                Future<Long> cancelled = submission.get(3, TimeUnit.SECONDS);
                assertThrows(CancellationException.class, cancelled::get);
                assertTrue(f.finished.await(3, TimeUnit.SECONDS));
                assertEquals(64, f.requests.size());
                assertEquals(4L * 1024 * 1024, source.getOffset());
                for (CompletableFuture<?> reply : replies) assertTrue(reply.isCancelled());
            } finally { producer.shutdownNow(); }
        }
    }

    @Test
    void largeConfiguredTransfersStillRespectTheOwnedByteBudget() throws Exception {
        try (Fixture f = new Fixture(8 * 1024 * 1024)) {
            f.credits = 64;
            CountDownLatch submitted = new CountDownLatch(1);
            CompletableFuture<SMB2WriteResponse> reply = new CompletableFuture<>();
            f.respond = request -> { submitted.countDown(); return reply; };
            ByteChunkProvider source = generated(16L * 1024 * 1024);
            ExecutorService producer = Executors.newSingleThreadExecutor();
            try {
                Future<Future<Long>> submission = producer.submit(() -> f.writer.writeAsync(source));
                assertTrue(submitted.await(3, TimeUnit.SECONDS));
                assertEquals(4L * 1024 * 1024, source.getOffset());
                assertEquals(4 * 1024 * 1024, f.requests.get(0).bytes.length);
                assertFalse(submission.isDone());
                f.writer.cancelAsyncWrites();
                Future<Long> cancelled = submission.get(3, TimeUnit.SECONDS);
                assertThrows(CancellationException.class, cancelled::get);
                assertTrue(f.finished.await(3, TimeUnit.SECONDS));
                assertTrue(reply.isCancelled());
                assertEquals(1, f.requests.size());
            } finally { producer.shutdownNow(); }
        }
    }

    @Test
    void callerCanReuseItsInputBufferAsSoonAsWriteAsyncReturns() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            CountDownLatch serializing = new CountDownLatch(1), release = new CountDownLatch(1);
            f.beforeSerialize = () -> {
                serializing.countDown();
                try { assertTrue(release.await(3, TimeUnit.SECONDS)); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
            };
            byte[] source = {1, 2, 3};
            Future<Long> written = f.writer.writeAsync(source, 0, 0, 3);
            try {
                assertTrue(serializing.await(3, TimeUnit.SECONDS));
                Arrays.fill(source, (byte) 9);
            } finally { release.countDown(); }
            assertEquals(3L, written.get(3, TimeUnit.SECONDS));
            assertArrayEquals(new byte[]{1, 2, 3}, f.requests.get(0).bytes);
        }
    }

    @Test
    void cancellationDuringSubmissionCancelsTheLatePublishedRequest() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
            CompletableFuture<SMB2WriteResponse> late = new CompletableFuture<>();
            f.respond = request -> {
                entered.countDown();
                try { assertTrue(release.await(3, TimeUnit.SECONDS)); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
                return late;
            };
            Future<Long> result = f.writer.writeAsync(new byte[131072], 0, 0, 131072);
            try {
                assertTrue(entered.await(3, TimeUnit.SECONDS));
                assertTrue(result.cancel(false));
                assertThrows(CancellationException.class, result::get);
            } finally { release.countDown(); }
            assertTrue(f.finished.await(3, TimeUnit.SECONDS));
            assertTrue(late.isCancelled());
            assertEquals(1, f.requests.size());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void acknowledgementCannotExceedActualCreditLimitedSubmission(boolean async) throws Exception {
        try (Fixture f = new Fixture(131072)) {
            f.credits = 1;
            f.respond = request -> CompletableFuture.completedFuture(acknowledge(65537));
            if (async) {
                ExecutionException error = assertThrows(ExecutionException.class,
                        () -> f.writer.writeAsync(new byte[131072], 0, 0, 131072).get(3, TimeUnit.SECONDS));
                assertInstanceOf(SMBRuntimeException.class, error.getCause());
            } else {
                assertThrows(SMBRuntimeException.class, () -> f.writer.write(new byte[131072], 0));
            }
            assertEquals(1, f.requests.size());
            assertEquals(65536, f.requests.get(0).bytes.length);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 4})
    void invalidAcknowledgementsCannotLoopOrDropBytes(int count) throws Exception {
        try (Fixture f = new Fixture(65536)) {
            f.respond = request -> CompletableFuture.completedFuture(acknowledge(count));
            ExecutionException error = assertThrows(ExecutionException.class,
                    () -> f.writer.writeAsync(new byte[3], 0, 0, 3).get(3, TimeUnit.SECONDS));
            assertInstanceOf(SMBRuntimeException.class, error.getCause());
            assertEquals(1, f.requests.size());
        }
    }

    @Test
    void failureAfterAcknowledgedProgressDoesNotReplayAnAmbiguousTail() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            IOException lost = new IOException("response lost after WRITE");
            f.respond = request -> {
                if (f.requests.size() == 1) return CompletableFuture.completedFuture(acknowledge(1));
                CompletableFuture<SMB2WriteResponse> response = new CompletableFuture<>();
                response.completeExceptionally(lost); return response;
            };
            assertThrows(ExecutionException.class, () -> f.writer.writeAsync(new byte[]{1, 2, 3}, 0, 0, 3).get(3, TimeUnit.SECONDS));
            assertEquals(2, f.requests.size());
            assertEquals(1, f.requests.get(1).offset);
            assertArrayEquals(new byte[]{2, 3}, f.requests.get(1).bytes);
        }
    }

    @Test
    void asyncWriteValidatesServerStatusBeforeAcceptingCount() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            f.respond = request -> {
                SMB2WriteResponse denied = acknowledge(request.bytes.length);
                denied.getHeader().setStatusCode(NtStatus.STATUS_ACCESS_DENIED.getValue());
                return CompletableFuture.completedFuture(denied);
            };
            ExecutionException error = assertThrows(ExecutionException.class,
                    () -> f.writer.writeAsync(new byte[3], 0, 0, 3).get(3, TimeUnit.SECONDS));
            assertInstanceOf(SMBApiException.class, error.getCause());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void offsetOverflowIsRejectedBeforeAnyWireRequest(boolean async) throws Exception {
        try (Fixture f = new Fixture(65536)) {
            ByteChunkProvider source = new ArrayByteChunkProvider(new byte[3], Long.MAX_VALUE - 1);
            if (async) {
                assertThrows(ArithmeticException.class, () -> f.writer.writeAsync(source));
            } else {
                assertThrows(ArithmeticException.class, () -> f.writer.write(source));
            }
            assertTrue(f.requests.isEmpty());
            assertEquals(0, source.getLastWriteSize());
        }
    }

    @Test
    void fileCloseDrainsAsyncTailsBeforeSendingClose() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            CompletableFuture<SMB2WriteResponse> firstReply = new CompletableFuture<>();
            CountDownLatch sent = new CountDownLatch(1);
            f.respond = request -> {
                sent.countDown();
                return f.requests.size() == 1 ? firstReply : CompletableFuture.completedFuture(acknowledge(1));
            };
            File file = f.file();
            Future<Long> written = file.writeAsync(new byte[]{1, 2, 3}, 0, 0, 3);
            assertTrue(sent.await(3, TimeUnit.SECONDS));
            ExecutorService closer = Executors.newSingleThreadExecutor();
            java.util.concurrent.atomic.AtomicReference<Thread> closing = new java.util.concurrent.atomic.AtomicReference<>();
            try {
                Future<?> closed = closer.submit(() -> { closing.set(Thread.currentThread()); file.close(); });
                awaitWaiting(closing);
                assertEquals(1, f.closed.getCount());
                assertThrows(SMBRuntimeException.class, () -> file.writeAsync(new byte[1], 0, 0, 1));
                firstReply.complete(acknowledge(1));
                closed.get(3, TimeUnit.SECONDS);
                assertEquals(3L, written.get(3, TimeUnit.SECONDS));
                assertEquals(3, f.requests.size());
                assertEquals(0, f.closed.getCount());
            } finally { firstReply.complete(acknowledge(1)); closer.shutdownNow(); }
        }
    }

    @Test
    void closeNoWaitCancelsAsyncWriteWithoutIssuingAnotherTail() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            CompletableFuture<SMB2WriteResponse> reply = new CompletableFuture<>();
            CountDownLatch sent = new CountDownLatch(1);
            f.respond = request -> { sent.countDown(); return reply; };
            File file = f.file();
            Future<Long> written = file.writeAsync(new byte[]{1, 2, 3}, 0, 0, 3);
            assertTrue(sent.await(3, TimeUnit.SECONDS));
            file.closeNoWait();
            assertThrows(CancellationException.class, written::get);
            assertTrue(f.finished.await(3, TimeUnit.SECONDS));
            assertTrue(reply.isCancelled());
            assertEquals(1, f.requests.size());
            assertEquals(0, f.closed.getCount());
        }
    }

    @Test
    void fileCloseStillReleasesHandleWhenItsPendingWriteFails() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            CompletableFuture<SMB2WriteResponse> reply = new CompletableFuture<>();
            CountDownLatch sent = new CountDownLatch(1);
            f.respond = request -> { sent.countDown(); return reply; };
            File file = f.file();
            Future<Long> written = file.writeAsync(new byte[1], 0, 0, 1);
            assertTrue(sent.await(3, TimeUnit.SECONDS));
            ExecutorService closer = Executors.newSingleThreadExecutor();
            java.util.concurrent.atomic.AtomicReference<Thread> closing = new java.util.concurrent.atomic.AtomicReference<>();
            try {
                Future<?> closed = closer.submit(() -> { closing.set(Thread.currentThread()); file.close(); });
                awaitWaiting(closing);
                reply.completeExceptionally(new IOException("WRITE outcome unknown"));
                assertThrows(ExecutionException.class, () -> closed.get(3, TimeUnit.SECONDS));
                assertThrows(ExecutionException.class, () -> written.get(3, TimeUnit.SECONDS));
                assertEquals(0, f.closed.getCount());
            } finally { reply.complete(acknowledge(1)); closer.shutdownNow(); }
        }
    }

    private void awaitWaiting(java.util.concurrent.atomic.AtomicReference<Thread> thread) {
        awaitWaiting(thread, Thread.State.WAITING);
    }

    private void awaitWaiting(java.util.concurrent.atomic.AtomicReference<Thread> thread, Thread.State state) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (System.nanoTime() < deadline) {
            if (thread.get() != null && thread.get().getState() == state) return;
            Thread.yield();
        }
        fail("thread did not reach its pending wait");
    }

    @Test
    void acknowledgesSubmittedWritesWhileTheSourcePreparesTheNextChunk() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            CountDownLatch acknowledged = new CountDownLatch(1);
            f.respond = request -> CompletableFuture.completedFuture(new SMB2WriteResponse() {
                @Override public int getBytesWritten() {
                    acknowledged.countDown();
                    return request.bytes.length;
                }
            });
            ByteChunkProvider source = new ByteChunkProvider() {
                int chunks;
                @Override public boolean isAvailable() { return chunks < 2; }
                @Override public int bytesLeft() { return 65536; }
                @Override public void prepareWrite(int limit) {
                    if (chunks == 1) {
                        try {
                            assertTrue(acknowledged.await(3, TimeUnit.SECONDS),
                                    "The worker must consume the ready response while the source prepares more input");
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new AssertionError(e);
                        }
                    }
                }
                @Override protected int getChunk(byte[] bytes) { chunks++; return bytes.length; }
            };
            assertEquals(131072L, f.writer.writeAsync(source).get(3, TimeUnit.SECONDS));
            assertEquals(2, f.requests.size());
            assertEquals(131072L, source.getOffset());
        }
    }

    @ParameterizedTest
    @CsvSource({"stage,success", "stage,error", "stage,cancel", "native,success", "native,error", "native,cancel",
            "opaque,success", "opaque,error", "opaque,cancel"})
    void consumesResponsesThatCompleteWhileWaitingForSourceInput(String kind, String outcome) throws Exception {
        try (Fixture f = new Fixture(65536)) {
            CountDownLatch sourceBlocked = new CountDownLatch(1), releaseSource = new CountDownLatch(1);
            CountDownLatch sent = new CountDownLatch(1), acknowledged = new CountDownLatch(1);
            java.util.concurrent.atomic.AtomicReference<Thread> consumer = new java.util.concurrent.atomic.AtomicReference<>();
            f.beforeSerialize = () -> consumer.set(Thread.currentThread());
            SMB2WriteResponse response = new SMB2WriteResponse() {
                @Override public int getBytesWritten() { acknowledged.countDown(); return 65536; }
            };
            CompletableFuture<SMB2WriteResponse> stage = new CompletableFuture<>();
            IOException lost = new IOException("response lost");
            FutureTask<SMB2WriteResponse> opaque = new FutureTask<>(() -> {
                if ("error".equals(outcome)) throw lost;
                return response;
            });
            Promise<SMB2WriteResponse, SMBRuntimeException> promise = new Promise<>("write", SMBRuntimeException.Wrapper);
            CompletableFuture<Void> completion = new CompletableFuture<>();
            Future<SMB2WriteResponse> reply = "stage".equals(kind) ? stage : "opaque".equals(kind) ? opaque
                    : new CancellableFuture<>(promise.future(), () -> promise.deliverError(new CancellationException()), completion);
            f.respond = request -> { sent.countDown(); return reply; };
            ByteChunkProvider source = new ByteChunkProvider() {
                int chunks;
                @Override public boolean isAvailable() { return chunks < 2; }
                @Override public int bytesLeft() { return 65536; }
                @Override public void prepareWrite(int limit) {
                    if (chunks == 1) {
                        sourceBlocked.countDown();
                        try { assertTrue(releaseSource.await(5, TimeUnit.SECONDS)); }
                        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
                    }
                }
                @Override protected int getChunk(byte[] bytes) { chunks++; return bytes.length; }
            };
            ExecutorService producer = Executors.newSingleThreadExecutor();
            try {
                Future<Future<Long>> submitted = producer.submit(() -> f.writer.writeAsync(source));
                assertTrue(sourceBlocked.await(3, TimeUnit.SECONDS));
                assertTrue(sent.await(3, TimeUnit.SECONDS));
                awaitWaiting(consumer, "opaque".equals(kind) ? Thread.State.TIMED_WAITING : Thread.State.WAITING);
                if ("cancel".equals(outcome)) assertTrue(reply.cancel(false));
                else if ("opaque".equals(kind)) opaque.run();
                else if ("stage".equals(kind)) {
                    if ("error".equals(outcome)) stage.completeExceptionally(lost);
                    else stage.complete(response);
                } else {
                    if ("error".equals(outcome)) promise.deliverError(lost);
                    else promise.deliver(response);
                    completion.complete(null);
                }
                if ("success".equals(outcome)) {
                    assertTrue(acknowledged.await(3, TimeUnit.SECONDS),
                            "A response completing during the empty-input wait must wake its consumer");
                } else {
                    assertTrue(f.finished.await(3, TimeUnit.SECONDS), "Failure must finish the worker before source input resumes");
                    assertEquals(1, acknowledged.getCount());
                }
                releaseSource.countDown();
                Future<Long> result = submitted.get(3, TimeUnit.SECONDS);
                if ("success".equals(outcome)) {
                    assertEquals(131072L, result.get(3, TimeUnit.SECONDS));
                    assertEquals(2, f.requests.size());
                } else {
                    ExecutionException failure = assertThrows(ExecutionException.class, () -> result.get(3, TimeUnit.SECONDS));
                    Throwable cause = failure.getCause();
                    while (cause.getCause() != null) cause = cause.getCause();
                    if ("cancel".equals(outcome)) assertInstanceOf(CancellationException.class, cause);
                    else assertSame(lost, cause);
                    assertEquals(1, f.requests.size());
                }
            } finally {
                releaseSource.countDown();
                producer.shutdownNow();
                assertTrue(producer.awaitTermination(5, TimeUnit.SECONDS));
            }
        }
    }

    @Test
    void asyncStreamingTotalsBeyondTwoGiBUseBoundedChunksAndLongCounts() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            f.capture = false;
            long length = (1L << 31) + 65537;
            ByteChunkProvider source = generated(length);
            Future<Long> result = f.writer.writeAsync(source);
            assertEquals(length, result.get(20, TimeUnit.SECONDS));
            assertEquals(length, source.getOffset());
        }
    }

    @Test
    void completionAndCancellationRaceHasOneConsistentFutureOutcome() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            ExecutorService racers = Executors.newFixedThreadPool(2);
            try {
                for (int i = 0; i < 100; i++) {
                    CountDownLatch sent = new CountDownLatch(1), start = new CountDownLatch(1);
                    CompletableFuture<SMB2WriteResponse> reply = new CompletableFuture<>();
                    f.respond = request -> { sent.countDown(); return reply; };
                    Future<Long> written = f.writer.writeAsync(new byte[1], i, 0, 1);
                    assertTrue(sent.await(3, TimeUnit.SECONDS));
                    Future<Boolean> cancelled = racers.submit(() -> { start.await(); return written.cancel(false); });
                    Future<?> completed = racers.submit(() -> { start.await(); reply.complete(acknowledge(1)); return null; });
                    start.countDown();
                    boolean won = cancelled.get(3, TimeUnit.SECONDS);
                    completed.get(3, TimeUnit.SECONDS);
                    if (won) {
                        assertTrue(written.isCancelled());
                        assertThrows(CancellationException.class, written::get);
                    } else {
                        assertEquals(1L, written.get(3, TimeUnit.SECONDS));
                    }
                }
            } finally { racers.shutdownNow(); }
        }
    }

    @Test
    void sourceFailureStopsAndCancelsPreviouslySubmittedWrites() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            CountDownLatch sent = new CountDownLatch(1);
            CompletableFuture<SMB2WriteResponse> reply = new CompletableFuture<>();
            f.respond = request -> { sent.countDown(); return reply; };
            ByteChunkProvider source = new ByteChunkProvider() {
                int prepared;
                @Override public boolean isAvailable() { return true; }
                @Override public int bytesLeft() { return 65536; }
                @Override public void prepareWrite(int limit) {
                    if (++prepared == 2) {
                        try { assertTrue(sent.await(3, TimeUnit.SECONDS)); }
                        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
                        throw new SMBRuntimeException("source read failed");
                    }
                }
                @Override protected int getChunk(byte[] bytes) { return bytes.length; }
            };
            SMBRuntimeException error = assertThrows(SMBRuntimeException.class, () -> f.writer.writeAsync(source));
            assertEquals("source read failed", error.getMessage());
            assertTrue(f.finished.await(3, TimeUnit.SECONDS));
            assertTrue(reply.isCancelled());
            assertEquals(1, f.requests.size());
        }
    }

    @Test
    void emptyProviderCompletesWithoutSending() throws Exception {
        try (Fixture f = new Fixture(65536)) {
            assertEquals(0L, f.writer.writeAsync(new byte[0], 0, 0, 0).get(3, TimeUnit.SECONDS));
            assertTrue(f.requests.isEmpty());
        }
    }

    private static ByteChunkProvider generated(long length) {
        return new ByteChunkProvider() {
            long remaining = length;
            @Override public boolean isAvailable() { return remaining > 0; }
            @Override public void prepareWrite(int size) { }
            @Override public int bytesLeft() { return (int) Math.min(Integer.MAX_VALUE, remaining); }
            @Override protected int getChunk(byte[] bytes) {
                int size = (int) Math.min(bytes.length, remaining); remaining -= size; return size;
            }
        };
    }

    private static SMB2WriteResponse acknowledge(int count) {
        return new SMB2WriteResponse() {
            @Override public int getBytesWritten() { return count; }
        };
    }

    private static class Submitted {
        final long offset;
        final byte[] bytes;
        Submitted(long offset, byte[] bytes) { this.offset = offset; this.bytes = bytes; }
    }

    private static class Fixture implements AutoCloseable {
        final List<Submitted> requests = new CopyOnWriteArrayList<>();
        final ExecutorService worker = Executors.newSingleThreadExecutor();
        final CountDownLatch finished = new CountDownLatch(1);
        final SMB2Writer writer;
        final DiskShare share;
        final CountDownLatch closed = new CountDownLatch(1);
        volatile int credits = 16;
        volatile boolean capture = true;
        volatile Runnable beforeSerialize = () -> { };
        volatile Function<Submitted, Future<SMB2WriteResponse>> respond = request -> CompletableFuture.completedFuture(acknowledge(request.bytes.length));

        Fixture(int limit) throws Exception {
            TreeConnect tree = mock(TreeConnect.class);
            Session session = mock(Session.class, withSettings().stubOnly());
            when(tree.getSession()).thenReturn(session);
            when(tree.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, limit, limit, limit, true));
            when(tree.getConfig()).thenReturn(SmbConfig.builder().withWriteBufferSize(limit).build());
            doAnswer(call -> {
                Runnable task = call.getArgument(0);
                worker.execute(() -> { try { task.run(); } finally { finished.countDown(); } });
                return null;
            }).when(session).executeAsyncWrite(any());
            when(session.send(any())).thenAnswer(call -> {
                SMB2Packet packet = call.getArgument(0);
                if (packet instanceof SMB2Close) {
                    closed.countDown();
                    return CompletableFuture.completedFuture(new SMB2Close());
                }
                SMB2WriteRequest request = (SMB2WriteRequest) packet;
                beforeSerialize.run();
                request.setCreditsAssigned(credits);
                SMBBuffer buffer = new SMBBuffer(); request.write(buffer);
                byte[] wire = buffer.getCompactData();
                ByteBuffer decoded = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
                Submitted submission = new Submitted(decoded.getLong(72), Arrays.copyOfRange(wire, 112, 112 + decoded.getInt(68)));
                if (capture) requests.add(submission);
                return respond.apply(submission);
            });
            share = new DiskShare(new SmbPath("server", "share"), tree, null);
            writer = new SMB2Writer(share, ID, "test");
        }
        File file() { return new File(ID, share, new SmbPath("server", "share", "test")); }
        @Override public void close() throws Exception {
            worker.shutdownNow();
            assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS));
        }
    }
}
