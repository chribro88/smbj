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

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.messages.SMB2Cancel;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.commons.concurrent.AFuture;
import com.hierynomus.smbj.common.SMBRuntimeException;
import org.junit.jupiter.api.Test;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class RequestCancellationTest {
    private Request request() {
        return new Request(new SMB2Echo(SMB2Dialect.SMB_3_1_1), 123, UUID.randomUUID());
    }

    @Test
    void failedCallbackCannotRetryWithChangedAsyncIdentity() {
        Request request = request();
        AtomicInteger attempts = new AtomicInteger();
        AFuture<?> future = request.getFuture(() -> {
            assertNotNull(request.newCancel(SMB2Dialect.SMB_3_1_1, 47));
            attempts.incrementAndGet();
            throw new SMBRuntimeException("unknown wire outcome");
        });
        assertThrows(SMBRuntimeException.class, () -> future.cancel(true));
        request.setAsyncId(789);
        assertFalse(future.cancel(true));
        assertNull(request.newCancel(SMB2Dialect.SMB_3_1_1, 47));
        assertEquals(1, attempts.get());
    }

    @Test
    void cancellationWakesAnExistingGetAndRejectsLaterGets() throws Exception {
        Request request = request();
        AFuture<?> future = request.getFuture(() -> { });
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            Future<CancellationException> waiting = worker.submit(() -> assertThrows(CancellationException.class, future::get));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (!request.getPromise().hasWaiters() && System.nanoTime() < deadline) Thread.yield();
            assertTrue(request.getPromise().hasWaiters());
            assertTrue(future.cancel(false));
            assertNotNull(waiting.get(1, TimeUnit.SECONDS));
            assertThrows(CancellationException.class, future::get);
            assertThrows(CancellationException.class, () -> future.get(1, TimeUnit.SECONDS));
        } finally { worker.shutdownNow(); }
    }

    @Test
    void asyncSnapshotIncludesZeroIdAndIsImmutableAfterClaim() {
        Request request = request();
        request.setAsyncId(0);
        SMB2Cancel cancel = request.newCancel(SMB2Dialect.SMB_3_1_1, 47);
        request.setAsyncId(789);
        assertTrue(cancel.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_ASYNC_COMMAND));
        assertEquals(0, cancel.getHeader().getAsyncId());
        assertEquals(123, cancel.getHeader().getMessageId());
        assertEquals(47, cancel.getHeader().getSessionId());
        assertNull(request.newCancel(SMB2Dialect.SMB_3_1_1, 47));
    }

    @Test
    void completedOrFailedRequestCannotClaimCancellation() {
        Request success = request();
        success.getPromise().deliver(new SMB2Echo(SMB2Dialect.SMB_3_1_1));
        assertNull(success.newCancel(SMB2Dialect.SMB_3_1_1, 47));
        Request failed = request();
        failed.getPromise().deliverError(new SMBRuntimeException("closed"));
        assertNull(failed.newCancel(SMB2Dialect.SMB_3_1_1, 47));
    }

    @Test
    void callbackDoesNotHoldFutureLockAndConcurrentCancelEmitsOnce() throws Exception {
        Request request = request();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicInteger attempts = new AtomicInteger();
        AFuture<?> future = request.getFuture(() -> {
            attempts.incrementAndGet();
            entered.countDown();
            try {
                assertTrue(release.await(5, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SMBRuntimeException(e);
            }
        });
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = workers.submit(() -> future.cancel(true));
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            Future<Boolean> second = workers.submit(() -> {
                assertTrue(future.isDone());
                assertTrue(future.isCancelled());
                return future.cancel(true);
            });
            assertFalse(second.get(1, TimeUnit.SECONDS));
            release.countDown();
            assertTrue(first.get(1, TimeUnit.SECONDS));
            assertEquals(1, attempts.get());
        } finally {
            release.countDown();
            workers.shutdownNow();
        }
    }
}
