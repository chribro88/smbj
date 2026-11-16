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

import com.hierynomus.protocol.transport.TransportException;
import org.junit.jupiter.api.Test;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class RequestFutureReviewTest {
    @Test
    void failedRequestIsDonePreservesCauseAndCannotSendCancel() {
        Request request = new Request(new com.hierynomus.mssmb2.messages.SMB2Echo(com.hierynomus.mssmb2.SMB2Dialect.SMB_3_1_1), 1, UUID.randomUUID());
        AtomicInteger cancels = new AtomicInteger();
        Future<?> future = request.getFuture(cancels::incrementAndGet);
        TransportException original = new TransportException("synthetic failure");
        assertFalse(future.isDone());
        request.getPromise().deliverError(original);
        assertTrue(future.isDone());
        ExecutionException failure = assertThrows(ExecutionException.class, () -> future.get(1, TimeUnit.SECONDS));
        assertSame(original, failure.getCause().getCause());
        assertFalse(future.cancel(true));
        assertEquals(0, cancels.get());
    }
}
