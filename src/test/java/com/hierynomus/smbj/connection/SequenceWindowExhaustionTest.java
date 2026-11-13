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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.lang.reflect.Field;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class SequenceWindowExhaustionTest {
    private SequenceWindow at(long first) throws Exception {
        SequenceWindow window = new SequenceWindow();
        Field field = SequenceWindow.class.getDeclaredField("lowestAvailable");
        field.setAccessible(true); ((AtomicLong) field.get(window)).set(first);
        window.creditsGranted(10);
        return window;
    }

    @Test
    void signedLongBoundaryIsNotUnsignedMessageIdExhaustion() throws Exception {
        SequenceWindow window = at(Long.MAX_VALUE);
        assertArrayEquals(new long[]{Long.MAX_VALUE, Long.MIN_VALUE, Long.MIN_VALUE + 1}, window.get(3));
        assertEquals(Long.MIN_VALUE + 2, window.get());
    }

    @Test
    void finalUsableRangeDoesNotWrapOrAllocateNotificationMid() throws Exception {
        SequenceWindow window = at(-3L);
        assertArrayEquals(new long[]{-3L, -2L}, window.get(2));
        TransportException exhausted = assertThrows(TransportException.class, () -> window.get(1));
        window.creditsGranted(10);
        assertSame(exhausted, assertThrows(TransportException.class, () -> window.get(1)));
    }

    @Test
    void rangeCrossingUnsignedEndIsRejectedBeforeConsumingCredits() throws Exception {
        SequenceWindow window = at(-2L);
        int before = window.available();
        assertThrows(TransportException.class, () -> window.get(3));
        assertEquals(before, window.available());
    }

    @Test
    void concurrentExhaustionCannotResetOrReallocateIds() throws Exception {
        SequenceWindow window = at(-2L);
        ExecutorService workers = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Callable<Boolean> allocate = () -> {
                start.await();
                try { assertEquals(-2L, window.get()); return true; }
                catch (TransportException exhausted) { return false; }
            };
            Future<Boolean> first = workers.submit(allocate), second = workers.submit(allocate);
            start.countDown();
            assertNotEquals(first.get(3, TimeUnit.SECONDS), second.get(3, TimeUnit.SECONDS));
        } finally { workers.shutdownNow(); }
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 65536, Integer.MAX_VALUE})
    void invalidCreditChargeCannotCreateAnUnboundedRange(int credits) {
        SequenceWindow window = new SequenceWindow();
        window.disableCredits();
        assertThrows(IllegalArgumentException.class, () -> window.get(credits));
    }
}
