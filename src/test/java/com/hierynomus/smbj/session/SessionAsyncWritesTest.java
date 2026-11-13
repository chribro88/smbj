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

import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.ConnectionClosed;
import com.hierynomus.smbj.event.SMBEventBus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.spec.SecretKeySpec;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(15)
class SessionAsyncWritesTest {
    @Test
    void workerAndQueueAdmissionAreBoundedAndSessionFailureSettlesQueuedWork() throws Exception {
        Session session = new Session(null, SmbConfig.createDefaultConfig(), null, null, null, null, null);
        CountDownLatch started = new CountDownLatch(4), release = new CountDownLatch(1), stopped = new CountDownLatch(4);
        List<FutureTask<Void>> queued = new ArrayList<>();
        try {
            for (int i = 0; i < 4; i++) session.executeAsyncWrite(blocking(started, release, stopped));
            assertTrue(started.await(3, TimeUnit.SECONDS));
            for (int i = 0; i < 64; i++) {
                FutureTask<Void> task = new FutureTask<>(() -> fail("queued task must not start"));
                queued.add(task); session.executeAsyncWrite(task);
            }
            assertThrows(RejectedExecutionException.class,
                    () -> session.executeAsyncWrite(new FutureTask<>(() -> null)));
            session.failChannels(new IOException("session failed"));
            assertTrue(stopped.await(3, TimeUnit.SECONDS));
            for (FutureTask<Void> task : queued) assertTrue(task.isCancelled());
            assertThrows(RejectedExecutionException.class,
                    () -> session.executeAsyncWrite(new FutureTask<>(() -> null)));
        } finally {
            release.countDown(); session.failChannels(new IOException("test cleanup"));
        }
    }

    @Test
    void blockedSessionCannotStarveAnotherSessionsAsyncWriter() throws Exception {
        Session first = new Session(null, SmbConfig.createDefaultConfig(), null, null, null, null, null);
        Session second = new Session(null, SmbConfig.createDefaultConfig(), null, null, null, null, null);
        CountDownLatch started = new CountDownLatch(4), release = new CountDownLatch(1), stopped = new CountDownLatch(4);
        try {
            for (int i = 0; i < 4; i++) first.executeAsyncWrite(blocking(started, release, stopped));
            assertTrue(started.await(3, TimeUnit.SECONDS));
            FutureTask<Integer> healthy = new FutureTask<>(() -> 47);
            second.executeAsyncWrite(healthy);
            assertEquals(47, healthy.get(3, TimeUnit.SECONDS));
        } finally {
            release.countDown();
            first.failChannels(new IOException("test cleanup"));
            second.failChannels(new IOException("test cleanup"));
            assertTrue(stopped.await(3, TimeUnit.SECONDS));
        }
    }

    @Test
    void losingPrimaryDoesNotStopSurvivingChannelButLosingLastChannelStopsAdmission() throws Exception {
        SMBEventBus bus = new SMBEventBus();
        Connection primary = mock(Connection.class), secondary = mock(Connection.class);
        when(primary.isConnected()).thenReturn(true); when(secondary.isConnected()).thenReturn(true);
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null, bus, null, null, null);
        session.addChannel(secondary, new SecretKeySpec(new byte[16], "AesCmac"));
        try {
            bus.publish(new ConnectionClosed("server", 445, primary));
            FutureTask<Integer> surviving = new FutureTask<>(() -> 47);
            session.executeAsyncWrite(surviving);
            assertEquals(47, surviving.get(3, TimeUnit.SECONDS));
            bus.publish(new ConnectionClosed("server", 445, secondary));
            assertThrows(RejectedExecutionException.class,
                    () -> session.executeAsyncWrite(new FutureTask<>(() -> null)));
        } finally { session.failChannels(new IOException("test cleanup")); }
    }

    private FutureTask<Void> blocking(CountDownLatch started, CountDownLatch release, CountDownLatch stopped) {
        return new FutureTask<>(() -> {
            started.countDown();
            try { release.await(); return null; }
            finally { stopped.countDown(); }
        });
    }
}
