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

import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.ServerList;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ConnectionCleanupCompletionTest {
    @Test
    @SuppressWarnings("unchecked")
    void concurrentClosersSharePhysicalCleanupFailure() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        Connection connection = new Connection(SmbConfig.builder()
                .withTransportLayerFactory((handlers, settings) -> transport).build(), null,
                new SMBEventBus(), new ServerList());
        CountDownLatch closing = new CountDownLatch(1), release = new CountDownLatch(1), secondEntered = new CountDownLatch(1);
        IOException failure = new IOException("socket cleanup failed");
        doAnswer(call -> {
            closing.countDown();
            assertTrue(release.await(3, TimeUnit.SECONDS));
            throw failure;
        }).when(transport).disconnect();
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Future<IOException> first = workers.submit(() -> assertThrows(IOException.class, () -> connection.close(true)));
            assertTrue(closing.await(3, TimeUnit.SECONDS));
            Future<IOException> second = workers.submit(() -> {
                secondEntered.countDown();
                return assertThrows(IOException.class, () -> connection.close(true));
            });
            assertTrue(secondEntered.await(3, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> second.get(100, TimeUnit.MILLISECONDS));
            release.countDown();
            assertSame(failure, first.get(3, TimeUnit.SECONDS));
            assertSame(failure, second.get(3, TimeUnit.SECONDS));
            verify(transport, times(1)).disconnect();
        } finally {
            release.countDown();
            workers.shutdownNow();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void reentrantCleanupCallbackDoesNotWaitForItself() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        Connection connection = new Connection(SmbConfig.builder()
                .withTransportLayerFactory((handlers, settings) -> transport).build(), null,
                new SMBEventBus(), new ServerList());
        doAnswer(call -> { connection.close(true); return null; }).when(transport).disconnect();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            worker.submit(() -> { connection.close(true); return null; }).get(3, TimeUnit.SECONDS);
            verify(transport, times(1)).disconnect();
        } finally { worker.shutdownNow(); }
    }
}
