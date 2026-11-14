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
package com.hierynomus.smbj;

import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.connection.AbortTestConnection;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.testing.PacketProcessor.DefaultPacketProcessor;
import com.hierynomus.smbj.testing.StubTransportLayerFactory;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.net.SocketFactory;
import java.io.IOException;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(10)
class SMBClientConnectLifecycleTest {
    @Test
    void clientCloseAbortsExistingAndPendingConnectionsWithoutWaitingForSocketFactory() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AbortTestConnection.TestSocket lateSocket = new AbortTestConnection.TestSocket();
        SocketFactory sockets = mock(SocketFactory.class);
        when(sockets.createSocket(anyString(), anyInt())).thenAnswer(call -> {
            entered.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            return lateSocket;
        });
        AtomicInteger attempts = new AtomicInteger();
        AtomicReference<Connection> pending = new AtomicReference<>();
        StubTransportLayerFactory<SMBPacketData<?>, SMBPacket<?, ?>> established =
                new StubTransportLayerFactory<>(new DefaultPacketProcessor());
        SmbConfig config = SmbConfig.builder().withTransactTimeout(2, TimeUnit.SECONDS)
                .withTransportLayerFactory((handlers, settings) -> {
                    if (attempts.getAndIncrement() == 0) {
                        return established.createTransportLayer(handlers, settings);
                    }
                    pending.set((Connection) handlers.getReceiver());
                    return new DirectTcpTransport<>(sockets, 0, handlers);
                }).build();
        SMBClient client = new SMBClient(config);
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Connection existing = client.connect("existing.invalid");
            Future<Connection> connecting = workers.submit(() -> client.connect("pending.invalid"));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            workers.submit(client::close).get(1, TimeUnit.SECONDS);
            assertTrue(existing.isClosed());
            assertTrue(pending.get().isClosed());
            Future<Connection> rejected = workers.submit(() -> client.connect("after-close.invalid"));
            assertInstanceOf(IOException.class,
                    assertThrows(ExecutionException.class, () -> rejected.get(1, TimeUnit.SECONDS)).getCause());
            release.countDown();
            assertInstanceOf(IOException.class,
                    assertThrows(ExecutionException.class, () -> connecting.get(2, TimeUnit.SECONDS)).getCause());
            assertTrue(lateSocket.isClosed());
            assertEquals(1, lateSocket.closeCalls.get());
            assertEquals(2, attempts.get());
        } finally {
            release.countDown();
            client.close();
            lateSocket.close();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS));
        }
    }

    @Test
    void concurrentPooledConnectsRetainIndependentUsageLeases() throws Exception {
        SmbConfig config = SmbConfig.builder().withTransportLayerFactory(
                new StubTransportLayerFactory<>(new DefaultPacketProcessor())).build();
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try (SMBClient client = new SMBClient(config)) {
            Future<Connection> first = workers.submit(() -> client.connect("same.invalid"));
            Future<Connection> second = workers.submit(() -> client.connect("same.invalid"));
            Connection connection = first.get(2, TimeUnit.SECONDS);
            assertSame(connection, second.get(2, TimeUnit.SECONDS));
            connection.close();
            assertTrue(connection.isConnected());
            connection.close();
            assertTrue(connection.isClosed());
        } finally {
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS));
        }
    }
}
