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
package com.hierynomus.smbj.transport.tcp.async;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.transport.*;
import com.hierynomus.smb.*;
import com.hierynomus.smbj.connection.SMBPacketSerializer;
import org.junit.jupiter.api.Test;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AsyncTransportLifecycleTest {
    @Test
    void disconnectWinsAgainstLateConnectCompletionWithoutStartingReader() throws Exception {
        Fixture f = new Fixture(false);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            Future<?> connect = worker.submit(() -> assertThrows(IOException.class,
                    () -> f.transport.connect(new InetSocketAddress("localhost", 445))));
            assertTrue(f.dialing.await(3, TimeUnit.SECONDS));
            f.transport.disconnect();
            f.connected.complete(null);
            connect.get(3, TimeUnit.SECONDS);
            assertFalse(f.transport.isConnected());
            verify(f.channel, never()).read(any(ByteBuffer.class), anyLong(), any(), any(), any());
            assertThrows(TransportException.class, () -> f.transport.write(new SMB2Echo(SMB2Dialect.SMB_2_1)));
        } finally {
            f.connected.complete(null);
            f.transport.disconnect();
            worker.shutdownNow();
        }
    }

    @Test
    void failedConnectClosesChannelWithoutStartingReader() throws Exception {
        Fixture f = new Fixture(false);
        f.connected.completeExceptionally(new IOException("dial failed"));
        assertThrows(TransportException.class, () -> f.transport.connect(new InetSocketAddress("localhost", 445)));
        assertFalse(f.transport.isConnected());
        assertFalse(f.open.get());
        verify(f.channel, never()).read(any(ByteBuffer.class), anyLong(), any(), any(), any());
    }

    @Test
    void readFailureNotifiesOwnerOnceAndClosesChannel() throws Exception {
        Fixture f = new Fixture(true);
        try {
            f.transport.connect(new InetSocketAddress("localhost", 445));
            EOFException failure = new EOFException("peer closed");
            f.reader.get().failed(failure, null);
            f.reader.get().failed(failure, null);
            verify(f.receiver, times(1)).handleError(same(failure));
            assertFalse(f.transport.isConnected());
            assertFalse(f.open.get());
        } finally { f.transport.disconnect(); }
    }

    @Test
    void failedWriteAbandonsQueuedFramesAndNotifiesOutsideWriterMonitor() throws Exception {
        Fixture f = new Fixture(true);
        try {
            f.transport.connect(new InetSocketAddress("localhost", 445));
            doAnswer(call -> {
                assertFalse(Thread.holdsLock(f.transport));
                return null;
            }).when(f.receiver).handleError(any());
            f.transport.write(new SMB2Echo(SMB2Dialect.SMB_2_1));
            f.transport.write(new SMB2Echo(SMB2Dialect.SMB_2_1));
            IOException failure = new IOException("unknown write outcome");
            f.writer.get().failed(failure, null);
            f.writer.get().failed(failure, null);
            assertFalse(f.transport.isConnected());
            verify(f.channel, times(1)).write(any(ByteBuffer.class), anyLong(), any(), any(), any());
            verify(f.receiver, times(1)).handleError(same(failure));
            assertThrows(TransportException.class, () -> f.transport.write(new SMB2Echo(SMB2Dialect.SMB_2_1)));
        } finally { f.transport.disconnect(); }
    }

    @Test
    void intentionalDisconnectStopsReaderWithoutReportingSpuriousFailure() throws Exception {
        Fixture f = new Fixture(true);
        f.transport.connect(new InetSocketAddress("localhost", 445));
        f.transport.disconnect();
        f.reader.get().failed(new java.nio.channels.AsynchronousCloseException(), null);
        verify(f.receiver, never()).handleError(any());
    }

    private static class Fixture {
        final AsynchronousSocketChannel channel = mock(AsynchronousSocketChannel.class);
        final AtomicBoolean open = new AtomicBoolean(true);
        final CompletableFuture<Void> connected = new CompletableFuture<>();
        final CountDownLatch dialing = new CountDownLatch(1);
        final AtomicReference<CompletionHandler<Integer, PacketBufferReader>> reader = new AtomicReference<>();
        final AtomicReference<CompletionHandler<Integer, Object>> writer = new AtomicReference<>();
        final PacketReceiver<SMBPacketData<?>> receiver;
        final AsyncDirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> transport;

        @SuppressWarnings("unchecked")
        Fixture(boolean complete) throws Exception {
            receiver = mock(PacketReceiver.class);
            when(channel.isOpen()).thenAnswer(call -> open.get());
            doAnswer(call -> { open.set(false); return null; }).when(channel).close();
            when(channel.connect(any())).thenAnswer(call -> { dialing.countDown(); return connected; });
            doAnswer(call -> { reader.set(call.getArgument(4)); return null; })
                    .when(channel).read(any(ByteBuffer.class), anyLong(), any(), any(), any());
            doAnswer(call -> { writer.set(call.getArgument(4)); return null; })
                    .when(channel).write(any(ByteBuffer.class), anyLong(), any(), any(), any());
            PacketFactory<SMBPacketData<?>> factory = mock(PacketFactory.class);
            transport = new AsyncDirectTcpTransport<>(0,
                    new PacketHandlers<>(new SMBPacketSerializer(), receiver, factory), channel);
            if (complete) connected.complete(null);
        }
    }
}
