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
import com.hierynomus.mssmb2.SMB2PacketFactory;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.protocol.transport.*;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smb.SMBPacketData;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.*;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransport;
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransportFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.channels.AsynchronousChannelGroup;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class AsyncConnectionFailureTest {
    @Test
    void peerEofFailsOutstandingNegotiateAndRetiresConnection() throws Exception {
        AsynchronousChannelGroup group = AsynchronousChannelGroup.withFixedThreadPool(2, Executors.defaultThreadFactory());
        AtomicInteger events = new AtomicInteger();
        CountDownLatch retired = new CountDownLatch(1);
        SMBEventBus bus = new SMBEventBus() {
            public void publish(SMBEvent event) {
                if (event instanceof ConnectionClosed) {
                    events.incrementAndGet();
                    retired.countDown();
                }
                super.publish(event);
            }
        };
        SmbConfig config = SmbConfig.builder().withTransportLayerFactory(new AsyncDirectTcpTransportFactory<>(group))
                .withTransactTimeout(30, TimeUnit.SECONDS).build();
        Connection connection = new Connection(config, null, bus, new ServerList());
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(2000);
            Future<?> connecting = worker.submit(() -> {
                connection.connect("127.0.0.1", listener.getLocalPort());
                return null;
            });
            try (Socket peer = listener.accept()) {
                peer.setSoTimeout(2000);
                DataInputStream input = new DataInputStream(peer.getInputStream());
                int length = input.readInt();
                assertTrue(length >= 64 && length < 1024 * 1024);
                input.readFully(new byte[length]);
                Request request = connection.outstandingRequests.getRequestByMessageId(0L);
                assertNotNull(request);
                assertFalse(request.getPromise().isFulfilled());
                peer.shutdownOutput();
                ExecutionException failure = assertThrows(ExecutionException.class, () -> connecting.get(2, TimeUnit.SECONDS));
                assertInstanceOf(IOException.class, failure.getCause());
                assertTrue(retired.await(2, TimeUnit.SECONDS));
                assertTrue(request.getPromise().isFulfilled());
                assertTrue(connection.isClosed());
                assertFalse(connection.isConnected());
                assertEquals(-1, input.read());
                assertEquals(1, events.get());
                assertFalse(group.isShutdown());
            }
        } finally {
            connection.close(true);
            worker.shutdownNow();
            assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS));
            group.shutdownNow();
            assertTrue(group.awaitTermination(3, TimeUnit.SECONDS));
        }
        assertEquals(1, events.get());
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void asyncDecoderAndReceiverFailuresAreReportedOnce(boolean decoderFailure, boolean fatalError) throws Exception {
        AsynchronousChannelGroup group = AsynchronousChannelGroup.withFixedThreadPool(2, Executors.defaultThreadFactory());
        Throwable failure = fatalError ? new AssertionError("controlled async failure") : new IllegalStateException("controlled async failure");
        AtomicInteger errors = new AtomicInteger();
        AtomicReference<Throwable> observed = new AtomicReference<>();
        CountDownLatch failed = new CountDownLatch(1);
        PacketFactory<SMBPacketData<?>> decoder = new PacketFactory<SMBPacketData<?>>() {
            public SMBPacketData<?> read(byte[] bytes) throws BufferException, IOException {
                if (decoderFailure) throwUnchecked(failure);
                return new SMB2PacketFactory().read(bytes);
            }
            public boolean canHandle(byte[] bytes) { return true; }
        };
        PacketReceiver<SMBPacketData<?>> receiver = new PacketReceiver<SMBPacketData<?>>() {
            public void handle(SMBPacketData<?> packet) { throwUnchecked(failure); }
            public void handleError(Throwable exception) {
                errors.incrementAndGet();
                observed.set(exception);
                failed.countDown();
            }
        };
        AsyncDirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> transport = new AsyncDirectTcpTransport<>(0,
                new PacketHandlers<>(new SMBPacketSerializer(), receiver, decoder), group);
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(2000);
            transport.connect(new InetSocketAddress("127.0.0.1", listener.getLocalPort()));
            try (Socket peer = listener.accept()) {
                peer.setSoTimeout(2000);
                SMBBuffer packet = new SMBBuffer();
                new SMB2Echo(SMB2Dialect.SMB_2_1).write(packet);
                byte[] bytes = packet.getCompactData();
                DataOutputStream output = new DataOutputStream(peer.getOutputStream());
                output.writeInt(bytes.length);
                output.write(bytes);
                output.flush();
                assertTrue(failed.await(2, TimeUnit.SECONDS));
                assertSame(failure, observed.get());
                assertFalse(transport.isConnected());
                assertEquals(-1, peer.getInputStream().read());
                assertThrows(TransportException.class, () -> transport.write(new SMB2Echo(SMB2Dialect.SMB_2_1)));
                assertThrows(IOException.class,
                        () -> transport.connect(new InetSocketAddress("127.0.0.1", listener.getLocalPort())));
                assertFalse(group.isShutdown());
            }
        } finally {
            transport.disconnect();
            group.shutdownNow();
            assertTrue(group.awaitTermination(3, TimeUnit.SECONDS));
        }
        assertEquals(1, errors.get());
    }

    @Test
    void intentionalDisconnectDoesNotReportAsyncFailure() throws Exception {
        AsynchronousChannelGroup group = AsynchronousChannelGroup.withFixedThreadPool(2, Executors.defaultThreadFactory());
        AtomicInteger errors = new AtomicInteger();
        PacketReceiver<SMBPacketData<?>> receiver = new PacketReceiver<SMBPacketData<?>>() {
            public void handle(SMBPacketData<?> packet) { fail("No packet was sent by the peer"); }
            public void handleError(Throwable failure) { errors.incrementAndGet(); }
        };
        AsyncDirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> transport = new AsyncDirectTcpTransport<>(0,
                new PacketHandlers<>(new SMBPacketSerializer(), receiver, new PacketFactory<SMBPacketData<?>>() {
                    public SMBPacketData<?> read(byte[] bytes) throws BufferException, IOException {
                        return new SMB2PacketFactory().read(bytes);
                    }
                    public boolean canHandle(byte[] bytes) { return true; }
                }), group);
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(2000);
            transport.connect(new InetSocketAddress("127.0.0.1", listener.getLocalPort()));
            try (Socket peer = listener.accept()) {
                peer.setSoTimeout(2000);
                transport.disconnect();
                assertFalse(transport.isConnected());
                assertEquals(-1, peer.getInputStream().read());
                assertFalse(group.isShutdown());
            }
        } finally {
            transport.disconnect();
            group.shutdownNow();
            assertTrue(group.awaitTermination(3, TimeUnit.SECONDS));
        }
        assertEquals(0, errors.get());
    }

    private static void throwUnchecked(Throwable failure) {
        if (failure instanceof Error) throw (Error) failure;
        throw (RuntimeException) failure;
    }
}
