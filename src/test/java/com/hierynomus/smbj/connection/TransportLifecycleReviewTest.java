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

import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.transport.*;
import com.hierynomus.smb.*;
import com.hierynomus.smbj.transport.PacketReader;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import javax.net.SocketFactory;
import java.io.*;
import java.net.*;
import java.lang.reflect.Field;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class TransportLifecycleReviewTest {
    static final PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> HANDLERS = new PacketHandlers<>(
        new SMBPacketSerializer(), new PacketReceiver<SMBPacketData<?>>() {
            public void handle(SMBPacketData<?> p) { }
            public void handleError(Throwable error) { }
        }, new PacketFactory<SMBPacketData<?>>() {
            public SMBPacketData<?> read(byte[] bytes) { throw new AssertionError(); }
            public boolean canHandle(byte[] bytes) { return false; }
        });

    static class ControlledSocket extends Socket {
        volatile boolean closed;
        final CountDownLatch writing = new CountDownLatch(1);
        final CountDownLatch releaseWrite;
        final CountDownLatch releaseRead = new CountDownLatch(1);
        ControlledSocket(boolean blockWrite) { releaseWrite = new CountDownLatch(blockWrite ? 1 : 0); }
        @Override public boolean isConnected() { return true; }
        @Override public boolean isClosed() { return closed; }
        @Override public void setSoTimeout(int n) { }
        @Override public InputStream getInputStream() { return new InputStream() {
            @Override public int read() throws IOException {
                try { releaseRead.await(); } catch (InterruptedException e) { throw new IOException(e); }
                return -1;
            }
            @Override public void close() { releaseRead.countDown(); }
        }; }
        @Override public OutputStream getOutputStream() { return new OutputStream() {
            @Override public void write(int value) throws IOException {
                writing.countDown();
                try { releaseWrite.await(); } catch (InterruptedException e) { throw new IOException(e); }
                if (closed) throw new SocketException("Socket closed");
            }
        }; }
        @Override public void close() { closed = true; releaseRead.countDown(); releaseWrite.countDown(); }
    }
    static class ControlledFactory extends SocketFactory {
        final Socket socket;
        final CountDownLatch dialing = new CountDownLatch(1);
        final CountDownLatch releaseDial;
        ControlledFactory(Socket socket, boolean blockDial) {
            this.socket = socket; releaseDial = new CountDownLatch(blockDial ? 1 : 0);
        }
        @Override public Socket createSocket(String host, int port) throws IOException {
            dialing.countDown();
            try { releaseDial.await(); } catch (InterruptedException e) { throw new IOException(e); }
            return socket;
        }
        @Override public Socket createSocket(String h, int p, InetAddress l, int lp) throws IOException { return createSocket(h,p); }
        @Override public Socket createSocket(InetAddress h, int p) throws IOException { return createSocket(h.toString(),p); }
        @Override public Socket createSocket(InetAddress h, int p, InetAddress l, int lp) throws IOException { return createSocket(h.toString(),p); }
    }

    static <T> FutureTask<T> task(Callable<T> action) {
        FutureTask<T> future = new FutureTask<>(action);
        Thread thread = new Thread(future, "lifecycle-review-worker");
        thread.setDaemon(true);
        thread.start();
        return future;
    }

    static <T> T result(Future<T> future) throws Exception {
        try { return future.get(3, TimeUnit.SECONDS); }
        catch (TimeoutException timeout) {
            Thread.getAllStackTraces().forEach((thread, stack) -> {
                System.err.println(thread);
                for (StackTraceElement frame : stack) System.err.println("  " + frame);
            });
            throw timeout;
        }
    }

    static Thread reader(DirectTcpTransport<?, ?> transport) throws Exception {
        Field field = DirectTcpTransport.class.getDeclaredField("packetReaderThread");
        field.setAccessible(true);
        Object reader = field.get(transport);
        if (reader == null) return null;
        field = PacketReader.class.getDeclaredField("thread");
        field.setAccessible(true);
        return (Thread) field.get(reader);
    }

    @Test
    void socketClosureDoesNotWaitForBlockedWriter() throws Exception {
        ControlledSocket socket = new ControlledSocket(true);
        DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> transport = new DirectTcpTransport<>(
                new ControlledFactory(socket, false), 0, HANDLERS);
        transport.connect(new InetSocketAddress("127.0.0.1", 445));
        Thread reader = reader(transport);
        FutureTask<TransportException> writer = task(() -> assertThrows(TransportException.class,
                () -> transport.write(new SMB2Echo(SMB2Dialect.SMB_2_1))));
        FutureTask<Void> close = null;
        try {
            assertTrue(socket.writing.await(3, TimeUnit.SECONDS));
            close = task(() -> { transport.disconnect(); return null; });
            result(close);
            assertTrue(socket.closed);
            assertNotNull(result(writer));
        } finally {
            socket.close();
            if (close != null) result(close);
            result(writer);
            transport.disconnect();
            reader.join(3000);
            assertFalse(reader.isAlive());
        }
    }

    @Test
    void disconnectRejectsFactoryCompletionWithoutCreatingReader() throws Exception {
        ControlledSocket socket = new ControlledSocket(false);
        ControlledFactory factory = new ControlledFactory(socket, true);
        DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> transport = new DirectTcpTransport<>(factory, 0, HANDLERS);
        FutureTask<IOException> connect = task(() -> assertThrows(IOException.class,
                () -> transport.connect(new InetSocketAddress("127.0.0.1", 445))));
        try {
            assertTrue(factory.dialing.await(3, TimeUnit.SECONDS));
            transport.disconnect();
            factory.releaseDial.countDown();
            result(connect);
            assertTrue(socket.closed);
            assertFalse(transport.isConnected());
            assertNull(reader(transport));
        } finally {
            factory.releaseDial.countDown();
            socket.close();
            try { result(connect); } finally {
                transport.disconnect();
                Thread reader = reader(transport);
                if (reader != null) { reader.join(3000); assertFalse(reader.isAlive()); }
            }
        }
    }

    @Test
    void disconnectDoesNotWaitForCandidateSocketConfiguration() throws Exception {
        CountDownLatch configuring = new CountDownLatch(1), resume = new CountDownLatch(1);
        ControlledSocket socket = new ControlledSocket(false) {
            @Override public void setSoTimeout(int timeout) {
                configuring.countDown();
                try {
                    assertTrue(resume.await(3, TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(e);
                }
            }
        };
        DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> transport = new DirectTcpTransport<>(
                new ControlledFactory(socket, false), 0, HANDLERS);
        FutureTask<IOException> connect = task(() -> assertThrows(IOException.class,
                () -> transport.connect(new InetSocketAddress("127.0.0.1", 445))));
        try {
            assertTrue(configuring.await(3, TimeUnit.SECONDS));
            result(task(() -> { transport.disconnect(); return null; }));
            resume.countDown();
            result(connect);
            assertTrue(socket.closed);
            assertFalse(transport.isConnected());
            assertNull(reader(transport));
        } finally {
            resume.countDown();
            socket.close();
            result(connect);
            transport.disconnect();
        }
    }

    @Test
    void candidateConfigurationFailureClosesItsSocketWithoutPublishingReader() throws Exception {
        ControlledSocket socket = new ControlledSocket(false) {
            @Override public OutputStream getOutputStream() {
                throw new IllegalStateException("socket setup failed");
            }
        };
        DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> transport = new DirectTcpTransport<>(
                new ControlledFactory(socket, false), 0, HANDLERS);
        assertThrows(IllegalStateException.class, () -> transport.connect(new InetSocketAddress("127.0.0.1", 445)));
        assertTrue(socket.closed);
        assertFalse(transport.isConnected());
        assertNull(reader(transport));
    }

    @Test
    void realJdkSocketCloseReleasesStalledTransportWrite() throws Exception {
        try (ServerSocket server = new ServerSocket()) {
            server.setReceiveBufferSize(4096);
            server.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            try (Socket socket = new Socket()) {
                socket.setSendBufferSize(4096);
                socket.setSoLinger(false, 0);
                socket.connect(server.getLocalSocketAddress());
                try (Socket peer = server.accept()) {
                    DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> transport = new DirectTcpTransport<>(
                            new ControlledFactory(socket, false), 0, HANDLERS);
                    transport.connect((InetSocketAddress) server.getLocalSocketAddress());
                    Thread reader = reader(transport);
                    AtomicReference<Thread> writing = new AtomicReference<>();
                    FutureTask<TransportException> writer = task(() -> {
                        writing.set(Thread.currentThread());
                        return assertThrows(TransportException.class, () -> {
                            // The peer never reads: 64 MiB cannot fit in the bounded socket buffers.
                            SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_2_1) {
                                @Override public void write(SMBBuffer buffer) { buffer.putRawBytes(new byte[1048576]); }
                            };
                            for (int i = 0; i < 64; i++) transport.write(packet);
                        });
                    });
                    try {
                        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                        boolean stalled = false;
                        while (System.nanoTime() < deadline && !stalled) {
                            Thread thread = writing.get();
                            if (thread != null) {
                                for (StackTraceElement frame : thread.getStackTrace()) {
                                    if (frame.getClassName().equals("sun.nio.ch.SocketDispatcher") && frame.getMethodName().startsWith("write")) stalled = true;
                                }
                            }
                            if (!stalled) Thread.sleep(1);
                        }
                        assertTrue(stalled, "writer must reach native socket output before abort");
                        System.out.println("LOOPBACK sendBuffer=" + socket.getSendBufferSize() + " receiveBuffer=" + peer.getReceiveBufferSize() + " linger=" + socket.getSoLinger());
                        result(task(() -> { transport.disconnect(); return null; }));
                        assertTrue(socket.isClosed());
                        assertNotNull(result(writer));
                    } finally {
                        socket.close();
                        peer.close();
                        result(writer);
                        transport.disconnect();
                        reader.join(3000);
                        assertFalse(reader.isAlive());
                    }
                }
            }
        }
    }
}
