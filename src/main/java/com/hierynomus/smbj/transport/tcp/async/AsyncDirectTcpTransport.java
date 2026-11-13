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

import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.PacketReceiver;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.Queue;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A transport layer over Direct TCP/IP that uses asynchronous I/O.
 */
public class AsyncDirectTcpTransport<D extends PacketData<?>, P extends Packet<?>> implements TransportLayer<P> {
    private static final int DEFAULT_CONNECT_TIMEOUT = 5000;
    private static final int DIRECT_HEADER_SIZE = 4;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final PacketHandlers<D, P> handlers;
    private final AsynchronousSocketChannel socketChannel;
    private final AsyncPacketReader<D> packetReader;
    private final AtomicBoolean connected;
    private final AtomicBoolean closed = new AtomicBoolean();
    private int soTimeout = 0;

    // AsynchronousSocketChannel doesn't support concurrent writes, so queue pending writes for later
    private final Queue<ByteBuffer> writeQueue;
    private AtomicBoolean writingNow;

    public AsyncDirectTcpTransport(int soTimeout, PacketHandlers<D, P> handlers, AsynchronousChannelGroup group)
        throws IOException {
        this(soTimeout, handlers, AsynchronousSocketChannel.open(group));
    }

    AsyncDirectTcpTransport(int soTimeout, PacketHandlers<D, P> handlers, AsynchronousSocketChannel channel) {
        this.soTimeout = soTimeout;
        this.handlers = handlers;
        this.socketChannel = channel;
        this.packetReader = new AsyncPacketReader<>(this.socketChannel, handlers.getPacketFactory(), new PacketReceiver<D>() {
            @Override
            public void handle(D packet) throws TransportException {
                handlers.getReceiver().handle(packet);
            }

            @Override
            public void handleError(Throwable failure) {
                fail(failure);
            }
        });
        this.writeQueue = new LinkedBlockingQueue<>();
        this.connected = new AtomicBoolean(false);
        this.writingNow = new AtomicBoolean(false);
    }

    @Override
    public void write(P packet) throws TransportException {
        if (!isConnected()) {
            throw new TransportException("Transport is not connected");
        }
        ByteBuffer bufferToSend = prepareBufferToSend(packet); // Serialize first, as it might throw
        logger.trace("Sending packet << {} >>", packet);
        try {
            writeOrEnqueue(bufferToSend);
        } catch (RuntimeException failure) {
            fail(failure);
            throw TransportException.Wrapper.wrap(failure);
        }
    }

    private void writeOrEnqueue(ByteBuffer buffer) throws TransportException {
        boolean start;
        synchronized (this) {
            if (!isConnected()) {
                throw new TransportException("Transport disconnected before write admission");
            }
            writeQueue.add(buffer);
            start = !writingNow.getAndSet(true);
        }
        if (start) startAsyncWrite();
    }

    @Override
    public void connect(InetSocketAddress remoteAddress) throws IOException {
        if (closed.get()) {
            throw new TransportException("Transport is closed");
        }
        String remoteHostname = remoteAddress.getHostString();
        try {
            Future<Void> connectFuture = socketChannel.connect(remoteAddress);
            connectFuture.get(DEFAULT_CONNECT_TIMEOUT, TimeUnit.MILLISECONDS);
            connected.set(true);
            if (closed.get()) {
                connected.set(false);
                throw new TransportException("Transport disconnected while connecting");
            }
            packetReader.start(remoteHostname, this.soTimeout);
        } catch (ExecutionException | TimeoutException e) {
            closeAfterConnectFailure(e);
            throw TransportException.Wrapper.wrap(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            closeAfterConnectFailure(e);
            throw TransportException.Wrapper.wrap(e);
        } catch (IOException | RuntimeException e) {
            closeAfterConnectFailure(e);
            throw e;
        }
    }

    private void closeAfterConnectFailure(Exception failure) {
        try {
            disconnect();
        } catch (IOException cleanupFailure) {
            failure.addSuppressed(cleanupFailure);
        }
    }

    @Override
    public void disconnect() throws IOException {
        // Mark disconnected first
        closed.set(true);
        connected.set(false);
        packetReader.stop();
        try {
            socketChannel.close();
        } finally {
            synchronized (this) {
                writeQueue.clear();
                writingNow.set(false);
            }
        }
    }

    @Override
    public boolean isConnected() {
        return connected.get() && !closed.get() && socketChannel.isOpen();
    }

    private void fail(Throwable failure) {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        try {
            disconnect();
        } catch (IOException closeFailure) {
            if (failure != closeFailure) {
                failure.addSuppressed(closeFailure);
            }
        } finally {
            handlers.getReceiver().handleError(failure);
        }
    }

    public void setSoTimeout(int soTimeout) {
        this.soTimeout = soTimeout;
    }

    private void startAsyncWrite() {
        if (!isConnected()) {
            return;
        }
        ByteBuffer toSend = writeQueue.peek();
        if (toSend == null) return;
        socketChannel.write(toSend, soTimeout, TimeUnit.MILLISECONDS, null, new CompletionHandler<Integer, Object>() {

            @Override
            public void completed(Integer result, Object attachment) {
                logger.trace("Written {} bytes to async transport", result);
                try {
                    startNextWriteIfWaiting();
                } catch (RuntimeException failure) {
                    fail(failure);
                }
            }

            @Override
            public void failed(Throwable exc, Object attachment) {
                fail(exc);
            }

            private void startNextWriteIfWaiting() {
                boolean next;
                synchronized (AsyncDirectTcpTransport.this) {
                    if (!isConnected()) {
                        return;
                    }
                    ByteBuffer head = writeQueue.peek();
                    if (head != null && !head.hasRemaining()) {
                        writeQueue.remove();
                    }
                    next = !writeQueue.isEmpty();
                    if (!next) writingNow.set(false);
                }
                if (next) startAsyncWrite();
            }
        });
    }

    private ByteBuffer prepareBufferToSend(P packet) {
        Buffer<?> packetData = handlers.getSerializer().write(packet);
        int dataSize = packetData.available();
        ByteBuffer toSend = ByteBuffer.allocate(dataSize + DIRECT_HEADER_SIZE);
        toSend.order(ByteOrder.BIG_ENDIAN);
        toSend.putInt(packetData.available()); // also writes the initial 0 byte
        toSend.put(packetData.array(), packetData.rpos(), packetData.available());
        ((java.nio.Buffer) toSend).flip(); // Java8/9 compatibility
        try {
            packetData.skip(dataSize);
        } catch (BufferException e) {
            throw SMBRuntimeException.Wrapper.wrap(e); // should never happen
        }
        return toSend;
    }

}
