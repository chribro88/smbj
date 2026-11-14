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
package com.hierynomus.smbj.share;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.smbj.ProgressListener;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.io.ByteChunkProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import com.hierynomus.smb.SMBBuffer;

/**
 * Generic class that allows to write data to a share entry (Be it a printer or
 * a file)
 */
public class SMB2Writer {
    private static final Logger logger = LoggerFactory.getLogger(SMB2Writer.class);
    private static final int ASYNC_WINDOW_BYTES = 4 * 1024 * 1024;
    private static final int MAX_PENDING_WRITES = 64;

    private Share share;
    private SMB2FileId fileId;
    private String entryName;
    private final Set<FutureTask<Long>> pending = ConcurrentHashMap.newKeySet();
    private boolean closing;

    public SMB2Writer(Share share, SMB2FileId fileId, String entryName) {
        this.share = share;
        this.fileId = fileId;
        this.entryName = entryName;
    }

    /**
     * Write the data in buffer to this file at position fileOffset.
     *
     * @param buffer     the data to write
     * @param fileOffset The offset, in bytes, into the file to which the data
     *                   should be written
     * @return the actual number of bytes that was written to the file
     */
    public long write(byte[] buffer, long fileOffset) {
        return write(buffer, fileOffset, 0, buffer.length);
    }

    /**
     * Write the data in buffer to this file at position fileOffset.
     *
     * @param buffer     the data to write
     * @param fileOffset The offset, in bytes, into the file to which the data
     *                   should be written
     * @param offset     the start offset in the data
     * @param length     the number of bytes that are written
     * @return the actual number of bytes that was written to the file
     */
    public long write(byte[] buffer, long fileOffset, int offset, int length) {
        return write(new ArrayByteChunkProvider(buffer, offset, length, fileOffset), null);
    }

    /**
     * Write all available data from the byte chunk provider to this file. The
     * offset in the file to which data is written is determined by
     * {@link ByteChunkProvider#getOffset()}.
     *
     * @param provider the byte chunk provider
     * @return the actual number of bytes that was written to the file
     */
    public long write(ByteChunkProvider provider) {
        return write(provider, null);
    }

    /**
     * Write all available data from the byte chunk provider to this file. The
     * offset in the file to which data is written is determined by
     * {@link ByteChunkProvider#getOffset()}.
     *
     * @param provider         the byte chunk provider
     * @param progressListener an optional callback that will be invoked when data
     *                         has been written to the file
     * @return the actual number of bytes that was written to the file
     */
    public long write(ByteChunkProvider provider, ProgressListener progressListener) {
        long bytesWritten = 0;
        while (provider.isAvailable()) {
            WriteChunk chunk = new WriteChunk(provider, share.getWriteBufferSize());
            while (chunk.remaining() > 0) {
                ArrayByteChunkProvider tail = chunk.tail();
                SMB2WriteResponse response = share.write(fileId, tail);
                int count = chunk.acknowledge(response, tail.getLastWriteSize());
                bytesWritten = Math.addExact(bytesWritten, count);
                if (progressListener != null) {
                    progressListener.onProgressChanged(count, Math.addExact(chunk.fileOffset, chunk.acknowledged));
                }
            }
        }
        return bytesWritten;
    }

    /***
     * Write the data Async in buffer to this file at position fileOffset.
     *
     * @param buffer     the data to write
     * @param fileOffset The offset, in bytes, into the file to which the data
     *                   should be written
     * @param offset     the start offset in the data
     * @param length     the number of bytes that are written
     * @return A Future containing the total number of bytes written
     */
    public Future<Long> writeAsync(byte[] buffer, long fileOffset, int offset, int length) {
        return writeAsync(new ArrayByteChunkProvider(buffer, offset, length, fileOffset));
    }

    /**
     * Async Write all available data from the byte chunk provider to this file. The
     * offset in the file to which data is written is determined by
     * {@link ByteChunkProvider#getOffset()}.
     *
     * The provider is read on the calling thread; no reads occur after this method
     * returns. A full pipeline applies backpressure. At most four writes execute per session, with
     * 64 queued operations. Each operation
     * retains up to 4 MiB of chunks, at most 64 requests.
     *
     * @param provider the byte chunk provider
     * @return a future containing the acknowledged total
     */
    public Future<Long> writeAsync(ByteChunkProvider provider) {
        java.util.Objects.requireNonNull(provider, "provider");
        AsyncWrite operation = new AsyncWrite();
        FutureTask<Long> result = new FutureTask<Long>(operation) {
            @Override public boolean cancel(boolean interrupt) {
                if (!super.cancel(interrupt)) return false;
                operation.cancelPending();
                return true;
            }
            @Override protected void done() {
                if (isCancelled()) {
                    operation.cancelled.set(true);
                    operation.signalProducer();
                }
                pending.remove(this);
            }
        };
        synchronized (pending) {
            if (closing) throw new SMBRuntimeException("File writer is closing or closed");
            pending.add(result);
        }
        try {
            share.executeAsyncWrite(result);
            operation.produce(provider);
            return result;
        } catch (RuntimeException | Error failure) {
            result.cancel(false);
            throw failure;
        }
    }

    private List<FutureTask<Long>> closingWrites() {
        synchronized (pending) {
            closing = true;
            return new ArrayList<>(pending);
        }
    }

    void finishAsyncWrites() {
        List<FutureTask<Long>> writes = closingWrites();
        SMBRuntimeException failure = null;
        for (FutureTask<Long> write : writes) {
            try {
                write.get();
            } catch (CancellationException cancelled) {
                // A cancelled write has no successful byte count to flush.
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                for (FutureTask<Long> outstanding : writes) outstanding.cancel(false);
                throw new SMBRuntimeException(interrupted);
            } catch (ExecutionException failed) {
                if (failure == null) failure = new SMBRuntimeException(failed.getCause());
                else failure.addSuppressed(failed.getCause());
            }
        }
        if (failure != null) throw failure;
    }

    void cancelAsyncWrites() {
        for (FutureTask<Long> write : closingWrites()) write.cancel(false);
    }

    private final class WriteChunk {
        private final byte[] bytes;
        private final long fileOffset;
        private int acknowledged;
        private int submitted;
        private Future<SMB2WriteResponse> response;

        WriteChunk(ByteChunkProvider provider, int limit) {
            if (limit <= 0) throw new SMBRuntimeException("Invalid WRITE buffer limit");
            limit = Math.min(limit, ASYNC_WINDOW_BYTES);
            provider.prepareWrite(limit);
            int length = Math.min(limit, provider.bytesLeft());
            if (length <= 0) throw new SMBRuntimeException("WRITE provider made no progress");
            fileOffset = provider.getOffset();
            if (fileOffset < 0) throw new IllegalArgumentException("Negative WRITE file offset");
            Math.addExact(fileOffset, length);
            SMBBuffer snapshot = new SMBBuffer();
            provider.writeBytes(snapshot, length);
            bytes = snapshot.getCompactData();
        }

        int remaining() { return bytes.length - acknowledged; }
        ArrayByteChunkProvider tail() {
            return new ArrayByteChunkProvider(bytes, acknowledged, remaining(), Math.addExact(fileOffset, acknowledged));
        }
        int acknowledge(SMB2WriteResponse response, int submitted) {
            int count = response.getBytesWritten();
            if (count <= 0 || submitted <= 0 || submitted > remaining() || count > submitted) {
                throw new SMBRuntimeException("Invalid SMB WRITE acknowledgement count: " + count);
            }
            acknowledged += count;
            return count;
        }
    }

    private final class AsyncWrite implements Callable<Long> {
        private final int limit = Math.min(share.getWriteBufferSize(), ASYNC_WINDOW_BYTES);
        private final int window = limit > 0 ? Math.max(1, Math.min(MAX_PENDING_WRITES, ASYNC_WINDOW_BYTES / limit)) : 1;
        private final Semaphore slots = new Semaphore(window);
        private final CountDownLatch started = new CountDownLatch(1);
        private final Deque<WriteChunk> input = new ArrayDeque<>();
        private boolean produced;
        private volatile Throwable failure;
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final Set<Future<SMB2WriteResponse>> active = ConcurrentHashMap.newKeySet();

        void produce(ByteChunkProvider provider) {
            try {
                started.await();
                while (true) {
                    checkCancelled();
                    if (!provider.isAvailable()) break;
                    slots.acquire();
                    try {
                        checkCancelled();
                        WriteChunk chunk = new WriteChunk(provider, limit);
                        synchronized (input) {
                            checkCancelled();
                            input.addLast(chunk);
                            input.notifyAll();
                        }
                    } catch (RuntimeException | Error failed) {
                        slots.release();
                        throw failed;
                    }
                }
                synchronized (input) {
                    produced = true;
                    input.notifyAll();
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new SMBRuntimeException(interrupted);
            } catch (RuntimeException | Error failed) {
                if (failed != failure && !(failed instanceof CancellationException && cancelled.get())) throw failed;
            }
        }

        // A null result means the producer has finished and its input queue is empty.
        private WriteChunk takeInput() {
            synchronized (input) {
                try {
                    while (input.isEmpty() && !produced) {
                        checkCancelled();
                        input.wait();
                    }
                    checkCancelled();
                    return input.pollFirst();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new SMBRuntimeException(interrupted);
                }
            }
        }

        @Override public Long call() {
            started.countDown();
            try {
                if (limit <= 0) throw new SMBRuntimeException("Invalid WRITE buffer limit");
                Deque<WriteChunk> pending = new ArrayDeque<>();
                boolean end = false;
                long total = 0;
                while (!end || !pending.isEmpty()) {
                    checkCancelled();
                    while (!end && pending.size() < window) {
                        if (!pending.isEmpty() && pending.peekFirst().response.isDone()) {
                            synchronized (input) {
                                if (input.isEmpty()) break;
                            }
                        }
                        WriteChunk chunk = takeInput();
                        if (chunk == null) end = true;
                        else {
                            submit(chunk);
                            pending.addLast(chunk);
                        }
                    }
                    if (pending.isEmpty()) break;
                    WriteChunk chunk = pending.removeFirst();
                    while (chunk.remaining() > 0) {
                        checkCancelled();
                        SMB2WriteResponse response;
                        try {
                            response = share.receiveWrite(fileId, chunk.response);
                        } finally {
                            active.remove(chunk.response);
                        }
                        checkCancelled();
                        total = Math.addExact(total, chunk.acknowledge(response, chunk.submitted));
                        if (chunk.remaining() > 0) submit(chunk);
                    }
                    slots.release();
                }
                return total;
            } catch (RuntimeException | Error failed) {
                failure = failed;
                throw failed;
            } finally {
                if (failure != null) cancelled.set(true);
                signalProducer();
                cancelPending();
                active.clear();
                synchronized (input) { input.clear(); }
            }
        }

        private void submit(WriteChunk chunk) {
            checkCancelled();
            ArrayByteChunkProvider tail = chunk.tail();
            logger.debug("Sending async write request to {} from offset {}", entryName, tail.getOffset());
            chunk.response = share.writeAsync(fileId, tail);
            active.add(chunk.response);
            chunk.submitted = tail.getLastWriteSize();
            if (cancelled.get()) chunk.response.cancel(false);
            checkCancelled();
        }

        private void checkCancelled() {
            Throwable failed = failure;
            if (failed instanceof RuntimeException) throw (RuntimeException) failed;
            if (failed instanceof Error) throw (Error) failed;
            if (cancelled.get() || Thread.currentThread().isInterrupted()) {
                throw new CancellationException("WRITE cancelled");
            }
        }

        private void signalProducer() {
            started.countDown();
            slots.release(window);
            synchronized (input) { input.notifyAll(); }
        }

        private void cancelPending() {
            signalProducer();
            for (Future<SMB2WriteResponse> response : active) {
                try {
                    response.cancel(false);
                } catch (RuntimeException failure) {
                    logger.debug("Could not cancel pending WRITE", failure);
                }
            }
        }
    }

    public OutputStream getOutputStream() {
        return getOutputStream(null, 0);
    }

    public OutputStream getOutputStream(ProgressListener listener, long offset) {
        return new FileOutputStream(this, share.getWriteBufferSize(), offset, listener);
    }
}
