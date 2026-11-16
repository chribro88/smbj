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

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.protocol.commons.concurrent.AFuture;
import com.hierynomus.protocol.commons.concurrent.CancellableFuture;
import com.hierynomus.protocol.commons.concurrent.Promise;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.common.SMBRuntimeException;

import java.util.Date;
import java.util.UUID;

public class Request {

    private final Promise<SMB2Packet, SMBRuntimeException> promise;
    private SMBPacket<?, ?> packet;
    private final SMBPacket<?, ?> wirePacket;
    private final int creditsAssigned;
    private final long messageId;
    private final UUID cancelId;
    private final SMB2MessageCommandCode command;
    private final long sessionId;
    private final boolean encrypted;
    private final boolean signingRequired;
    private final Date timestamp;
    private volatile long asyncId;
    private final java.util.concurrent.atomic.AtomicReference<CancellableFuture.CancelCallback> cancellation;
    private final java.util.concurrent.atomic.AtomicBoolean cancelled;
    private volatile boolean retrying;
    private long authenticationGeneration;

    public Request(SMBPacket<?, ?> packet, long messageId, UUID cancelId) {
        this(packet, messageId, cancelId, false);
    }

    Request(SMBPacket<?, ?> packet, long messageId, UUID cancelId, boolean signingRequired) {
        this(packet, messageId, cancelId, signingRequired, null);
    }

    Request(SMBPacket<?, ?> packet, long messageId, UUID cancelId, boolean signingRequired, Request previous) {
        this.packet = packet instanceof SMB2Packet ? ((SMB2Packet) packet).getPacket() : packet;
        this.wirePacket = packet;
        this.creditsAssigned = packet instanceof SMB2Packet ? ((SMB2Packet) packet).getCreditsAssigned() : 1;
        this.encrypted = packet instanceof PacketEncryptor.EncryptedPacketWrapper;
        this.signingRequired = signingRequired;
        this.messageId = messageId;
        this.cancelId = cancelId;
        if (packet.getHeader() instanceof SMB2PacketHeader) {
            SMB2PacketHeader header = (SMB2PacketHeader) packet.getHeader();
            this.command = header.getMessage();
            this.sessionId = header.getSessionId();
        } else {
            // An SMB1 multi-protocol negotiate request receives an SMB2 NEGOTIATE response.
            this.command = SMB2MessageCommandCode.SMB2_NEGOTIATE;
            this.sessionId = 0;
        }
        timestamp = previous == null ? new Date() : previous.timestamp;
        this.promise = previous == null ? new Promise<>(String.valueOf(messageId), SMBRuntimeException.Wrapper) : previous.promise;
        this.cancellation = previous == null ? new java.util.concurrent.atomic.AtomicReference<>() : previous.cancellation;
        this.cancelled = previous == null ? new java.util.concurrent.atomic.AtomicBoolean() : previous.cancelled;
    }

    int getCreditsAssigned() {
        return creditsAssigned;
    }

    public SMB2Packet getRetryPacket() {
        final SMB2Packet original = (SMB2Packet) packet;
        com.hierynomus.smb.SMBBuffer sent = encrypted ? original.getBuffer() : wirePacket.getBuffer();
        if (sent == null) {
            return original; // A transport can fail before serializing a durable CREATE.
        }
        final byte[] body = java.util.Arrays.copyOfRange(sent.array(), SMB2PacketHeader.STRUCTURE_SIZE, sent.wpos());
        return new SMB2Packet() {
            { this.header = original.getHeader(); }

            @Override
            protected void writeTo(com.hierynomus.smb.SMBBuffer buffer) {
                buffer.putRawBytes(body);
            }

            @Override
            public int getMaxPayloadSize() {
                return original.getMaxPayloadSize();
            }

            @Override
            public SMB2Packet getPacket() {
                return original;
            }
        };
    }

    public boolean isCancelled() {
        return cancelled.get();
    }

    public void markRetrying() {
        retrying = true;
    }

    boolean isRetrying() {
        return retrying;
    }

    public long getAuthenticationGeneration() {
        return authenticationGeneration;
    }

    void setAuthenticationGeneration(long generation) {
        authenticationGeneration = generation;
    }

    public long getAsyncId() {
        return asyncId;
    }

    /**
     * Returns the command captured when this request was registered for sending.
     * @return the request command
     */
    public SMB2MessageCommandCode getCommand() {
        return command;
    }

    /**
     * Returns the session ID captured when this request was registered for sending.
     * @return the request session ID
     */
    public long getSessionId() {
        return sessionId;
    }

    /**
     * Returns whether this request was registered for sending inside an SMB2 TRANSFORM frame.
     * @return true if the request was sent encrypted
     */
    public boolean isEncrypted() {
        return encrypted;
    }

    /**
     * Returns whether the request's session required signing when it was registered for sending.
     * @return true if the session required signing
     */
    public boolean isSigningRequired() {
        return signingRequired;
    }

    public void setAsyncId(long asyncId) {
        this.asyncId = asyncId;
    }

    public void complete(SMB2Packet response) {
        promise.lock();
        try {
            if (!promise.isFulfilled()) {
                promise.deliver(response);
            }
        } finally {
            promise.unlock();
        }
    }

    public void fail(Throwable failure) {
        promise.lock();
        try {
            if (!promise.isFulfilled()) {
                promise.deliverError(failure);
            }
        } finally {
            promise.unlock();
        }
    }

    public Promise<SMB2Packet, SMBRuntimeException> getPromise() {
        return promise;
    }

    long getMessageId() {
        return messageId;
    }

    @SuppressWarnings("unchecked")
    <T extends SMB2Packet> AFuture<T> getFuture(final CancellableFuture.CancelCallback callback) {
        cancellation.set(callback);
        return (AFuture<T>) new CancellableFuture<>(promise.future(), () -> {
            synchronized (packet) {
                cancelled.set(true);
                cancellation.get().cancel();
            }
        });

    }

    UUID getCancelId() {
        return cancelId;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public SMBPacket<?, ?> getPacket() {
        return packet;
    }
}
