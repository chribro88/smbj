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

import com.hierynomus.security.AEADBlockCipher;
import com.hierynomus.security.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import static com.hierynomus.mssmb2.SMB2MessageFlag.SMB2_FLAGS_SIGNED;
import static com.hierynomus.mssmb2.SMB2PacketHeader.EMPTY_SIGNATURE;
import static com.hierynomus.mssmb2.SMB2PacketHeader.SIGNATURE_OFFSET;
import static com.hierynomus.mssmb2.SMB2PacketHeader.SIGNATURE_SIZE;
import static com.hierynomus.mssmb2.SMB2PacketHeader.STRUCTURE_SIZE;

import java.security.MessageDigest;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.security.Mac;
import com.hierynomus.security.SecurityException;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smb.SMBBuffer;

public class PacketSignatory implements Signatory {
    private static final Logger logger = LoggerFactory.getLogger(PacketSignatory.class);

    private SecurityProvider securityProvider;

    PacketSignatory(SecurityProvider securityProvider) {
        this.securityProvider = securityProvider;
    }

    @Override
    public SMB2Packet sign(SMB2Packet packet, SecretKey secretKey) {
        if (secretKey != null) {
            return new SignedPacketWrapper(packet, secretKey);
        } else {
            logger.debug("Not wrapping {} as signed, as no key is set.", packet.getHeader().getMessage());
            return packet;
        }
    }

    // TODO make session a packet handler which wraps the incoming packets
    @Override
    public boolean verify(SMB2PacketData packet, SecretKey secretKey) {
        try {
            SMBBuffer buffer = packet.getDataBuffer();
            SMB2PacketHeader header = packet.getHeader();
            if (!header.isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR)
                    || !header.isFlagSet(SMB2_FLAGS_SIGNED)
                    || !validExtent(buffer, header)) {
                return false;
            }
            Mac mac = getMac(secretKey, packet.getHeader(), securityProvider);
            int headerStart = packet.getHeader().getHeaderStartPosition();
            int bodyStart = headerStart + STRUCTURE_SIZE;
            mac.update(buffer.array(), headerStart, SIGNATURE_OFFSET);
            mac.update(EMPTY_SIGNATURE);
            mac.update(buffer.array(), bodyStart, packet.getHeader().getMessageEndPosition() - bodyStart);
            byte[] signature = signature(mac, secretKey);
            byte[] receivedSignature = packet.getHeader().getSignature();
            return MessageDigest.isEqual(java.util.Arrays.copyOf(signature, SIGNATURE_SIZE), receivedSignature);
        } catch (SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] signature(Mac mac, SecretKey key) {
        byte[] signature = mac.doFinal();
        if (signature.length < SIGNATURE_SIZE
                || ("AES-GMAC".equals(key.getAlgorithm()) && signature.length != SIGNATURE_SIZE)) {
            throw new IllegalStateException("Invalid signing tag length: " + signature.length);
        }
        return signature;
    }

    private static boolean validExtent(SMBBuffer buffer, SMB2PacketHeader header) {
        int start = header.getHeaderStartPosition();
        int end = header.getMessageEndPosition();
        int next = header.getNextCommandOffset();
        return start >= 0 && end >= start && end - start >= STRUCTURE_SIZE && end <= buffer.wpos()
                && buffer.array()[start + 4] == STRUCTURE_SIZE && buffer.array()[start + 5] == 0
                && (next == 0 || (next == end - start && (next & 7) == 0));
    }

    private static Mac getMac(SecretKey secretKey, SMB2PacketHeader header, SecurityProvider securityProvider) throws SecurityException {
        Mac mac = "AES-GMAC".equals(secretKey.getAlgorithm()) ? new Gmac(securityProvider, header)
                : securityProvider.getMac(secretKey.getAlgorithm());
        mac.init(secretKey.getEncoded());
        return mac;
    }

    /** GMAC authenticates the wire packet as AAD; its nonce is mandated by MS-SMB2 3.1.4.1. */
    private static final class Gmac implements Mac {
        private final AEADBlockCipher cipher;
        private final byte[] nonce = new byte[12];
        private final byte[] singleByte = new byte[1];

        Gmac(SecurityProvider provider, SMB2PacketHeader header) throws SecurityException {
            cipher = provider.getAEADBlockCipher("AES/GCM/NoPadding");
            long messageId = header.getMessageId();
            for (int i = 0; i < 8; i++) nonce[i] = (byte) (messageId >>> (8 * i));
            if (header.isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR)) nonce[8] |= 1;
            if (header.getMessage() == SMB2MessageCommandCode.SMB2_CANCEL) nonce[8] |= 2;
        }

        public void init(byte[] key) throws SecurityException {
            if (key.length != 16) {
                throw new IllegalArgumentException("SMB AES-128-GMAC requires a 16-byte signing key");
            }
            cipher.init(Cipher.CryptMode.ENCRYPT, key, new GCMParameterSpec(128, nonce));
        }
        public void update(byte value) { singleByte[0] = value; update(singleByte); }
        public void update(byte[] bytes) { update(bytes, 0, bytes.length); }
        public void update(byte[] bytes, int offset, int length) {
            try { cipher.updateAAD(bytes, offset, length); }
            catch (SecurityException e) { throw new IllegalStateException(e); }
        }
        public byte[] doFinal() {
            try { return cipher.doFinal(EMPTY_SIGNATURE, 0, 0); }
            catch (SecurityException e) { throw new IllegalStateException(e); }
        }
        public void reset() { cipher.reset(); }
    }

    public class SignedPacketWrapper extends SMB2Packet {
        private final SMB2Packet wrappedPacket;
        private SecretKey secretKey;
        private SMBBuffer serializedBuffer;

        SignedPacketWrapper(SMB2Packet packet, SecretKey secretKey) {
            this.wrappedPacket = packet;
            this.secretKey = secretKey;
        }

        @Override
        public int getMaxPayloadSize() {
            return wrappedPacket.getMaxPayloadSize();
        }

        @Override
        public void write(SMBBuffer buffer) {
            serializedBuffer = buffer;
            try {
                SMB2PacketHeader header = wrappedPacket.getHeader();
                if (header.isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR)) {
                    throw new IllegalArgumentException("Cannot send a server response on a client connection");
                }
                header.setFlag(SMB2_FLAGS_SIGNED);
                int packetStartPos = buffer.wpos();
                wrappedPacket.write(buffer);
                header.setMessageEndPosition(buffer.wpos());
                if (!validExtent(buffer, header)) {
                    throw new IllegalArgumentException("Invalid SMB message extent for signing");
                }
                Mac mac = getMac(secretKey, header, securityProvider);
                mac.update(buffer.array(), packetStartPos, SIGNATURE_OFFSET);
                mac.update(EMPTY_SIGNATURE);
                mac.update(buffer.array(), packetStartPos + STRUCTURE_SIZE,
                        buffer.wpos() - packetStartPos - STRUCTURE_SIZE);
                byte[] signature = signature(mac, secretKey);
                System.arraycopy(signature, 0, buffer.array(), packetStartPos + SIGNATURE_OFFSET, SIGNATURE_SIZE);
            } catch (SecurityException e) {
                // TODO other exception
                throw new IllegalStateException(e);
            }
        }

        // CUSTOM ADDED: preauthentication hashes must cover the actual signed wire bytes.
        @Override
        public SMBBuffer getBuffer() {
            return serializedBuffer;
        }

        @Override
        public SMB2PacketHeader getHeader() {
            return wrappedPacket.getHeader();
        }

        @Override
        public long getSequenceNumber() {
            return wrappedPacket.getSequenceNumber();
        }

        @Override
        public int getStructureSize() {
            return wrappedPacket.getStructureSize();
        }

        @Override
        public String toString() {
            return "Signed(" + wrappedPacket.toString() + ")";
        }

        /**
         * Return the result of the {@link #getPacket()} call on the wrapped packet.
         * @return The unwrapped wrapppedPacket
         */
        @Override
        public SMB2Packet getPacket() {
            return wrappedPacket.getPacket();
        }
    }
}
