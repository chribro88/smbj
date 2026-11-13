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
package com.hierynomus.smbj.testing;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageConverter;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.mssmb2.SMB3EncryptedPacketData;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.protocol.Packet;
import com.hierynomus.protocol.PacketData;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.transport.PacketHandlers;
import com.hierynomus.protocol.transport.PacketReceiver;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.PacketEncryptor;
import com.hierynomus.smbj.transport.TransportLayerFactory;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class StubTransportLayerFactory<D extends PacketData<?>, P extends Packet<?>>
        implements TransportLayerFactory<D, P> {
    private PacketProcessor processor;

    public StubTransportLayerFactory(PacketProcessor p) {
        this.processor = p;
    }

    @Override
    public TransportLayer<P> createTransportLayer(PacketHandlers<D, P> handlers,
            SmbConfig config) {
        return new StubTransportLayer<>(handlers.getReceiver(), processor);
    }

    private static class StubTransportLayer<D extends PacketData<?>, P extends Packet<?>> implements TransportLayer<P> {
        private boolean connected;
        private PacketReceiver<D> receiver;
        private PacketProcessor processPacket;
        private SMB2Dialect dialect = SMB2Dialect.SMB_2_1;

        StubTransportLayer(PacketReceiver<D> receiver, PacketProcessor processPacket) {
            this.receiver = receiver;
            if (this.receiver instanceof Connection) {
                ((Connection) this.receiver).setMessageConverter(new StubMessageConverter());
            }

            this.processPacket = processPacket;
        }

        @Override
        public void write(P packet) throws TransportException {
            if (!(packet instanceof SMB2Packet)) {
                throw new TransportException("Unsupported packet type " + packet.getClass().getSimpleName());
            }
            SMB2Packet request = (SMB2Packet) packet;
            SMB2Packet response = processPacket.process(request);

            if (response != null) {
                if (response.getHeader().getMessage() == null) {
                    response.getHeader().setMessageType(request.getHeader().getMessage());
                }
                response.getHeader().setMessageId(request.getHeader().getMessageId());
                response.getHeader().setCreditResponse(request.getHeader().getCreditRequest());
                if (response.getHeader().getSessionId() == 0 && request.getHeader().getSessionId() != 0) {
                    response.getHeader().setSessionId(request.getHeader().getSessionId());
                }
                if (response instanceof SMB2NegotiateResponse) {
                    dialect = ((SMB2NegotiateResponse) response).getDialect();
                }
                if (response instanceof SMB2SessionSetup && response.getHeader().getStatusCode() == 0) {
                    response = authenticationResponse((SMB2SessionSetup) response);
                }
                try {
                    if (response instanceof PacketEncryptor.EncryptedPacketWrapper) {
                        SMBBuffer buffer = new SMBBuffer();
                        response.write(buffer);
                        receiver.handle((D) new SMB3EncryptedPacketData(buffer.getCompactData()));
                    } else {
                        receiver.handle((D) new StubPacketData(response));
                    }
                } catch (BufferException e) {
                    throw new TransportException(e);
                }
            } else {
                throw new TransportException("No response for " + packet);
            }
        }

        private SMB2SessionSetup authenticationResponse(SMB2SessionSetup response) throws TransportException {
            long flags = EnumWithValue.EnumUtils.toLong(response.getSessionFlags());
            if ((flags & 3) != 0) return response;
            if (dialect == SMB2Dialect.SMB_3_1_1) {
                throw new TransportException("The synthetic transport has no SMB 3.1.1 preauthentication transcript");
            }
            try {
                byte[] key = ByteArrayUtils.parseHex("09921d4431b171b977370bf8910900f9");
                Mac hmac = Mac.getInstance("HmacSHA256");
                if (dialect.isSmb3x()) {
                    byte[] context = "SMB2AESCMAC\0\0SmbSign\0".getBytes(StandardCharsets.US_ASCII);
                    byte[] input = ByteBuffer.allocate(context.length + 8).putInt(1).put(context).putInt(128).array();
                    hmac.init(new SecretKeySpec(key, "HmacSHA256"));
                    key = Arrays.copyOf(hmac.doFinal(input), 16);
                }
                byte[] token = response.getSecurityBuffer();
                byte[] wire = new byte[72 + token.length];
                ByteBuffer fields = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
                fields.putInt(0x424d53fe).putShort((short) 64).putShort((short) 1).putInt(0)
                        .putShort((short) 1).putShort((short) response.getHeader().getCreditResponse()).putInt(9).putInt(0)
                        .putLong(response.getHeader().getMessageId()).putInt(0).putInt(0)
                        .putLong(response.getHeader().getSessionId()).put(new byte[16]);
                fields.putShort((short) 9).putShort((short) flags).putShort((short) 72).putShort((short) token.length).put(token);
                byte[] signature;
                if (dialect.isSmb3x()) {
                    CMac cmac = new CMac(AESEngine.newInstance());
                    cmac.init(new KeyParameter(key));
                    cmac.update(wire, 0, wire.length);
                    signature = new byte[16];
                    cmac.doFinal(signature, 0);
                } else {
                    hmac.init(new SecretKeySpec(key, "HmacSHA256"));
                    signature = hmac.doFinal(wire);
                }
                System.arraycopy(signature, 0, wire, 48, 16);
                return (SMB2SessionSetup) new SMB2MessageConverter().readPacket(null, new SMB2PacketData(wire));
            } catch (GeneralSecurityException | BufferException failure) {
                throw new TransportException("Cannot sign the synthetic authentication response", failure);
            }
        }

        @Override
        public void connect(InetSocketAddress remoteAddress) throws IOException {
            connected = true;
        }

        @Override
        public void disconnect() throws IOException {
            connected = false;
        }

        @Override
        public boolean isConnected() {
            return connected;
        }
    }

    private static class StubPacketData extends SMB2PacketData {
        private SMB2Packet packet;

        StubPacketData(SMB2Packet packet) throws BufferException {
            super(new byte[0]);
            this.packet = packet;
        }

        @Override
        public SMB2PacketHeader getHeader() {
            return packet.getHeader();
        }

        @Override
        protected void readHeader() throws BufferException {
        }
    }

    private static class StubMessageConverter extends SMB2MessageConverter {
        private SMB2MessageConverter realConverter = new SMB2MessageConverter();

        @Override
        public SMB2Packet readPacket(SMBPacket requestPacket, SMB2PacketData packetData) throws BufferException {
            if (packetData instanceof StubPacketData) {
                return ((StubPacketData) packetData).packet;
            } else {
                return realConverter.readPacket(requestPacket, packetData);
            }
        }
    }
}
