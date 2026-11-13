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
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ResponseAuthenticationTest {
    @ParameterizedTest
    @ValueSource(longs = {0, 47, 48, 999})
    void unsignedReplyCannotChangeItsSessionToBypassRequiredSigning(long responseSession) throws Exception {
        try (Fixture f = new Fixture(true)) {
            f.connection.handle(new SMB2PacketData(response(responseSession, null)));
            f.assertRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {0, 47, 48, 999})
    void signedReplyUsesRequestSessionKeyDespiteResponseSession(long responseSession) throws Exception {
        try (Fixture f = new Fixture(true)) {
            f.connection.handle(new SMB2PacketData(response(responseSession, new byte[16])));
            assertTrue(f.request.getPromise().isFulfilled());
            assertEquals(8, f.connection.sequenceWindow.available());
        }
    }

    @Test
    void anotherSessionsValidSignatureCannotCompleteRequest() throws Exception {
        try (Fixture f = new Fixture(true)) {
            byte[] otherKey = new byte[16]; otherKey[0] = 1;
            f.connection.handle(new SMB2PacketData(response(48, otherKey)));
            f.assertRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {0, 47, 48, 999})
    void optionalSigningStillAllowsUnsignedReply(long responseSession) throws Exception {
        try (Fixture f = new Fixture(false)) {
            f.connection.handle(new SMB2PacketData(response(responseSession, null)));
            assertTrue(f.request.getPromise().isFulfilled());
            assertEquals(8, f.connection.sequenceWindow.available());
        }
    }

    @Test
    void optionalSigningStillRejectsAnInvalidSignature() throws Exception {
        try (Fixture f = new Fixture(false)) {
            byte[] wire = response(0, new byte[16]); wire[48] ^= 1;
            f.connection.handle(new SMB2PacketData(wire));
            f.assertRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {0, 48, 999})
    void signedErrorReplyUsesRequestSessionKey(long responseSession) throws Exception {
        try (Fixture f = new Fixture(true)) {
            f.connection.handle(new SMB2PacketData(response(responseSession, new byte[16], 0xc0000022)));
            assertTrue(f.request.getPromise().isFulfilled());
            assertEquals(0xc0000022L, f.request.getPromise().future().get().getHeader().getStatusCode());
            assertEquals(8, f.connection.sequenceWindow.available());
        }
    }

    @Test
    void unsignedReplyForUnknownRequestSessionIsRejected() throws Exception {
        try (Fixture f = new Fixture(false)) {
            ((SMB2Echo) f.request.getPacket()).getHeader().setSessionId(999);
            f.connection.handle(new SMB2PacketData(response(48, null)));
            f.assertRejected();
        }
    }

    @Test
    void unsignedInterimReplyRemainsPermitted() throws Exception {
        try (Fixture f = new Fixture(true)) {
            byte[] wire = response(0, null);
            ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
            header.putInt(8, 0x103); header.putInt(16, 3); header.putLong(32, 19);
            f.connection.handle(new SMB2PacketData(wire));
            assertFalse(f.request.getPromise().isFulfilled());
            assertEquals(19, f.request.getAsyncId());
            assertEquals(8, f.connection.sequenceWindow.available());
        }
    }

    private byte[] response(long session, byte[] key) throws Exception {
        return response(session, key, 0);
    }

    private byte[] response(long session, byte[] key, int status) throws Exception {
        byte[] wire = new byte[status == 0 ? 68 : 72];
        ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(0, 0x424d53fe); header.putShort(4, (short) 64);
        header.putShort(12, (short) 13); header.putShort(14, (short) 7);
        header.putInt(16, key == null ? 1 : 9); header.putLong(24, 123);
        header.putInt(8, status); header.putLong(40, session);
        header.putShort(64, (short) (status == 0 ? 4 : 9));
        if (key != null) {
            byte[] nonce = new byte[12]; nonce[0] = 123; nonce[8] = 1;
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(wire);
            System.arraycopy(cipher.doFinal(), 0, wire, 48, 16);
        }
        return wire;
    }

    private static class Fixture implements AutoCloseable {
        final Connection connection;
        final Request request;

        @SuppressWarnings("unchecked")
        Fixture(boolean signingRequired) throws Exception {
            TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
            SmbConfig config = SmbConfig.builder().withTransportLayerFactory((handlers, settings) -> transport).build();
            connection = new Connection(config, null, new SMBEventBus(), new ServerList());
            ConnectionContext context = mock(ConnectionContext.class);
            when(context.getServer()).thenReturn(new Server("localhost", 445));
            Field state = Connection.class.getDeclaredField("connectionContext");
            state.setAccessible(true); state.set(connection, context);
            Session session = mock(Session.class);
            when(session.isSigningRequired()).thenReturn(signingRequired);
            when(session.getSigningKey(any(), eq(false), same(connection)))
                    .thenReturn(new SecretKeySpec(new byte[16], "AES-GMAC"));
            connection.getSessionTable().registerSession(47L, session);
            Session otherSession = mock(Session.class);
            byte[] otherKey = new byte[16]; otherKey[0] = 1;
            when(otherSession.getSigningKey(any(), eq(false), same(connection)))
                    .thenReturn(new SecretKeySpec(otherKey, "AES-GMAC"));
            connection.getSessionTable().registerSession(48L, otherSession);
            SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
            packet.getHeader().setSessionId(47);
            request = new Request(packet, 123, UUID.randomUUID());
            connection.outstandingRequests.registerOutstanding(request);
        }

        void assertRejected() {
            assertFalse(request.getPromise().isFulfilled());
            assertSame(request, connection.outstandingRequests.getRequestByMessageId(123L));
            assertEquals(1, connection.sequenceWindow.available());
        }

        @Override public void close() throws Exception { connection.close(true); }
    }
}
