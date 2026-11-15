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
import com.hierynomus.mssmb2.SMB3EncryptedPacketData;
import com.hierynomus.mssmb2.SMB3EncryptionCipher;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.session.SessionContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ResponseAuthenticationTest {
    private long encryptedNonce;

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

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void encryptedReplyUsesMatchingSessionContext(boolean jce) throws Exception {
        try (Fixture f = new Fixture(true, jce)) {
            f.connection.handle(new SMB3EncryptedPacketData(encrypted(response(47, null), 47)));
            assertTrue(f.request.getPromise().isFulfilled());
            assertEquals(8, f.connection.sequenceWindow.available());
        }
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void retiredSessionTransformCannotAffectAnotherSessionsOutstandingWork(boolean jce, boolean tampered) throws Exception {
        try (Fixture f = new Fixture(true, jce)) {
            byte[] late = encrypted(response(47, null), 47);
            if (tampered) late[4] ^= 1;
            f.connection.abandonRequest(123, new TransportException("Authentication cleanup timed out"));
            Session retired = f.connection.getSessionTable().find(47L);
            f.connection.getSessionTable().removeSession(47L, retired);
            retired.getSessionContext().setDecryptionKey(null);
            Request healthy = f.register(124, 48);

            for (int delivery = 0; delivery < 2; delivery++) {
                f.connection.handle(new SMB3EncryptedPacketData(late));
                assertEquals(1, f.connection.sequenceWindow.available());
                assertTrue(f.request.getPromise().isFulfilled());
                assertNull(f.connection.outstandingRequests.getRequestByMessageId(123L));
                assertNull(f.connection.outstandingRequests.getRequestByCancelId(f.request.getCancelId()));
                assertFalse(healthy.getPromise().isFulfilled());
                assertSame(healthy, f.connection.outstandingRequests.getRequestByMessageId(124L));
            }

            byte[] reply = response(48, null);
            ByteBuffer.wrap(reply).order(ByteOrder.LITTLE_ENDIAN).putLong(24, 124);
            f.connection.handle(new SMB3EncryptedPacketData(encrypted(reply, 48)));
            assertTrue(healthy.getPromise().isFulfilled());
            assertEquals(8, f.connection.sequenceWindow.available());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void encryptedReplyCannotUseAnotherSessionsContext(boolean jce) throws Exception {
        try (Fixture f = new Fixture(true, jce)) {
            f.connection.handle(new SMB3EncryptedPacketData(encrypted(response(48, null), 48)));
            f.assertRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void encryptedReplyRejectsAnInvalidTag(boolean jce) throws Exception {
        try (Fixture f = new Fixture(true, jce)) {
            byte[] wire = encrypted(response(47, null), 47); wire[4] ^= 1;
            assertThrows(com.hierynomus.smbj.common.SMBRuntimeException.class,
                    () -> f.connection.handle(new SMB3EncryptedPacketData(wire)));
            f.assertRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void encryptedReplyWithMismatchedInnerSessionSignalsTransportFailure(boolean jce) throws Exception {
        try (Fixture f = new Fixture(true, jce)) {
            assertThrows(TransportException.class,
                    () -> f.connection.handle(new SMB3EncryptedPacketData(encrypted(response(48, null), 47))));
            f.assertRejected();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void encryptedCompoundKeepsMatchingRepliesAndPadding(boolean jce) throws Exception {
        try (Fixture f = new Fixture(true, jce)) {
            Request second = f.register(124, 47);
            f.connection.handle(new SMB3EncryptedPacketData(encrypted(compound(123, 47, 124, 47), 47)));
            assertTrue(f.request.getPromise().isFulfilled());
            assertTrue(second.getPromise().isFulfilled());
            assertEquals(15, f.connection.sequenceWindow.available());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void encryptedCompoundRejectsForeignMemberBeforeCompletingAnyRequest(boolean jce) throws Exception {
        try (Fixture f = new Fixture(true, jce)) {
            Request second = f.register(124, 48);
            assertThrows(TransportException.class, () -> f.connection.handle(
                    new SMB3EncryptedPacketData(encrypted(compound(123, 47, 124, 48), 47))));
            f.assertRejected();
            assertFalse(second.getPromise().isFulfilled());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void encryptedCompoundCanDiscardFirstReplyAndStillReadNextMember(boolean jce) throws Exception {
        try (Fixture f = new Fixture(true, jce)) {
            f.connection.handle(new SMB3EncryptedPacketData(encrypted(compound(999, 47, 123, 47), 47)));
            assertTrue(f.request.getPromise().isFulfilled());
            assertEquals(8, f.connection.sequenceWindow.available());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {-8, 8, 63, 68, 144})
    void encryptedCompoundRejectsInvalidExtentBeforeCompletingFirstRequest(int next) throws Exception {
        try (Fixture f = new Fixture(true)) {
            byte[] plain = compound(123, 47, 124, 47);
            ByteBuffer.wrap(plain).order(ByteOrder.LITTLE_ENDIAN).putInt(20, next);
            assertThrows(Exception.class,
                    () -> f.connection.handle(new SMB3EncryptedPacketData(encrypted(plain, 47))));
            f.assertRejected();
        }
    }

    @Test
    void encryptedCompoundRejectsTruncatedHeaderBeforeCompletingFirstRequest() throws Exception {
        try (Fixture f = new Fixture(true)) {
            byte[] plain = Arrays.copyOf(compound(123, 47, 124, 47), 132);
            assertThrows(Exception.class,
                    () -> f.connection.handle(new SMB3EncryptedPacketData(encrypted(plain, 47))));
            f.assertRejected();
        }
    }

    private byte[] compound(long firstMid, long firstSession, long secondMid, long secondSession) throws Exception {
        byte[] first = response(firstSession, null), second = response(secondSession, null);
        ByteBuffer header = ByteBuffer.wrap(first).order(ByteOrder.LITTLE_ENDIAN);
        header.putLong(24, firstMid); header.putInt(20, 72);
        ByteBuffer.wrap(second).order(ByteOrder.LITTLE_ENDIAN).putLong(24, secondMid);
        byte[] plain = Arrays.copyOf(first, 72 + second.length);
        Arrays.fill(plain, first.length, 72, (byte) 0x5a);
        System.arraycopy(second, 0, plain, 72, second.length);
        return plain;
    }

    private byte[] encrypted(byte[] plain, long session) throws Exception {
        byte[] wire = new byte[52 + plain.length], key = new byte[16];
        if (session == 48) key[0] = 1;
        ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(0, 0x424d53fd); header.putLong(20, ++encryptedNonce);
        header.putInt(36, plain.length); header.putShort(42, (short) 1); header.putLong(44, session);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(wire, 20, 32)));
        cipher.updateAAD(wire, 20, 32);
        byte[] ciphertext = cipher.doFinal(plain);
        System.arraycopy(ciphertext, 0, wire, 52, plain.length);
        System.arraycopy(ciphertext, plain.length, wire, 4, 16);
        return wire;
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

        Fixture(boolean signingRequired) throws Exception {
            this(signingRequired, false);
        }

        @SuppressWarnings("unchecked")
        Fixture(boolean signingRequired, boolean jce) throws Exception {
            TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
            SmbConfig config = SmbConfig.builder().withTransportLayerFactory((handlers, settings) -> transport)
                    .withSecurityProvider(jce ? new JceSecurityProvider() : new BCSecurityProvider()).build();
            connection = new Connection(config, null, new SMBEventBus(), new ServerList());
            ConnectionContext context = mock(ConnectionContext.class);
            when(context.getServer()).thenReturn(new Server("localhost", 445));
            when(context.getNegotiatedProtocol()).thenReturn(
                    new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
            when(context.getCipherId()).thenReturn(SMB3EncryptionCipher.AES_128_GCM);
            Field state = Connection.class.getDeclaredField("connectionContext");
            state.setAccessible(true); state.set(connection, context);
            Field encryptor = Connection.class.getDeclaredField("encryptor");
            encryptor.setAccessible(true); ((PacketEncryptor) encryptor.get(connection)).init(context);
            Session session = mock(Session.class);
            SessionContext keys = new SessionContext();
            keys.setDecryptionKey(new SecretKeySpec(new byte[16], "AES"));
            when(session.getSessionContext()).thenReturn(keys);
            when(session.isSigningRequired()).thenReturn(signingRequired);
            when(session.getSigningKey(any(), eq(false), same(connection)))
                    .thenReturn(new SecretKeySpec(new byte[16], "AES-GMAC"));
            connection.getSessionTable().registerSession(47L, session);
            Session otherSession = mock(Session.class);
            byte[] otherKey = new byte[16]; otherKey[0] = 1;
            SessionContext otherKeys = new SessionContext();
            otherKeys.setDecryptionKey(new SecretKeySpec(otherKey, "AES"));
            when(otherSession.getSessionContext()).thenReturn(otherKeys);
            when(otherSession.getSigningKey(any(), eq(false), same(connection)))
                    .thenReturn(new SecretKeySpec(otherKey, "AES-GMAC"));
            connection.getSessionTable().registerSession(48L, otherSession);
            request = register(123, 47);
        }

        Request register(long mid, long session) throws Exception {
            SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
            packet.getHeader().setSessionId(session);
            Request registered = new Request(packet, mid, UUID.randomUUID());
            connection.outstandingRequests.registerOutstanding(registered);
            return registered;
        }

        void assertRejected() {
            assertFalse(request.getPromise().isFulfilled());
            assertSame(request, connection.outstandingRequests.getRequestByMessageId(123L));
            assertEquals(1, connection.sequenceWindow.available());
        }

        @Override public void close() throws Exception { connection.close(true); }
    }
}
