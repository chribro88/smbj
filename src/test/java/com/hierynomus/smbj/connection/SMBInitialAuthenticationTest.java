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

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.Packets;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.session.SessionContext;
import com.hierynomus.smbj.testing.StubAuthenticator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SMBInitialAuthenticationTest {
    @ParameterizedTest
    @CsvSource({"false,SMB_2_1,AES_CMAC", "true,SMB_2_1,AES_CMAC",
            "false,SMB_3_0,AES_CMAC", "true,SMB_3_0,AES_CMAC",
            "false,SMB_3_1_1,AES_CMAC", "true,SMB_3_1_1,AES_CMAC",
            "false,SMB_3_1_1,AES_GMAC", "true,SMB_3_1_1,AES_GMAC"})
    void verifiesFinalReplyBeforePublishingAcrossProviders(boolean jce, SMB2Dialect dialect,
            SMB3SigningAlgorithm algorithm) throws Exception {
        Fixture fixture = new Fixture(jce, dialect, algorithm);
        fixture.rounds = 3;
        fixture.keyAtCompletion = true;
        assertSame(fixture.session, fixture.establish());
        assertSame(fixture.session, fixture.sessions.find(47L));
        assertTrue(fixture.preauth.activeSessions().isEmpty());
        verify(fixture.connection, times(3)).sessionSetupAccepted(any());
        assertArrayEquals(fixture.lastWire, Packets.getPacketBytes(fixture.lastResponse),
                "Verification must preserve the received bytes, including padding");
        assertArrayEquals(Arrays.copyOf(fixture.gssKey, 16), fixture.keys.getSessionKey().getEncoded());
        assertArrayEquals(fixture.signingKey(), dialect.isSmb3x()
                ? fixture.keys.getSigningKey().getEncoded() : fixture.keys.getSessionKey().getEncoded());
    }

    @ParameterizedTest
    @CsvSource({"false,AES_CMAC", "true,AES_CMAC", "false,AES_GMAC", "true,AES_GMAC"})
    void rejectsInvalidFinalRepliesEvenWhenOrdinarySigningIsOptional(boolean jce,
            SMB3SigningAlgorithm algorithm) throws Exception {
        for (String fault : new String[]{"signature", "padding", "key", "unsigned", "role"}) {
            Fixture fixture = new Fixture(jce, SMB2Dialect.SMB_3_1_1, algorithm);
            fixture.fault = fault;
            fixture.rounds = 2;
            SMBRuntimeException failure = assertThrows(SMBRuntimeException.class, fixture::establish, fault);
            assertInstanceOf(IOException.class, failure.getCause());
            assertTrue(failure.getCause().getMessage().contains("authentication response signature"), fault);
            assertTrue(failure.getCause().getMessage().contains("exchange=2"), fault);
            assertTrue(fixture.sessions.activeSessions().isEmpty(), fault);
            assertTrue(fixture.preauth.activeSessions().isEmpty(), fault);
            verify(fixture.keys, never()).established(any());
            verify(fixture.connection, times(1)).sessionSetupAccepted(any());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @SuppressWarnings("unchecked")
    void actualReceiveChainDefersCreditsUntilAuthenticationAcceptsTheReply(boolean corrupt) throws Exception {
        Fixture peer = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        peer.rounds = 2;
        peer.fault = corrupt ? "padding" : "none";
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = peer.connection(transport);
        try {
            doAnswer(call -> {
                assertTrue(connection.getSessionTable().activeSessions().isEmpty());
                int before = connection.sequenceWindow.available();
                peer.reply(call.getArgument(0), false);
                connection.handle(new SMB2PacketData(peer.lastWire));
                assertEquals(before, connection.sequenceWindow.available(), "Receive chain cannot spend unverified credits");
                return null;
            }).when(transport).write(any());
            SMBSessionBuilder builder = new SMBSessionBuilder(connection, peer.config, auth -> peer.session);
            AuthenticationContext auth = new AuthenticationContext("user", new char[0], "domain");
            if (corrupt) {
                assertThrows(SMBRuntimeException.class, () -> builder.establish(auth));
                assertEquals(2, connection.sequenceWindow.available(), "Only the unsigned initial challenge granted credits");
                assertTrue(connection.getSessionTable().activeSessions().isEmpty());
            } else {
                assertSame(peer.session, builder.establish(auth));
                assertEquals(5, connection.sequenceWindow.available());
                assertSame(peer.session, connection.getSessionTable().find(47L));
            }
            assertTrue(connection.getPreauthSessionTable().activeSessions().isEmpty());
        } finally {
            connection.close(true);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void anotherCommandCannotBypassDeferredAuthenticationCredits() throws Exception {
        Fixture peer = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = peer.connection(transport);
        try {
            SMB2SessionSetup request = new SMB2SessionSetup(SMB2Dialect.SMB_3_1_1,
                    EnumSet.of(SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED),
                    EnumSet.noneOf(SMB2GlobalCapability.class));
            Future<SMB2SessionSetup> result = connection.send(request);
            peer.reply(request, false);
            byte[] impostor = peer.lastWire.clone();
            impostor[12] = 13; // ECHO under the live SESSION_SETUP MessageId.
            impostor[16] = 1;
            Arrays.fill(impostor, 48, 64, (byte) 0);
            connection.handle(new SMB2PacketData(impostor));
            assertFalse(result.isDone());
            assertEquals(0, connection.sequenceWindow.available());
            connection.handle(new SMB2PacketData(peer.lastWire));
            assertTrue(result.isDone());
            assertArrayEquals(peer.lastWire, Packets.getPacketBytes(result.get()));
            assertEquals(0, connection.sequenceWindow.available(), "Delivery alone must not accept authentication credits");
        } finally {
            connection.close(true);
        }
    }

    @ParameterizedTest
    @CsvSource({"SMB_2_1,1", "SMB_3_0,2"})
    void preservesUnsignedGuestOrAnonymousExceptionsOnEarlierDialects(SMB2Dialect dialect, int flags) throws Exception {
        Fixture fixture = new Fixture(false, dialect, SMB3SigningAlgorithm.AES_CMAC);
        fixture.sessionFlags = flags;
        fixture.fault = "unsigned";
        fixture.gssKey = null;
        assertSame(fixture.session, fixture.establish());
        assertFalse(fixture.keys.isSigningRequired());
    }

    @ParameterizedTest
    @CsvSource({"false", "true"})
    void requiredEncryptionDoesNotBypassFinalVerification(boolean corrupt) throws Exception {
        Fixture fixture = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        fixture.sessionFlags = 4;
        when(fixture.context.supportsEncryption()).thenReturn(true);
        when(fixture.context.getCipherId()).thenReturn(SMB3EncryptionCipher.AES_128_GCM);
        fixture.fault = corrupt ? "padding" : "none";
        if (corrupt) {
            assertThrows(SMBRuntimeException.class, fixture::establish);
            assertTrue(fixture.sessions.activeSessions().isEmpty());
        } else {
            fixture.establish();
            assertTrue(fixture.keys.isEncryptData());
            assertFalse(fixture.keys.isSigningRequired());
        }
    }

    @ParameterizedTest
    @CsvSource({"0", "7", "32"})
    void handlesExportedKeyLengthsAccordingToSessionKeyRules(int keyLength) throws Exception {
        Fixture fixture = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        fixture.gssKey = new byte[keyLength];
        Arrays.fill(fixture.gssKey, (byte) 0x35);
        if (keyLength == 0) {
            SMBRuntimeException failure = assertThrows(SMBRuntimeException.class, fixture::establish);
            assertTrue(failure.getCause().getMessage().contains("did not export a session key"));
            assertTrue(fixture.sessions.activeSessions().isEmpty());
        } else {
            fixture.establish();
            assertArrayEquals(Arrays.copyOf(fixture.gssKey, 16), fixture.keys.getSessionKey().getEncoded());
        }
    }

    @Test
    void failedContinuationRetiresOnlyItsOwnProvisionalSession() throws Exception {
        Fixture fixture = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        fixture.rounds = 3;
        Session unrelated = mock(Session.class);
        fixture.preauth.registerSession(91L, unrelated);
        doAnswer(call -> {
            if (fixture.exchange == 1) throw new IOException("Continuation lost");
            return fixture.reply(call.getArgument(0));
        }).when(fixture.connection).sendAndReceive(any());
        assertThrows(SMBRuntimeException.class, fixture::establish);
        assertNull(fixture.preauth.find(47L));
        assertSame(unrelated, fixture.preauth.find(91L));
        verify(fixture.session).discardUnpublishedAuthentication();
        verify(fixture.connection, never()).close(anyBoolean());
    }

    @Test
    void cleanupCannotRemoveAnotherAttemptsReplacementEntry() throws Exception {
        Fixture fixture = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        fixture.rounds = 3;
        Session replacement = mock(Session.class);
        doAnswer(call -> {
            if (fixture.exchange == 1) {
                fixture.preauth.removeSession(47L);
                fixture.preauth.registerSession(47L, replacement);
                throw new IOException("Continuation lost");
            }
            return fixture.reply(call.getArgument(0));
        }).when(fixture.connection).sendAndReceive(any());
        assertThrows(SMBRuntimeException.class, fixture::establish);
        assertSame(replacement, fixture.preauth.find(47L));
        verify(fixture.session).discardUnpublishedAuthentication();
        verify(replacement, never()).discardUnpublishedAuthentication();
    }

    @Test
    void provisionalSessionIdCollisionCannotStealAnotherAttemptsContext() throws Exception {
        Fixture fixture = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        fixture.rounds = 2;
        Session other = mock(Session.class);
        fixture.preauth.registerSession(47L, other);
        assertThrows(SMBRuntimeException.class, fixture::establish);
        assertSame(other, fixture.preauth.find(47L));
        verify(other, never()).getSessionContext();
        verify(fixture.session).discardUnpublishedAuthentication();
    }

    @Test
    void authenticatedSessionIdCollisionCannotReplaceAnExistingSession() throws Exception {
        Fixture fixture = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        Session other = mock(Session.class);
        doAnswer(call -> {
            SMB2SessionSetup response = fixture.reply(call.getArgument(0));
            fixture.sessions.registerSession(47L, other);
            return response;
        }).when(fixture.connection).sendAndReceive(any());
        assertThrows(SMBRuntimeException.class, fixture::establish);
        assertSame(other, fixture.sessions.find(47L));
        verify(fixture.session).discardUnpublishedAuthentication();
        verify(other, never()).discardUnpublishedAuthentication();
    }

    @Test
    void changedContinuationSessionIdCannotSwitchAuthenticationOwnership() throws Exception {
        Fixture fixture = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        fixture.rounds = 3;
        Session other = mock(Session.class);
        fixture.preauth.registerSession(48L, other);
        doAnswer(call -> {
            SMB2SessionSetup response = fixture.reply(call.getArgument(0));
            if (fixture.exchange == 2) response.getHeader().setSessionId(48L);
            return response;
        }).when(fixture.connection).sendAndReceive(any());
        SMBRuntimeException failure = assertThrows(SMBRuntimeException.class, fixture::establish);
        assertTrue(failure.getCause().getMessage().contains("changed SessionId"));
        assertNull(fixture.preauth.find(47L));
        assertSame(other, fixture.preauth.find(48L));
        verify(other, never()).getSessionContext();
        verify(fixture.session).discardUnpublishedAuthentication();
    }

    @Test
    void challengeLoopIsBoundedAndDiscardsTheAttempt() throws Exception {
        Fixture fixture = new Fixture(false, SMB2Dialect.SMB_3_1_1, SMB3SigningAlgorithm.AES_GMAC);
        fixture.rounds = 100;
        SMBRuntimeException failure = assertThrows(SMBRuntimeException.class, fixture::establish);
        assertTrue(failure.getCause().getMessage().contains("exchange limit"));
        assertEquals(16, fixture.exchange);
        assertTrue(fixture.preauth.activeSessions().isEmpty());
        verify(fixture.session).discardUnpublishedAuthentication();
    }

    private static final class Fixture {
        private final Connection connection = mock(Connection.class);
        private final ConnectionContext context = mock(ConnectionContext.class);
        private final SessionTable sessions = new SessionTable();
        private final SessionTable preauth = new SessionTable();
        private final Session session = mock(Session.class);
        private final SessionContext keys = spy(new SessionContext());
        private final SMB2Dialect dialect;
        private final SMB3SigningAlgorithm algorithm;
        private final SMBSessionBuilder builder;
        private final SmbConfig config;
        private byte[] transcript = new byte[64];
        private byte[] gssKey = new byte[16];
        private String fault = "none";
        private int rounds = 1;
        private boolean keyAtCompletion;
        private int exchange;
        private long lastMessageId;
        private int sessionFlags;
        private byte[] lastWire;
        private SMB2SessionSetup lastResponse;

        private Fixture(boolean jce, SMB2Dialect dialect, SMB3SigningAlgorithm algorithm) throws Exception {
            this.dialect = dialect;
            this.algorithm = algorithm;
            Arrays.fill(gssKey, (byte) 0x35);
            when(connection.getConnectionContext()).thenReturn(context);
            when(connection.getSessionTable()).thenReturn(sessions);
            when(connection.getPreauthSessionTable()).thenReturn(preauth);
            NegotiatedProtocol protocol = new NegotiatedProtocol(dialect, 1048576, 1048576, 1048576, true);
            when(context.getNegotiatedProtocol()).thenReturn(protocol);
            when(connection.getNegotiatedProtocol()).thenReturn(protocol);
            when(context.getSigningAlgorithm()).thenReturn(algorithm);
            when(context.getClientCapabilities()).thenReturn(EnumSet.noneOf(SMB2GlobalCapability.class));
            when(context.getGssNegotiateToken()).thenReturn(new byte[0]);
            when(context.getPreauthIntegrityHashValue()).thenReturn(new byte[64]);
            when(context.getPreauthIntegrityHashId()).thenReturn(SMB3HashAlgorithm.SHA_512);
            when(session.getSessionId()).thenReturn(47L);
            when(session.getSessionContext()).thenReturn(keys);
            SecurityProvider provider = jce ? new JceSecurityProvider(new BouncyCastleProvider()) : new BCSecurityProvider();
            config = SmbConfig.builder().withSigningRequired(false).withSecurityProvider(provider)
                    .withAuthenticators(new StubAuthenticator.Factory() {
                        @Override
                        public StubAuthenticator create() {
                            return new StubAuthenticator() {
                                @Override
                                public AuthenticateResponse authenticate(AuthenticationContext auth, byte[] token,
                                        ConnectionContext connection) throws IOException {
                                    AuthenticateResponse response = super.authenticate(auth, token, connection);
                                    response.setSessionKey(keyAtCompletion && exchange < rounds ? null : gssKey);
                                    return response;
                                }
                            };
                        }
                    }).build();
            builder = new SMBSessionBuilder(connection, config, auth -> session);
            when(connection.sendAndReceive(any())).thenAnswer(call -> reply(call.getArgument(0)));
        }

        private Session establish() {
            return builder.establish(new AuthenticationContext("user", new char[0], "domain"));
        }

        private Connection connection(TransportLayer<SMBPacket<?, ?>> transport) throws Exception {
            SmbConfig config = SmbConfig.builder().withTransportLayerFactory((handlers, settings) -> transport).build();
            Connection actual = new Connection(config, null, new SMBEventBus(), new ServerList());
            java.lang.reflect.Field contextField = Connection.class.getDeclaredField("connectionContext");
            contextField.setAccessible(true);
            contextField.set(actual, context);
            when(context.getServer()).thenReturn(new Server("localhost", 445));
            return actual;
        }

        private SMB2SessionSetup reply(SMB2Packet request) throws Exception {
            return reply(request, true);
        }

        private SMB2SessionSetup reply(SMB2Packet request, boolean assignMessageId) throws Exception {
            assertTrue(sessions.activeSessions().isEmpty(), "No session can be published before the final signature");
            exchange++;
            if (assignMessageId) request.getHeader().setMessageId(exchange);
            lastMessageId = request.getHeader().getMessageId();
            request.setCreditsAssigned(1);
            SMBBuffer encoded = new SMBBuffer();
            request.write(encoded);
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(transcript);
            transcript = hash.digest(encoded.getCompactData());
            boolean complete = exchange == rounds;
            boolean signed = complete && !fault.equals("unsigned");
            byte[] wire = new byte[80];
            ByteBuffer fields = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
            fields.putInt(0x424d53fe).putShort((short) 64).putShort((short) 1)
                    .putInt(complete ? 0 : (int) NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue())
                    .putShort((short) 1).putShort((short) 3).putInt(signed ? 9 : 1).putInt(0).putLong(lastMessageId)
                    .putInt(0).putInt(0).putLong(47).put(new byte[16]);
            fields.putShort((short) 9).putShort((short) sessionFlags).putShort((short) 72).putShort((short) 1).put((byte) 0x60);
            if (signed) {
                byte[] key = signingKey();
                if (fault.equals("key")) key[0] ^= 1;
                System.arraycopy(signature(key, wire), 0, wire, 48, 16);
                if (fault.equals("signature")) wire[48] ^= 1;
                if (fault.equals("padding")) wire[79] ^= 1;
                if (fault.equals("role")) wire[16] &= ~1;
            }
            lastWire = wire.clone();
            lastResponse = (SMB2SessionSetup) new SMB2MessageConverter().readPacket(request, new SMB2PacketData(wire));
            if (!complete) {
                hash.update(transcript);
                transcript = hash.digest(wire);
            }
            return lastResponse;
        }

        private byte[] signingKey() throws Exception {
            byte[] sessionKey = Arrays.copyOf(gssKey == null || gssKey.length == 0 ? new byte[16] : gssKey, 16);
            if (!dialect.isSmb3x()) return sessionKey;
            ByteArrayOutputStream input = new ByteArrayOutputStream();
            input.write(new byte[]{0, 0, 0, 1});
            input.write((dialect == SMB2Dialect.SMB_3_1_1 ? "SMBSigningKey\0" : "SMB2AESCMAC\0")
                    .getBytes(StandardCharsets.US_ASCII));
            input.write(0);
            input.write(dialect == SMB2Dialect.SMB_3_1_1 ? transcript : "SmbSign\0".getBytes(StandardCharsets.US_ASCII));
            input.write(new byte[]{0, 0, 0, (byte) 128});
            Mac kdf = Mac.getInstance("HmacSHA256");
            kdf.init(new SecretKeySpec(sessionKey, "HmacSHA256"));
            return Arrays.copyOf(kdf.doFinal(input.toByteArray()), 16);
        }

        private byte[] signature(byte[] key, byte[] wire) throws Exception {
            if (!dialect.isSmb3x()) {
                Mac hmac = Mac.getInstance("HmacSHA256");
                hmac.init(new SecretKeySpec(key, "HmacSHA256"));
                return hmac.doFinal(wire);
            }
            if (algorithm == SMB3SigningAlgorithm.AES_GMAC) {
                byte[] nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putLong(lastMessageId).putInt(1).array();
                Cipher gmac = Cipher.getInstance("AES/GCM/NoPadding");
                gmac.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
                gmac.updateAAD(wire);
                return gmac.doFinal();
            }
            CMac cmac = new CMac(AESEngine.newInstance());
            cmac.init(new KeyParameter(key));
            cmac.update(wire, 0, wire.length);
            byte[] signature = new byte[16];
            cmac.doFinal(signature, 0);
            return signature;
        }
    }
}
