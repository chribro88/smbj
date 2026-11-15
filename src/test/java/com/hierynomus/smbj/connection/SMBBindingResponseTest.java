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
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.Authenticator;
import com.hierynomus.smbj.auth.GSSAuthenticationContext;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.session.SessionContext;
import com.hierynomus.smbj.testing.StubAuthenticator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.Mockito.*;

class SMBBindingResponseTest {
    private final Connection primary = mock(Connection.class);
    private final Connection secondary = mock(Connection.class);
    private final SessionTable bindingSessions = new SessionTable();
    private final Session session = mock(Session.class);
    private final SessionContext keys = new SessionContext();
    private final byte[] gssKey = ByteArrayUtils.parseHex("09921d4431b171b977370bf8910900f9");
    private SMB2Dialect dialect = SMB2Dialect.SMB_3_1_1;
    private SMB3SigningAlgorithm algorithm = SMB3SigningAlgorithm.AES_CMAC;
    private SecretKey originalKey = new SecretKeySpec(new byte[16], "AesCmac");
    private SecurityProvider provider = new BCSecurityProvider();
    private SmbConfig config;

    private long messageId = 2;
    private long lastMessageId;

    private SMBSessionBuilder builder(boolean required) {
        return builder(required, new StubAuthenticator.Factory());
    }

    private SMBSessionBuilder builder(boolean required,
            com.hierynomus.protocol.commons.Factory.Named<Authenticator> authenticator) {
        ConnectionContext context = mock(ConnectionContext.class);
        when(context.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(dialect, 1048576, 1048576, 1048576, true));
        when(context.getSigningAlgorithm()).thenReturn(algorithm);
        when(context.getServerGuid()).thenReturn(new UUID(0, 1));
        when(context.getClientGuid()).thenReturn(new UUID(0, 2));
        when(context.getServerCapabilities()).thenReturn(EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL));
        when(context.getClientCapabilities()).thenReturn(EnumSet.noneOf(SMB2GlobalCapability.class));
        when(context.getGssNegotiateToken()).thenReturn(new byte[0]);
        when(context.getPreauthIntegrityHashId()).thenReturn(SMB3HashAlgorithm.SHA_512);
        when(context.getPreauthIntegrityHashValue()).thenReturn(new byte[64]);
        when(primary.getConnectionContext()).thenReturn(context);
        when(secondary.getConnectionContext()).thenReturn(context);
        when(secondary.getSessionTable()).thenReturn(bindingSessions);
        when(session.getConnection()).thenReturn(primary);
        when(session.getSessionContext()).thenReturn(keys);
        when(session.getSessionId()).thenReturn(47L);
        keys.setSigningKey(originalKey);
        keys.setEncryptionKey(new SecretKeySpec(new byte[16], "AES"));
        config = SmbConfig.builder().withSigningRequired(required).withEncryptData(true)
                .withSecurityProvider(provider).withAuthenticators(authenticator).build();
        return new SMBSessionBuilder(secondary, config, null);
    }

    @ParameterizedTest
    @CsvSource({"false,7,fresh", "true,7,fresh", "false,16,fresh", "true,16,fresh", "false,32,fresh", "true,32,fresh",
            "false,7,session", "true,7,session", "false,16,session", "true,16,session", "false,32,session", "true,32,session",
            "false,7,previous", "true,7,previous", "false,16,previous", "true,16,previous", "false,32,previous", "true,32,previous",
            "false,16,missing", "true,16,missing", "false,16,failure", "true,16,failure"})
    void kerberosBindingUsesItsOwnExportedKeyAndPreservesEstablishedKeys(boolean jce, int exportedLength,
            String finalKeySource) throws Exception {
        provider = jce ? new JceSecurityProvider(new BouncyCastleProvider()) : new BCSecurityProvider();
        Class<?> extendedContext = Class.forName("com.sun.security.jgss.ExtendedGSSContext");
        Field contextField = SpnegoAuthenticator.class.getDeclaredField("gssContext");
        contextField.setAccessible(true);
        List<GSSContext> contexts = new ArrayList<>();
        List<byte[]> exportedKeys = new ArrayList<>();
        AtomicInteger keyQueries = new AtomicInteger();
        SpnegoAuthenticator.Factory factory = new SpnegoAuthenticator.Factory() {
            @Override
            public SpnegoAuthenticator create() {
                int contextIndex = contexts.size();
                byte[] exported = new byte[exportedLength];
                Arrays.fill(exported, (byte) (0x30 + contextIndex));
                exportedKeys.add(exported);
                AtomicInteger legs = new AtomicInteger();
                GSSContext context = mock(GSSContext.class, withSettings().extraInterfaces(extendedContext).defaultAnswer(call -> {
                    switch (call.getMethod().getName()) {
                        case "initSecContext":
                            byte[] input = call.getArgument(0);
                            if (legs.getAndIncrement() == 0) {
                                assertEquals(0, input.length);
                                return new byte[]{0x60};
                            }
                            assertArrayEquals(new byte[]{0x60}, input);
                            return null;
                        case "isEstablished":
                            return legs.get() == 2;
                        case "inquireSecContext":
                            assertEquals(2, legs.get(), "The GSS key is unavailable until the final peer token");
                            assertEquals("KRB5_GET_SESSION_KEY", call.getArgument(0).toString());
                            keyQueries.incrementAndGet();
                            if (contextIndex == 1 && "missing".equals(finalKeySource)) return null;
                            if (contextIndex == 1 && "failure".equals(finalKeySource)) throw new GSSException(GSSException.FAILURE);
                            return new SecretKeySpec(exported, "AES");
                        default:
                            return RETURNS_DEFAULTS.answer(call);
                    }
                }));
                contexts.add(context);
                SpnegoAuthenticator authenticator = new SpnegoAuthenticator();
                assertDoesNotThrow(() -> contextField.set(authenticator, context));
                return authenticator;
            }
        };
        SMBSessionBuilder first = builder(true, factory);
        when(session.getAuthenticationContext()).thenReturn(new GSSAuthenticationContext("user", "DOMAIN", new Subject(), null));
        SecretKeySpec sessionKey = new SecretKeySpec(gssKey.clone(), "HmacSHA256");
        SecretKey cipherKey = keys.getEncryptionKey();
        SecretKey decryptionKey = new SecretKeySpec(new byte[16], "AES");
        SecretKey applicationKey = new SecretKeySpec(new byte[16], "AES");
        keys.setSessionKey(sessionKey);
        keys.setDecryptionKey(decryptionKey);
        keys.setApplicationKey(applicationKey);
        byte[] originalTranscript = new byte[64];
        Arrays.fill(originalTranscript, (byte) 0x45);
        keys.setPreauthIntegrityHashValue(originalTranscript.clone());
        Connection next = mock(Connection.class);
        doReturn(secondary.getConnectionContext()).when(next).getConnectionContext();
        SessionTable nextSessions = new SessionTable();
        when(next.getSessionTable()).thenReturn(nextSessions);
        Connection[] candidates = {secondary, next};
        byte[][] expectedChannelKeys = new byte[2][];
        for (int i = 0; i < candidates.length; i++) {
            final int candidate = i;
            when(candidates[i].sendAndReceive(any())).thenAnswer(call -> {
                assertEquals(candidate, keyQueries.get(), "Binding request precedes this GSS context's key export");
                byte[] request = requestBytes(call.getArgument(0));
                byte[] normalized = request.clone();
                Arrays.fill(normalized, 48, 64, (byte) 0);
                assertArrayEquals(independentSignature(originalKey.getEncoded(), normalized), Arrays.copyOfRange(request, 48, 64));
                MessageDigest hash = MessageDigest.getInstance("SHA-512");
                hash.update(new byte[64]);
                byte[] transcript = hash.digest(request);
                expectedChannelKeys[candidate] = channelKey(transcript, Arrays.copyOf(exportedKeys.get(candidate), 16));
                byte[] signingInput = exportedKeys.get(candidate);
                if (candidate == 1 && ("session".equals(finalKeySource) || "previous".equals(finalKeySource))) {
                    signingInput = "session".equals(finalKeySource) ? sessionKey.getEncoded() : exportedKeys.get(0);
                }
                return response(0, true, false, channelKey(transcript, Arrays.copyOf(signingInput, 16)), 7);
            });
        }
        assertSame(session, first.bind(session, new PacketSignatory(provider)));
        org.mockito.ArgumentCaptor<SecretKey> firstKey = org.mockito.ArgumentCaptor.forClass(SecretKey.class);
        verify(session).addChannel(eq(secondary), firstKey.capture());
        assertArrayEquals(expectedChannelKeys[0], firstKey.getValue().getEncoded());
        SMBSessionBuilder second = new SMBSessionBuilder(next, config, null);
        if ("fresh".equals(finalKeySource)) {
            assertSame(session, second.bind(session, new PacketSignatory(provider)));
            org.mockito.ArgumentCaptor<SecretKey> secondKey = org.mockito.ArgumentCaptor.forClass(SecretKey.class);
            verify(session).addChannel(eq(next), secondKey.capture());
            assertArrayEquals(expectedChannelKeys[1], secondKey.getValue().getEncoded());
            assertFalse(Arrays.equals(firstKey.getValue().getEncoded(), secondKey.getValue().getEncoded()));
            verify(next).sessionSetupAccepted(any());
        } else {
            IOException rejected = assertThrows(IOException.class, () -> second.bind(session, new PacketSignatory(provider)));
            if ("missing".equals(finalKeySource)) {
                assertTrue(rejected.getMessage().contains("did not export"));
            } else if ("failure".equals(finalKeySource)) {
                assertInstanceOf(com.hierynomus.protocol.transport.TransportException.class, rejected);
                Throwable cause = rejected;
                while (cause.getCause() != null) cause = cause.getCause();
                assertInstanceOf(GSSException.class, cause);
            } else {
                assertTrue(rejected.getMessage().contains("invalid"));
            }
            verify(session, never()).addChannel(eq(next), any());
            verify(next, never()).sessionSetupAccepted(any());
            assertNull(nextSessions.find(47L));
        }
        assertEquals(2, contexts.size());
        assertNotSame(contexts.get(0), contexts.get(1));
        for (GSSContext context : contexts) verify(context, times(2)).initSecContext(any(byte[].class), eq(0), anyInt());
        assertEquals(2, keyQueries.get());
        assertSame(session, bindingSessions.find(47L));
        assertSame(sessionKey, keys.getSessionKey());
        assertSame(originalKey, keys.getSigningKey());
        assertSame(cipherKey, keys.getEncryptionKey());
        assertSame(decryptionKey, keys.getDecryptionKey());
        assertSame(applicationKey, keys.getApplicationKey());
        assertArrayEquals(originalTranscript, keys.getPreauthIntegrityHashValue());
    }

    @ParameterizedTest
    @CsvSource({"true,2", "false,1"})
    void bindingAdvertisesConfiguredSigningPolicyOnWire(boolean required, int expectedMode) throws Exception {
        SMBSessionBuilder builder = builder(required);
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            byte[] request = requestBytes(call.getArgument(0));
            assertEquals(1, request[66], "session binding flag");
            assertEquals(expectedMode, request[67], "SESSION_SETUP SecurityMode");
            return response(NtStatus.STATUS_ACCESS_DENIED.getValue(), false, false, originalKey.getEncoded(), 0);
        });
        assertThrows(SMBApiException.class, () -> builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        verify(session, never()).addChannel(any(), any());
    }

    @ParameterizedTest
    @CsvSource({"false,false,0", "false,false,7", "true,false,0", "false,true,7"})
    void verifiesFinalChannelKeyAndAllResponseBytes(boolean unsigned, boolean tampered, int padding) throws Exception {
        SMBSessionBuilder builder = builder(true);
        SecretKey encryptionKey = keys.getEncryptionKey();
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            byte[] hashInput = requestBytes(call.getArgument(0));
            MessageDigest sha = MessageDigest.getInstance("SHA-512");
            sha.update(new byte[64]);
            byte[] transcript = sha.digest(hashInput);
            byte[] channelKey = channelKey(transcript);
            return response(0, !unsigned, tampered, channelKey, padding);
        });
        if (unsigned || tampered) {
            IOException failure = assertThrows(IOException.class, () -> builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
            assertTrue(failure.getMessage().contains(unsigned ? "missing" : "invalid"));
            assertTrue(failure.getMessage().contains("exchange=1"));
            assertTrue(failure.getMessage().contains("status=0x00000000"));
            verify(session, never()).addChannel(any(), any());
            verify(secondary, never()).sessionSetupAccepted(any());
        } else {
            assertSame(session, builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
            verify(session).addChannel(eq(secondary), any());
            verify(secondary).sessionSetupAccepted(any());
        }
        assertSame(originalKey, keys.getSigningKey());
        assertSame(encryptionKey, keys.getEncryptionKey());
    }

    @ParameterizedTest
    @CsvSource({"false,false", "true,true"})
    void rejectsUnsignedOrCorruptContinuationBeforeProcessingToken(boolean signed, boolean tampered) throws Exception {
        SMBSessionBuilder builder = builder(true);
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            requestBytes(call.getArgument(0));
            return response(NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue(), signed, tampered, originalKey.getEncoded(), 0);
        });
        IOException failure = assertThrows(IOException.class, () -> builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        assertTrue(failure.getMessage().contains(signed ? "invalid" : "missing"));
        assertTrue(failure.getMessage().contains("exchange=1"));
        assertTrue(failure.getMessage().contains("status=0xc0000016"));
        verify(session, never()).addChannel(any(), any());
        verify(secondary, never()).sessionSetupAccepted(any());
    }

    @ParameterizedTest
    @CsvSource({"false,false", "true,false", "true,true"})
    void authenticatesSignedBindingErrorsBeforeGrantingCredits(boolean signed, boolean corrupt) throws Exception {
        SMBSessionBuilder builder = builder(true);
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            requestBytes(call.getArgument(0));
            return response(NtStatus.STATUS_ACCESS_DENIED.getValue(), signed, corrupt, originalKey.getEncoded(), 7);
        });
        if (corrupt) {
            assertThrows(IOException.class, () -> builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        } else {
            assertThrows(SMBApiException.class, () -> builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        }
        verify(secondary, times(signed && !corrupt ? 1 : 0)).sessionSetupAccepted(any());
        verify(session, never()).addChannel(any(), any());
        assertSame(originalKey, keys.getSigningKey());
    }

    // Behavioral regression: go-smb2 7f69f658, TestBindChannelMultiRoundAuthentication.
    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void authenticatesSeveralRoundsWithTheKeyExportedOnlyAtCompletion(boolean corruptContinuation) throws Exception {
        java.util.concurrent.atomic.AtomicInteger authentications = new java.util.concurrent.atomic.AtomicInteger();
        StubAuthenticator authenticator = new StubAuthenticator() {
            @Override
            public com.hierynomus.smbj.auth.AuthenticateResponse authenticate(
                    com.hierynomus.smbj.auth.AuthenticationContext context, byte[] token, ConnectionContext connection) throws IOException {
                com.hierynomus.smbj.auth.AuthenticateResponse result = super.authenticate(context, token, connection);
                if (authentications.incrementAndGet() < 4) result.setSessionKey(null);
                return result;
            }
        };
        SMBSessionBuilder builder = builder(true, new StubAuthenticator.Factory() {
            @Override
            public StubAuthenticator create() { return authenticator; }
        });
        byte[][] transcript = {new byte[64]};
        java.util.concurrent.atomic.AtomicInteger exchanges = new java.util.concurrent.atomic.AtomicInteger();
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(transcript[0]);
            transcript[0] = hash.digest(requestBytes(call.getArgument(0)));
            int exchange = exchanges.incrementAndGet();
            if (exchange == 3) return response(0, true, false, channelKey(transcript[0]), 7);
            SMB2SessionSetup challenge = response(NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue(), true,
                    corruptContinuation && exchange == 2, originalKey.getEncoded(), 7);
            hash.update(transcript[0]);
            transcript[0] = hash.digest(com.hierynomus.smb.Packets.getPacketBytes(challenge));
            return challenge;
        });
        if (corruptContinuation) {
            IOException failure = assertThrows(IOException.class, () -> builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
            assertTrue(failure.getMessage().contains("exchange=2"));
            assertEquals(2, authentications.get());
            verify(session, never()).addChannel(any(), any());
        } else {
            assertSame(session, builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
            assertEquals(4, authentications.get());
            assertEquals(3, exchanges.get());
            verify(session).addChannel(eq(secondary), any());
        }
        assertSame(originalKey, keys.getSigningKey());
    }

    // Behavioral regression: WindowsProtocolTestSuites 29ddb4238, MultipleChannel_SecondChannelSessionSetupFailAtFirstTime.
    @org.junit.jupiter.api.Test
    void failedBindingCanRetryWithoutHashingTheRejectedExchange() throws Exception {
        SMBSessionBuilder builder = builder(true);
        java.util.concurrent.atomic.AtomicInteger attempts = new java.util.concurrent.atomic.AtomicInteger();
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            byte[] request = requestBytes(call.getArgument(0));
            if (attempts.incrementAndGet() == 1) return response(NtStatus.STATUS_ACCESS_DENIED.getValue(), false, false, new byte[16], 0);
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(new byte[64]);
            return response(0, true, false, channelKey(hash.digest(request)), 0);
        });
        assertThrows(SMBApiException.class, () -> builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        verify(session, never()).addChannel(any(), any());
        assertSame(session, builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        assertEquals(2, attempts.get());
        verify(session, times(1)).addChannel(eq(secondary), any());
        assertSame(originalKey, keys.getSigningKey());
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(ints = {1, 2})
    void rejectsAuthenticatedBindingThatBecomesGuestOrAnonymous(int flags) throws Exception {
        SMBSessionBuilder builder = builder(true);
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(new byte[64]);
            byte[] transcript = hash.digest(requestBytes(call.getArgument(0)));
            return response(0, true, false, channelKey(transcript), 0, flags);
        });
        assertThrows(IOException.class, () -> builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        verify(session, never()).addChannel(any(), any());
        assertSame(originalKey, keys.getSigningKey());
    }

    @org.junit.jupiter.api.Test
    void aSessionPublishedAfterValidationCannotBeReplacedByBinding() throws Exception {
        builder(true);
        Session other = mock(Session.class);
        SessionTable raced = new SessionTable() {
            private boolean first = true;
            @Override public Session find(Long id) {
                if (first && id == 47L) {
                    first = false;
                    registerSession(id, other);
                    return null;
                }
                return super.find(id);
            }
        };
        when(secondary.getSessionTable()).thenReturn(raced);
        SMBSessionBuilder builder = new SMBSessionBuilder(secondary, config, null);
        Signatory signatory = mock(Signatory.class);
        assertThrows(IOException.class, () -> builder.bind(session, signatory));
        assertSame(other, raced.find(47L));
        verifyNoInteractions(signatory);
        verify(secondary, never()).sendAndReceive(any());
    }

    @org.junit.jupiter.api.Test
    void failedBindingCannotRemoveAnotherSessionsReplacementEntry() throws Exception {
        SMBSessionBuilder builder = builder(true);
        Session replacement = mock(Session.class);
        doAnswer(call -> {
            bindingSessions.removeSession(47L);
            bindingSessions.registerSession(47L, replacement);
            throw new IOException("Binding failed after entry replacement");
        }).when(secondary).sendAndReceive(any());
        assertThrows(IOException.class, () -> builder.bind(session, new PacketSignatory(provider)));
        assertSame(replacement, bindingSessions.find(47L));
        verify(session, never()).addChannel(any(), any());
    }

    @org.junit.jupiter.api.Test
    void failedAuxiliaryCleanupCannotPublishTheBoundChannel() throws Exception {
        SMBSessionBuilder builder = builder(true);
        Session auxiliary = mock(Session.class);
        IOException failure = new IOException("Auxiliary LOGOFF failed");
        doThrow(failure).when(auxiliary).close();
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(new byte[64]);
            return response(0, true, false, channelKey(hash.digest(requestBytes(call.getArgument(0)))), 0);
        });
        assertSame(failure, assertThrows(IOException.class,
                () -> builder.bind(session, new PacketSignatory(provider), true, auxiliary)));
        verify(session, never()).addChannel(any(), any());
        assertNull(bindingSessions.find(47L));
    }

    @org.junit.jupiter.api.Test
    void bindingMakesEstablishedCipherKeysAvailableBeforeChannelPublication() throws Exception {
        SMBSessionBuilder builder = builder(true);
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            assertSame(session, bindingSessions.find(47L), "Encrypted binding responses need the established session decryption key");
            verify(session, never()).addChannel(any(), any());
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(new byte[64]);
            return response(0, true, false, channelKey(hash.digest(requestBytes(call.getArgument(0)))), 0);
        });
        assertSame(session, builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        assertSame(session, bindingSessions.find(47L));
        verify(session).addChannel(eq(secondary), any());
    }

    @org.junit.jupiter.api.Test
    void failedBindingRemovesTemporaryKeysAndLeavesTheOriginalSessionUnchanged() throws Exception {
        SMBSessionBuilder builder = builder(true);
        SessionTable originalSessions = new SessionTable();
        originalSessions.registerSession(47L, session);
        when(primary.getSessionTable()).thenReturn(originalSessions);
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            assertSame(session, bindingSessions.find(47L));
            requestBytes(call.getArgument(0));
            return response(NtStatus.STATUS_ACCESS_DENIED.getValue(), false, false, new byte[16], 0);
        });
        assertThrows(SMBApiException.class, () -> builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        assertNull(bindingSessions.find(47L));
        assertSame(session, originalSessions.find(47L));
        assertSame(originalKey, keys.getSigningKey());
        verify(session, never()).addChannel(any(), any());
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(value = SMB2Dialect.class, names = {"SMB_3_0", "SMB_3_0_2"})
    void bindsEarlierSmb3DialectsWithoutPreauthenticationHashing(SMB2Dialect dialect) throws Exception {
        this.dialect = dialect;
        SMBSessionBuilder builder = builder(true);
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            requestBytes(call.getArgument(0));
            return response(0, true, false, channelKey(null), 7);
        });
        assertSame(session, builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        org.mockito.ArgumentCaptor<SecretKey> key = org.mockito.ArgumentCaptor.forClass(SecretKey.class);
        verify(session).addChannel(eq(secondary), key.capture());
        assertEquals("AesCmac", key.getValue().getAlgorithm());
        assertArrayEquals(channelKey(null), key.getValue().getEncoded());
        assertTrue(SmbConfig.builder().withDialects(dialect).build().getClientCapabilities()
                .contains(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL));
        assertSame(originalKey, keys.getSigningKey());
    }

    // go-smb2 7f69f658 documents original-key GMAC nonce reuse; successful binding is not a safety test.
    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void rejectsGmacBeforeSigningSendingOrRegistering(boolean required) throws Exception {
        algorithm = SMB3SigningAlgorithm.AES_GMAC;
        originalKey = new SecretKeySpec(new byte[16], algorithm.getAlgorithmName());
        SMBSessionBuilder builder = builder(required);
        Signatory signatory = mock(Signatory.class);
        IOException failure = assertThrows(IOException.class, () -> builder.bind(session, signatory));
        assertTrue(failure.getMessage().contains("GMAC"));
        assertTrue(failure.getMessage().contains("nonce uniqueness"));
        verifyNoInteractions(signatory);
        verify(secondary, never()).sendAndReceive(any());
        verify(secondary, never()).close(anyBoolean());
        verify(session, never()).addChannel(any(), any());
        assertNull(bindingSessions.find(47L));
        assertSame(originalKey, keys.getSigningKey());
    }

    @ParameterizedTest
    @CsvSource({"true,AES_CMAC,AES_CMAC", "false,AES_CMAC,AES_CMAC", "false,,AES_CMAC",
            "false,AES_CMAC,", "true,,"})
    void acceptsDefaultOrExplicitCmacWithGcmEncryption(boolean required,
            SMB3SigningAlgorithm originalAlgorithm, SMB3SigningAlgorithm candidateAlgorithm) throws Exception {
        SMBSessionBuilder builder = builder(required);
        ConnectionContext original = primary.getConnectionContext();
        ConnectionContext candidate = mock(ConnectionContext.class, delegatesTo(original));
        when(primary.getConnectionContext()).thenReturn(candidate);
        doReturn(originalAlgorithm).when(candidate).getSigningAlgorithm();
        when(original.getSigningAlgorithm()).thenReturn(candidateAlgorithm);
        when(original.getCipherId()).thenReturn(SMB3EncryptionCipher.AES_128_GCM);
        when(secondary.sendAndReceive(any())).thenAnswer(call -> {
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(new byte[64]);
            return response(0, true, false, channelKey(hash.digest(requestBytes(call.getArgument(0)))), 0);
        });
        SecretKey cipherKey = keys.getEncryptionKey();
        assertSame(session, builder.bind(session, new PacketSignatory(new BCSecurityProvider())));
        verify(session).addChannel(eq(secondary), any());
        assertSame(cipherKey, keys.getEncryptionKey());
    }

    @org.junit.jupiter.api.Test
    void rejectsSigningDisabledBeforeBinding() throws Exception {
        builder(false);
        SMBSessionBuilder builder = new SMBSessionBuilder(secondary,
                SmbConfig.builder().withDialects(SMB2Dialect.SMB_2_1).withSigningEnabled(false).build(), null);
        Signatory signatory = mock(Signatory.class);
        assertThrows(IOException.class, () -> builder.bind(session, signatory));
        verifyNoInteractions(signatory);
        verify(secondary, never()).sendAndReceive(any());
        assertNull(bindingSessions.find(47L));
    }

    private byte[] independentSignature(byte[] key, byte[] wire) throws Exception {
        CMac mac = new CMac(AESEngine.newInstance());
        mac.init(new KeyParameter(key)); mac.update(wire, 0, wire.length);
        byte[] signature = new byte[16]; mac.doFinal(signature, 0);
        return signature;
    }

    private byte[] requestBytes(SMB2Packet packet) {
        lastMessageId = messageId++;
        packet.getHeader().setMessageId(lastMessageId);
        packet.setCreditsAssigned(1);
        SMBBuffer wire = new SMBBuffer();
        packet.write(wire);
        return wire.getCompactData();
    }

    private byte[] channelKey(byte[] transcript) throws Exception {
        return channelKey(transcript, gssKey);
    }

    private byte[] channelKey(byte[] transcript, byte[] exportedKey) throws Exception {
        ByteArrayOutputStream input = new ByteArrayOutputStream();
        input.write(new byte[]{0, 0, 0, 1});
        input.write((dialect == SMB2Dialect.SMB_3_1_1 ? "SMBSigningKey\0" : "SMB2AESCMAC\0").getBytes(StandardCharsets.US_ASCII));
        input.write(0);
        input.write(dialect == SMB2Dialect.SMB_3_1_1 ? transcript : "SmbSign\0".getBytes(StandardCharsets.US_ASCII));
        input.write(new byte[]{0, 0, 0, (byte) 128});
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(exportedKey, "HmacSHA256"));
        return Arrays.copyOf(mac.doFinal(input.toByteArray()), 16);
    }

    private SMB2SessionSetup response(long status, boolean signed, boolean tampered, byte[] key, int padding) throws Exception {
        return response(status, signed, tampered, key, padding, 0);
    }

    private SMB2SessionSetup response(long status, boolean signed, boolean tampered, byte[] key, int padding, int sessionFlags) throws Exception {
        boolean error = status != 0 && status != NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue();
        if (error && !signed) {
            SMB2SessionSetup rejected = new SMB2SessionSetup();
            rejected.getHeader().setSessionId(47);
            rejected.getHeader().setStatusCode(status);
            return rejected;
        }
        byte[] wire = new byte[73 + padding];
        ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(0x424d53fe).putShort((short) 64).putShort((short) 1).putInt((int) status)
                .putShort((short) 1).putShort((short) 1).putInt(signed ? 9 : 1).putInt(0).putLong(lastMessageId)
                .putInt(0).putInt(0).putLong(47).put(new byte[16]);
        if (error) {
            header.putShort((short) 9).put((byte) 0).put((byte) 0).putInt(1).put((byte) 0);
        } else {
            header.putShort((short) 9).putShort((short) sessionFlags).putShort((short) 72).putShort((short) 1).put((byte) 0x60);
        }
        if (signed) {
            // Independent wire-signature oracle; includes trailing server padding.
            byte[] signature = independentSignature(key, wire);
            System.arraycopy(signature, 0, wire, 48, 16);
        }
        if (tampered) wire[wire.length - 1] ^= 1;
        return (SMB2SessionSetup) new SMB2MessageConverter().readPacket(null, new SMB2PacketData(wire));
    }
}
