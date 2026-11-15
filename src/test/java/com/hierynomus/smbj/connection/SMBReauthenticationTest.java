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
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.*;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.session.SessionContext;
import com.hierynomus.smbj.testing.StubAuthenticator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SMBReauthenticationTest {
    private final Connection connection = mock(Connection.class);
    private final ConnectionContext context = mock(ConnectionContext.class);
    private final Session session = mock(Session.class);
    private final SessionContext keys = new SessionContext();
    private final SessionTable sessions = new SessionTable();
    private final AtomicInteger rounds = new AtomicInteger(), tokens = new AtomicInteger();
    private final SecretKey original = new SecretKeySpec(new byte[16], SMB3SigningAlgorithm.AES_GMAC.getAlgorithmName());
    private final SecretKey channel = new SecretKeySpec(new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}, SMB3SigningAlgorithm.AES_GMAC.getAlgorithmName());
    private boolean exportKey = true, failClose;
    private final AtomicInteger closes = new AtomicInteger();
    private Throwable cachedFailure;
    private SmbConfig config;

    private SMBSessionBuilder builder() {
        when(connection.getConnectionContext()).thenReturn(context);
        when(connection.getSessionTable()).thenReturn(sessions);
        when(connection.getPreauthSessionTable()).thenReturn(new SessionTable());
        when(connection.isConnected()).thenReturn(true);
        when(connection.isSessionEstablished(session)).thenReturn(true);
        when(context.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 1048576, 1048576, 1048576, true));
        when(context.getGssNegotiateToken()).thenReturn(new byte[0]);
        when(context.getClientCapabilities()).thenReturn(EnumSet.noneOf(SMB2GlobalCapability.class));
        when(session.getSessionId()).thenReturn(47L);
        when(session.getAuthenticationContext()).thenReturn(new AuthenticationContext("user", new char[0], "domain"));
        when(session.getSigningKey(any(), eq(false), same(connection))).thenReturn(channel);
        when(session.getSessionContext()).thenReturn(keys);
        keys.setSigningKey(original);
        keys.setEncryptionKey(new SecretKeySpec(new byte[16], "AES"));
        keys.setPreauthIntegrityHashValue(new byte[64]);
        sessions.registerSession(47L, session);
        config = SmbConfig.builder().withSigningRequired(true).withSecurityProvider(new BCSecurityProvider())
                .withAuthenticators(new StubAuthenticator.Factory() {
                    @Override public StubAuthenticator create() {
                        return new TrackingAuthenticator();
                    }
                }).build();
        return new SMBSessionBuilder(connection, config, null);
    }

    private class TrackingAuthenticator extends StubAuthenticator implements java.io.Closeable {
        @Override public AuthenticateResponse authenticate(AuthenticationContext auth, byte[] token, ConnectionContext context) throws IOException {
            if (cachedFailure instanceof IOException) throw (IOException) cachedFailure;
            if (cachedFailure instanceof Error) throw (Error) cachedFailure;
            if (cachedFailure instanceof RuntimeException) throw (RuntimeException) cachedFailure;
            tokens.incrementAndGet();
            AuthenticateResponse response = super.authenticate(auth, token, context);
            if (!exportKey) response.setSessionKey(null);
            return response;
        }
        @Override public void close() throws IOException {
            closes.incrementAndGet();
            if (cachedFailure instanceof IOException) throw (IOException) cachedFailure;
            if (cachedFailure instanceof Error) throw (Error) cachedFailure;
            if (cachedFailure instanceof RuntimeException) throw (RuntimeException) cachedFailure;
            if (failClose) throw new IOException("Injected authentication cleanup failure");
        }
    }

    private void reauthenticate(SMBSessionBuilder builder) throws IOException {
        builder.reauthenticate(session, new PacketSignatory(new BCSecurityProvider()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void preservesAnIdenticalCachedAuthenticationAndCleanupFailure(boolean error) throws Exception {
        SMBSessionBuilder builder = builder();
        cachedFailure = error ? new AssertionError("Cached GSS failure") : new IOException("Cached GSS failure");
        assertSame(cachedFailure, assertThrows(Throwable.class, () -> reauthenticate(builder)));
        assertEquals(0, cachedFailure.getSuppressed().length);
        assertEquals(1, closes.get());
        retained();
    }

    private void retained() {
        assertSame(original, keys.getSigningKey());
        assertTrue(closes.get() > 0);
        assertArrayEquals(new byte[64], keys.getPreauthIntegrityHashValue());
        assertSame(session, sessions.find(47L));
        verify(session, never()).addChannel(any(), any());
        verify(session, never()).initializeOriginalKeyMessageIdReservation(anyLong());
    }

    @Test
    void verifiesEveryRoundWithTheBoundChannelKeyAndRetainsSessionState() throws Exception {
        SMBSessionBuilder builder = builder();
        SecretKey encryption = keys.getEncryptionKey();
        when(connection.sendAndReceive(eq(session), any(SMB2Packet.class))).thenAnswer(call ->
                response(rounds.incrementAndGet() == 1 ? NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue() : 0, "valid"));
        reauthenticate(builder);
        assertEquals(2, rounds.get()); assertEquals(3, tokens.get());
        verify(connection, times(2)).sessionSetupAccepted(any());
        assertSame(encryption, keys.getEncryptionKey()); retained();
    }

    @ParameterizedTest
    @ValueSource(strings = {"unsigned-more", "bad-more", "unsigned-final", "bad-final", "wrong-key-final", "changed-sid", "guest", "anonymous", "no-key"})
    void rejectsUnauthenticatedOrChangedResponsesWithoutCreditOrStateEffects(String fault) throws Exception {
        SMBSessionBuilder builder = builder(); exportKey = !fault.equals("no-key");
        when(connection.sendAndReceive(eq(session), any(SMB2Packet.class))).thenAnswer(call -> {
            rounds.incrementAndGet();
            return response(fault.endsWith("more") ? NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue() : 0, fault);
        });
        assertThrows(IOException.class, () -> reauthenticate(builder));
        verify(connection, never()).sessionSetupAccepted(any());
        assertEquals(fault.equals("no-key") ? 2 : 1, tokens.get()); retained();
    }

    @ParameterizedTest
    @ValueSource(strings = {"none", "io", "error"})
    void authenticatedFailureDiscardsTheSessionWithoutReplacingKeys(String cleanup) throws Exception {
        SMBSessionBuilder builder = builder();
        Throwable cleanupFailure = cleanup.equals("io") ? new IOException("Cleanup failed") : new AssertionError("Cleanup failed");
        if (!cleanup.equals("none")) doThrow(cleanupFailure).when(session).discardAuthenticatedSession();
        when(connection.sendAndReceive(eq(session), any(SMB2Packet.class))).thenAnswer(call ->
                response(NtStatus.STATUS_ACCESS_DENIED.getValue(), "valid"));
        SMBApiException rejected = assertThrows(SMBApiException.class, () -> reauthenticate(builder));
        assertEquals(NtStatus.STATUS_ACCESS_DENIED, rejected.getStatus());
        assertEquals(cleanup.equals("none") ? 0 : 1, rejected.getSuppressed().length);
        if (!cleanup.equals("none")) assertSame(cleanupFailure, rejected.getSuppressed()[0]);
        assertSame(original, keys.getSigningKey());
        assertEquals(1, closes.get());
        verify(session).discardAuthenticatedSession();
        verify(connection).sessionSetupAccepted(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"valid", "unsigned-error", "bad-final", "local", "local-api"})
    void onlyVerifiedPeerDenialRetiresThePublicSession(String fault) throws Exception {
        builder();
        NegotiatedProtocol protocol = context.getNegotiatedProtocol();
        when(connection.getNegotiatedProtocol()).thenReturn(protocol);
        com.hierynomus.smbj.event.SMBEventBus bus = spy(new com.hierynomus.smbj.event.SMBEventBus());
        Session live = new Session(connection, config, new AuthenticationContext("user", new char[0], "domain"),
                bus, null, new PacketSignatory(new BCSecurityProvider()), null);
        live.setSessionId(47); live.getSessionContext().setSigningKey(original);
        SMB2SessionSetup established = mock(SMB2SessionSetup.class);
        when(established.getSessionFlags()).thenReturn(EnumSet.noneOf(SMB2SessionSetup.SMB2SessionFlags.class));
        live.getSessionContext().established(established);
        live.addBorrowedChannel(connection, channel);
        when(connection.isSessionEstablished(live)).thenReturn(true);
        when(connection.sendAndReceive(same(live), any(SMB2Packet.class))).thenAnswer(call -> {
            rounds.incrementAndGet(); return response(NtStatus.STATUS_LOGON_FAILURE.getValue(), fault);
        });
        if (fault.equals("local")) cachedFailure = new IOException("Local credentials unavailable");
        if (fault.equals("local-api")) cachedFailure = new SMBApiException(NtStatus.STATUS_LOGON_FAILURE.getValue(),
                SMB2MessageCommandCode.SMB2_SESSION_SETUP, "Local authenticator failure", null);
        Connection pending = mock(Connection.class);
        assertTrue(live.beginBinding(pending));

        if (fault.equals("valid")) {
            SMBApiException failure = assertThrows(SMBApiException.class, live::reauthenticate);
            assertEquals(NtStatus.STATUS_LOGON_FAILURE, failure.getStatus());
            assertEquals(0, live.getChannelCount());
            assertThrows(IOException.class, live::reauthenticate);
            assertThrows(IOException.class, () -> live.beginBinding(mock(Connection.class)));
            assertThrows(com.hierynomus.protocol.transport.TransportException.class,
                    () -> live.send(new com.hierynomus.mssmb2.messages.SMB2Echo(SMB2Dialect.SMB_3_1_1)));
            verify(pending).close(true);
            verify(bus).publish(any(com.hierynomus.smbj.event.SessionLoggedOff.class));
            verify(connection).releaseSessionLeases(live);
        } else {
            Exception failure = assertThrows(Exception.class, live::reauthenticate);
            if (fault.equals("local-api")) assertSame(cachedFailure, failure);
            else assertInstanceOf(IOException.class, failure);
            assertEquals(1, live.getChannelCount());
            verify(pending, never()).close(anyBoolean());
            verify(bus, never()).publish(any(com.hierynomus.smbj.event.SessionLoggedOff.class));
            live.endBinding(pending);
            when(connection.isSessionEstablished(live)).thenReturn(false);
            live.discardUnpublishedAuthentication();
        }
        assertSame(original, live.getSessionContext().getSigningKey());
        assertEquals(1, closes.get());
        verify(connection, never()).send(any(SMB2Packet.class));
        verify(connection, never()).close(anyBoolean());
    }

    @Test
    void capsAuthenticationRoundsWithoutDiscardingTheEstablishedSession() throws Exception {
        SMBSessionBuilder builder = builder();
        when(connection.sendAndReceive(eq(session), any(SMB2Packet.class))).thenAnswer(call -> {
            rounds.incrementAndGet(); return response(NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue(), "valid");
        });
        assertTrue(assertThrows(IOException.class, () -> reauthenticate(builder)).getMessage().contains("exchange limit"));
        assertEquals(16, rounds.get()); assertEquals(17, tokens.get()); retained();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rejectsInactiveOrForeignSessionBeforeAuthentication(boolean disconnected) throws Exception {
        SMBSessionBuilder builder = builder();
        if (disconnected) when(connection.isConnected()).thenReturn(false);
        else when(connection.isSessionEstablished(session)).thenReturn(false);
        assertThrows(IOException.class, () -> reauthenticate(builder));
        assertEquals(0, tokens.get()); verify(connection, never()).sendAndReceive(any(Session.class), any(SMB2Packet.class));
    }

    @Test
    void cleanupFailureIsSuppressedOnTheOriginalVerificationFailure() throws Exception {
        SMBSessionBuilder builder = builder(); failClose = true;
        when(connection.sendAndReceive(eq(session), any(SMB2Packet.class))).thenAnswer(call -> {
            rounds.incrementAndGet(); return response(0, "bad-final");
        });
        IOException failure = assertThrows(IOException.class, () -> reauthenticate(builder));
        assertTrue(failure.getMessage().contains("signature is invalid"));
        assertEquals("Injected authentication cleanup failure", failure.getSuppressed()[0].getMessage());
        assertEquals(1, closes.get()); retained();
    }

    @Test
    void sessionCloseDoesNotWaitForReauthenticationOrPermitItsLateSuccess() throws Exception {
        builder();
        NegotiatedProtocol protocol = context.getNegotiatedProtocol();
        when(connection.getNegotiatedProtocol()).thenReturn(protocol);
        Session live = new Session(connection, config, new AuthenticationContext("user", new char[0], "domain"),
                new com.hierynomus.smbj.event.SMBEventBus(), null, new PacketSignatory(new BCSecurityProvider()), null);
        live.setSessionId(47); live.getSessionContext().setSigningKey(original);
        SMB2SessionSetup established = mock(SMB2SessionSetup.class);
        when(established.getSessionFlags()).thenReturn(EnumSet.noneOf(SMB2SessionSetup.SMB2SessionFlags.class));
        live.getSessionContext().established(established);
        when(connection.isSessionEstablished(live)).thenReturn(true);
        doReturn(java.util.concurrent.CompletableFuture.completedFuture(
                new com.hierynomus.mssmb2.messages.SMB2Logoff(SMB2Dialect.SMB_3_1_1, 47))).when(connection).send(any(SMB2Packet.class));
        java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1), resume = new java.util.concurrent.CountDownLatch(1);
        when(connection.sendAndReceive(same(live), any(SMB2Packet.class))).thenAnswer(call -> {
            entered.countDown(); assertTrue(resume.await(5, java.util.concurrent.TimeUnit.SECONDS));
            rounds.incrementAndGet(); return response(0, "wrong-key-final");
        });
        java.util.concurrent.ExecutorService workers = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            java.util.concurrent.Future<?> auth = workers.submit(() -> { live.reauthenticate(); return null; });
            assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS));
            workers.submit(() -> { live.close(); return null; }).get(2, java.util.concurrent.TimeUnit.SECONDS);
            resume.countDown();
            java.util.concurrent.ExecutionException failure = assertThrows(java.util.concurrent.ExecutionException.class,
                    () -> auth.get(2, java.util.concurrent.TimeUnit.SECONDS));
            assertInstanceOf(IOException.class, failure.getCause());
            assertTrue(failure.getCause().getMessage().contains("closed during reauthentication"));
            assertEquals(1, closes.get()); verify(connection, never()).close(anyBoolean());
        } finally {
            resume.countDown(); workers.shutdownNow(); assertTrue(workers.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS));
        }
    }

    private SMB2SessionSetup response(long status, String fault) throws Exception {
        byte[] wire = new byte[73];
        boolean signed = !fault.startsWith("unsigned");
        ByteBuffer bytes = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putInt(0x424d53fe).putShort((short) 64).putShort((short) 1).putInt((int) status)
                .putShort((short) 1).putShort((short) 7).putInt(signed ? 9 : 1).putInt(0).putLong(rounds.get())
                .putInt(0).putInt(0).putLong(fault.equals("changed-sid") ? 48 : 47).put(new byte[16]);
        boolean error = status != 0 && status != NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue();
        if (error) bytes.putShort((short) 9).put((byte) 0).put((byte) 0).putInt(1).put((byte) 0);
        else bytes.putShort((short) 9).putShort((short) (fault.equals("guest") ? 1 : fault.equals("anonymous") ? 2 : 0))
                .putShort((short) 72).putShort((short) 1).put((byte) 0x60);
        if (signed) {
            byte[] nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putLong(rounds.get()).putInt(1).array();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec((fault.equals("wrong-key-final") ? original : channel).getEncoded(), "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(wire); System.arraycopy(cipher.doFinal(), 0, wire, 48, 16);
        }
        if (fault.startsWith("bad")) wire[72] ^= 1;
        return (SMB2SessionSetup) new SMB2MessageConverter().readPacket(null, new SMB2PacketData(wire));
    }
}
