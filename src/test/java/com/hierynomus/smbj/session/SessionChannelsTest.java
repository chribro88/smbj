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
package com.hierynomus.smbj.session;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.SMB2Cancel;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.connection.Signatory;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import org.junit.jupiter.api.Test;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SessionChannelsTest {
    private final Connection primary = connection();
    private final Connection secondary = connection();
    private final SecretKey primaryKey = new SecretKeySpec(new byte[16], "AesCmac");
    private final SecretKey secondaryKey = new SecretKeySpec(new byte[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "AesCmac");
    private final Signatory signatory = mock(Signatory.class);

    private Connection connection() {
        Connection result = mock(Connection.class);
        when(result.isConnected()).thenReturn(true);
        when(result.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
        return result;
    }

    private Session session() {
        when(signatory.sign(any(), any())).thenAnswer(call -> call.getArgument(0));
        Session result = new Session(primary, SmbConfig.createDefaultConfig(), null, null, null, signatory, null);
        result.getSessionContext().setSigningKey(primaryKey);
        result.addChannel(secondary, secondaryKey);
        return result;
    }

    @Test
    void bootstrapAnchorKeepsBusyCallerIdsOutsideTheLowReservationCursor() {
        // Bootstrap precedes all operational channel publication.
        Session bootstrap = new Session(primary, SmbConfig.createDefaultConfig(), null, null, null, signatory, null);
        bootstrap.initializeOriginalKeyMessageIdReservation(3);
        bootstrap.prepareBootstrapChannel(secondary);
        assertFalse(bootstrap.reserveOriginalKeyMessageId(secondary, 3, false));
        assertTrue(bootstrap.reserveOriginalKeyMessageId(secondary, 1000000, false));
        assertTrue(bootstrap.reserveOriginalKeyMessageId(secondary, 1000007, false));
        assertFalse(bootstrap.reserveOriginalKeyMessageId(secondary, 1000000, false));
        Connection fresh = connection();
        assertTrue(bootstrap.reserveOriginalKeyMessageId(fresh, 4, false));
        assertTrue(bootstrap.reserveOriginalKeyMessageId(fresh, 5, false));
        assertTrue(bootstrap.reserveOriginalKeyMessageId(primary, 3, true));
        assertFalse(bootstrap.reserveOriginalKeyMessageId(primary, 3, true));
        assertFalse(bootstrap.reserveOriginalKeyMessageId(primary, -1, true));
        assertFalse(bootstrap.reserveOriginalKeyMessageId(fresh, 1000000, false));
    }

    @Test
    void bootstrapHandoffRequiresVerifiedMembershipAndUsesTheChannelKey() throws Exception {
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null, null, null, signatory, null);
        session.getSessionContext().setSigningKey(primaryKey);
        session.initializeOriginalKeyMessageIdReservation(3);
        session.prepareBootstrapChannel(secondary);
        assertThrows(IllegalStateException.class, () -> session.adoptBootstrapChannel(primary, secondary));
        session.addBorrowedChannel(secondary, secondaryKey);
        session.adoptBootstrapChannel(primary, secondary);
        assertSame(secondary, session.getConnection());
        when(signatory.sign(any(), any())).thenAnswer(call -> call.getArgument(0));
        com.hierynomus.smbj.connection.ConnectionContext context = mock(com.hierynomus.smbj.connection.ConnectionContext.class);
        when(context.getSigningAlgorithm()).thenReturn(com.hierynomus.mssmb2.SMB3SigningAlgorithm.AES_GMAC);
        when(secondary.getConnectionContext()).thenReturn(context);
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        session.send(packet, secondary);
        verify(signatory).sign(packet, secondaryKey);
        verify(secondary).send(packet);
        verify(secondary, never()).sendOriginalKey(any(), any());
        assertTrue(session.reserveOriginalKeyMessageId(connection(), 4, false));
    }

    @Test
    void discardingAnUnpublishedAuthenticationStopsItWithoutTouchingTheConnection() throws Exception {
        com.hierynomus.smbj.event.SMBEventBus bus = spy(new com.hierynomus.smbj.event.SMBEventBus());
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null, bus, null, signatory, null);

        session.discardUnpublishedAuthentication();
        session.close();

        assertEquals(0, session.getChannelCount());
        assertThrows(TransportException.class, () -> session.send(new SMB2Echo(SMB2Dialect.SMB_3_1_1)));
        assertThrows(java.io.IOException.class, session::reauthenticate);
        verify(bus).unsubscribe(session);
        verify(bus, never()).publish(any());
        verify(primary, never()).send(any());
        verify(primary, never()).close(anyBoolean());
    }

    @Test
    void discardingAuthenticationCannotInvalidateAnAlreadyPublishedSession() throws Exception {
        com.hierynomus.smbj.event.SMBEventBus bus = spy(new com.hierynomus.smbj.event.SMBEventBus());
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null, bus, null, signatory, null);
        when(primary.isSessionEstablished(session)).thenReturn(true);

        assertThrows(IllegalStateException.class, session::discardUnpublishedAuthentication);

        assertEquals(1, session.getChannelCount());
        verify(bus, never()).unsubscribe(session);
        verify(primary, never()).close(anyBoolean());
    }

    @Test
    void closeDisposesOwnedChannelsAndPreservesBorrowedConnections() throws Exception {
        com.hierynomus.smbj.event.SMBEventBus bus = new com.hierynomus.smbj.event.SMBEventBus();
        when(signatory.sign(any(), any())).thenAnswer(call -> call.getArgument(0));
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null, bus, null, signatory, null);
        session.getSessionContext().setSigningKey(primaryKey);
        session.addBorrowedChannel(secondary, secondaryKey);
        Connection owned = connection();
        session.addChannel(owned, secondaryKey);
        com.hierynomus.mssmb2.messages.SMB2Logoff response =
                new com.hierynomus.mssmb2.messages.SMB2Logoff(SMB2Dialect.SMB_3_1_1, 0);
        doReturn(CompletableFuture.completedFuture(response)).when(primary).send(any());

        session.close();

        verify(owned).close(true);
        verify(secondary, never()).close(anyBoolean());
        verify(primary, never()).close(anyBoolean());
        assertEquals(0, session.getChannelCount());
    }

    @Test
    void closeAbortsOwnedPendingConnectionsAndLeavesBorrowedAttemptsUnpublished() throws Exception {
        com.hierynomus.smbj.event.SMBEventBus bus = new com.hierynomus.smbj.event.SMBEventBus();
        when(signatory.sign(any(), any())).thenAnswer(call -> call.getArgument(0));
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null, bus, null, signatory, null);
        session.getSessionContext().setSigningKey(primaryKey);
        Connection owned = connection();
        assertTrue(session.beginBinding(owned, true));
        assertTrue(session.beginBinding(secondary, false));
        doReturn(CompletableFuture.completedFuture(
                new com.hierynomus.mssmb2.messages.SMB2Logoff(SMB2Dialect.SMB_3_1_1, 0)))
                .when(primary).send(any());

        session.close();

        verify(owned).close(true);
        verify(secondary, never()).close(anyBoolean());
        assertThrows(IllegalStateException.class, () -> session.addBorrowedChannel(secondary, secondaryKey));
        assertThrows(java.io.IOException.class, () -> session.beginBinding(secondary, false));
    }

    @Test
    void sessionSetupUsesTheSelectedSigningKeyWithoutEncryption() throws Exception {
        Session session = session();
        session.getSessionContext().setEncryptData(true);
        com.hierynomus.mssmb2.messages.SMB2SessionSetup request = new com.hierynomus.mssmb2.messages.SMB2SessionSetup(
                SMB2Dialect.SMB_3_1_1, java.util.EnumSet.of(com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED),
                java.util.EnumSet.noneOf(com.hierynomus.mssmb2.SMB2GlobalCapability.class));
        session.send(request, secondary);
        verify(signatory).sign(request, secondaryKey);
        verify(secondary).send(request);
    }

    @Test
    void aSendRacingWithCloseRetainsItsSelectedChannelKey() throws Exception {
        when(signatory.sign(any(), any())).thenAnswer(call -> call.getArgument(0));
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null,
                new com.hierynomus.smbj.event.SMBEventBus(), null, signatory, null);
        session.getSessionContext().setSigningKey(primaryKey);
        session.addBorrowedChannel(secondary, secondaryKey);
        NegotiatedProtocol protocol = primary.getNegotiatedProtocol();
        CountDownLatch selectingKey = new CountDownLatch(1), resume = new CountDownLatch(1), closeStarted = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<Thread> senderThread = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<Thread> closerThread = new java.util.concurrent.atomic.AtomicReference<>();
        when(primary.getNegotiatedProtocol()).thenAnswer(call -> {
            if (Thread.currentThread() == senderThread.get()) {
                selectingKey.countDown(); assertTrue(resume.await(5, TimeUnit.SECONDS));
            }
            return protocol;
        });
        doReturn(CompletableFuture.completedFuture(new com.hierynomus.mssmb2.messages.SMB2Logoff(SMB2Dialect.SMB_3_1_1, 0)))
                .when(primary).send(any());
        ExecutorService workers = Executors.newFixedThreadPool(2);
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        try {
            Future<?> sending = workers.submit(() -> { senderThread.set(Thread.currentThread()); return session.send(request, secondary); });
            assertTrue(selectingKey.await(2, TimeUnit.SECONDS));
            Future<?> closing = workers.submit(() -> {
                closerThread.set(Thread.currentThread()); closeStarted.countDown(); session.close(); return null;
            });
            assertTrue(closeStarted.await(2, TimeUnit.SECONDS));
            try { closing.get(200, TimeUnit.MILLISECONDS); }
            catch (TimeoutException waitingForKeySnapshot) {
                java.lang.management.ThreadInfo info = java.lang.management.ManagementFactory.getThreadMXBean().getThreadInfo(closerThread.get().getId());
                assertEquals(Thread.State.BLOCKED, info.getThreadState());
                assertEquals(senderThread.get().getId(), info.getLockOwnerId());
            }
            resume.countDown(); sending.get(5, TimeUnit.SECONDS); closing.get(5, TimeUnit.SECONDS);
            verify(signatory).sign(request, secondaryKey);
            verify(secondary, never()).close(anyBoolean());
        } finally {
            resume.countDown(); workers.shutdownNow(); assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    // Behavioral regression: go-smb2 7f69f658, TestSessionChannelsSelectLiveConnections.
    @Test
    void distributesRequestsWithEachChannelsOwnSigningKey() throws Exception {
        Session session = session();
        SMB2Echo first = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        SMB2Echo second = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        session.send(first);
        session.send(second);
        verify(primary).send(first);
        verify(secondary).send(second);
        verify(signatory).sign(first, primaryKey);
        verify(signatory).sign(second, secondaryKey);
    }

    @Test
    void retiresFailedChannelAndContinuesThroughSurvivor() throws Exception {
        Session session = session();
        when(primary.isClosed()).thenReturn(true);
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        session.send(request);
        verify(secondary).send(request);
        verify(primary, never()).send(any());
        assertEquals(1, session.getChannelCount());
    }

    @Test
    void shareRequiredEncryptionUsesTheSurvivingChannelAndSessionCipherKey() throws Exception {
        com.hierynomus.smbj.connection.PacketEncryptor encryptor =
                mock(com.hierynomus.smbj.connection.PacketEncryptor.class);
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null, null, null, signatory, encryptor);
        session.getSessionContext().setSigningKey(primaryKey);
        SecretKey cipherKey = new SecretKeySpec(new byte[16], "AES");
        session.getSessionContext().setEncryptionKey(cipherKey);
        session.addChannel(secondary, secondaryKey);
        when(primary.isClosed()).thenReturn(true);
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        com.hierynomus.smbj.connection.PacketEncryptor.EncryptedPacketWrapper wire =
                mock(com.hierynomus.smbj.connection.PacketEncryptor.EncryptedPacketWrapper.class);
        when(encryptor.encrypt(request, cipherKey)).thenReturn(wire);

        session.send(request, true);

        verify(encryptor).encrypt(request, cipherKey);
        verify(secondary).send(wire);
        verify(primary, never()).send(any());
        assertEquals(1, request.getHeader().getChannelSequence());
    }

    @Test
    void shareRequiredEncryptionFailsBeforeSendingWhenNoCipherKeyIsAvailable() throws Exception {
        Session session = session();
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1);

        assertThrows(TransportException.class, () -> session.send(request, true));

        verify(primary, never()).send(any());
        verify(secondary, never()).send(any());
    }

    @Test
    void cachedDfsSessionSurvivesPrimaryFailureWhileAnotherChannelRemains() throws Exception {
        Session nested = session();
        Session parent = new Session(primary, SmbConfig.createDefaultConfig(), null, null, null, signatory, null);
        java.lang.reflect.Field cache = Session.class.getDeclaredField("nestedSessionsByHost");
        cache.setAccessible(true);
        ((java.util.Map<String, Session>) cache.get(parent)).put("target", nested);
        when(primary.isConnected()).thenReturn(false);
        when(primary.isClosed()).thenReturn(true);

        assertSame(nested, parent.getNestedSession(new com.hierynomus.smbj.common.SmbPath("target", "share")));
        assertEquals(1, nested.getChannelCount());
        verify(primary, never()).close();
    }

    @Test
    void failsWhenEveryChannelHasClosed() {
        Session session = session();
        when(primary.isClosed()).thenReturn(true);
        when(secondary.isClosed()).thenReturn(true);
        assertThrows(TransportException.class, () -> session.send(new SMB2Echo(SMB2Dialect.SMB_3_1_1)));
    }

    @Test
    void aBlockedTransportCannotBlockSelectionOfAnotherChannel() throws Exception {
        Session session = session();
        // A transport's isConnected may wait behind a blocked socket write. Retirement must not call it.
        when(primary.isConnected()).thenThrow(new AssertionError("Blocked transport lock"));
        when(secondary.isConnected()).thenThrow(new AssertionError("Blocked transport lock"));
        SMB2Echo first = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        SMB2Echo second = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        session.send(first);
        session.send(second);
        verify(primary).send(first);
        verify(secondary).send(second);
    }

    @Test
    void aBlockedCandidateTransportCheckDoesNotBlockExistingChannelSelection() throws Exception {
        Session session = session();
        Connection candidate = connection();
        CountDownLatch checking = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(candidate.isConnected()).thenAnswer(call -> {
            checking.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            return true;
        });
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Future<?> publication = workers.submit(() -> session.addChannel(candidate, secondaryKey));
            assertTrue(checking.await(2, TimeUnit.SECONDS));
            workers.submit(() -> session.send(new SMB2Echo(SMB2Dialect.SMB_3_1_1))).get(1, TimeUnit.SECONDS);
            verify(primary).send(any());
            release.countDown();
            publication.get(1, TimeUnit.SECONDS);
            assertEquals(3, session.getChannelCount());
        } finally {
            release.countDown();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS));
        }
    }

    @Test
    void cancellationDuringTheTransportCheckPreventsPublication() {
        Session session = session();
        Connection candidate = connection();
        AtomicBoolean cancelled = new AtomicBoolean();
        when(candidate.isClosed()).thenAnswer(call -> cancelled.get());
        when(candidate.isConnected()).thenAnswer(call -> { cancelled.set(true); return true; });
        assertThrows(IllegalStateException.class, () -> session.addChannel(candidate, secondaryKey));
        assertEquals(2, session.getChannelCount());
    }

    // Behavioral regression: go-smb2 7f69f658, TestBoundWriteIsNotReplayedAfterConnectionLoss.
    @Test
    void neverReplaysAnUncertainWriteOnAnotherChannel() throws Exception {
        Session session = session();
        SMB2Packet request = new SMB2WriteRequest(SMB2Dialect.SMB_3_1_1,
                new SMB2FileId(new byte[8], new byte[8]), 1, 2,
                new ArrayByteChunkProvider(new byte[]{1, 2, 3}, 0), 3);
        doThrow(new TransportException("WRITE response lost")).when(primary).send(any());
        assertThrows(TransportException.class, () -> session.send(request));
        verify(primary, times(1)).send(request);
        verify(secondary, never()).send(any());
        when(primary.isClosed()).thenReturn(true);
        SMB2Echo next = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        session.send(next);
        verify(secondary).send(next);
    }

    // Behavioral regression: go-smb2 7f69f658, TestBoundRequestCancellationUsesOriginalChannel.
    @Test
    void sendsCancellationOnlyOnTheOwningChannel() throws Exception {
        Session session = session();
        SMB2Cancel cancel = new SMB2Cancel(SMB2Dialect.SMB_3_1_1, 1, 7, 0);
        session.send(cancel, secondary);
        assertEquals(7, cancel.getHeader().getMessageId());
        verify(secondary).send(cancel);
        verify(primary, never()).send(any());
    }

    @Test
    void rejectsAnUnboundConnectionWithoutSending() throws Exception {
        Session session = session();
        Connection unknown = connection();
        assertThrows(TransportException.class, () -> session.send(new SMB2Echo(SMB2Dialect.SMB_3_1_1), unknown));
        verify(unknown, never()).send(any());
    }
}
