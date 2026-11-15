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
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.transport.TransportException;
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

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConnectionMessageIdReservationTest {

    @Test
    void auxiliaryPreparationRequiresDifferentActualSigningKeyBytes() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport);
        try {
            Session main = mock(Session.class);
            when(main.getSessionContext()).thenReturn(new com.hierynomus.smbj.session.SessionContext());
            main.getSessionContext().setSigningKey(new javax.crypto.spec.SecretKeySpec(new byte[16], "AES-GMAC"));
            Session auxiliary = mock(Session.class);
            when(auxiliary.getSessionContext()).thenReturn(new com.hierynomus.smbj.session.SessionContext());
            auxiliary.getSessionContext().setSigningKey(new javax.crypto.spec.SecretKeySpec(new byte[16], "AES-GMAC"));
            connection.getSessionTable().registerSession(1L, main);
            assertFalse(connection.hasIndependentSigningSession(main));
            connection.getSessionTable().registerSession(2L, auxiliary);
            assertFalse(connection.hasIndependentSigningSession(main), "Different session/key objects cannot hide equal key bytes");
            byte[] different = new byte[16]; different[0] = 1;
            auxiliary.getSessionContext().setSigningKey(new javax.crypto.spec.SecretKeySpec(different, "AES-GMAC"));
            assertTrue(connection.hasIndependentSigningSession(main));
            connection.getSessionTable().removeSession(2L);
            assertFalse(connection.hasIndependentSigningSession(main));
        } finally {
            connection.close(true);
        }
    }

    @Test
    void originalKeyReservationsAreMonotonicAndNeverReleased() {
        Session session = new Session(null, null, null, null, null, null, null);
        session.initializeOriginalKeyMessageIdReservation(3);
        assertFalse(session.reserveOriginalKeyMessageId(2));
        assertTrue(session.reserveOriginalKeyMessageId(3));
        assertFalse(session.reserveOriginalKeyMessageId(3));
        assertTrue(session.reserveOriginalKeyMessageId(5));
        session.initializeOriginalKeyMessageIdReservation(4);
        assertFalse(session.reserveOriginalKeyMessageId(4));
        assertTrue(session.reserveOriginalKeyMessageId(6));
    }

    @Test
    void originalKeyReservationCannotWrapPastTheTerminalMessageId() {
        Session session = new Session(null, null, null, null, null, null, null);
        session.initializeOriginalKeyMessageIdReservation(-2);
        assertTrue(session.reserveOriginalKeyMessageId(-2));
        assertFalse(session.reserveOriginalKeyMessageId(-1));
        assertFalse(session.reserveOriginalKeyMessageId(0));
        assertFalse(session.reserveOriginalKeyMessageId(-2));
    }

    @Test
    void burnsCollidingMessageIdsWithUnsignedEchoesWithoutHoldingTheAllocationLockAcrossIo() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            Field lockField = Connection.class.getDeclaredField("lock");
            lockField.setAccessible(true);
            ReentrantLock allocationLock = (ReentrantLock) lockField.get(test.connection);
            List<SMB2Packet> writes = new ArrayList<>();
            TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
            when(transport.isConnected()).thenReturn(true);
            doAnswer(invocation -> {
                SMB2Packet sent = invocation.getArgument(0);
                assertFalse(allocationLock.isHeldByCurrentThread());
                writes.add(sent);
                SMB2Echo response = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
                response.getHeader().setMessageId(sent.getHeader().getMessageId());
                response.getHeader().setCreditResponse(1);
                response.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
                byte[] frame = AbortTestConnection.frame(response);
                test.connection.handle(new SMB2PacketData(Arrays.copyOfRange(frame, 4, frame.length)));
                return null;
            }).when(transport).write(any());
            test.connection.transport.disconnect();
            test.connection.transport = transport;
            Field lowestAvailableField = SequenceWindow.class.getDeclaredField("lowestAvailable");
            lowestAvailableField.setAccessible(true);
            long initialMessageId = ((AtomicLong) lowestAvailableField.get(test.connection.sequenceWindow)).get();

            SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
            long acceptedMessageId = initialMessageId + 2;
            SMB2Echo response = test.connection.sendAndReceive(request, messageId -> {
                assertTrue(allocationLock.isHeldByCurrentThread());
                return messageId >= acceptedMessageId;
            });

            assertEquals(acceptedMessageId, response.getHeader().getMessageId());
            assertEquals(3, writes.size());
            for (int i = 0; i < 2; i++) {
                SMB2Packet collision = writes.get(i);
                assertTrue(collision instanceof SMB2Echo);
                assertFalse(collision == request);
                assertEquals(initialMessageId + i, collision.getHeader().getMessageId());
                assertEquals(0, collision.getHeader().getSessionId());
                assertFalse(collision.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SIGNED));
            }
            assertSame(request, writes.get(2));
            assertEquals(acceptedMessageId, request.getHeader().getMessageId());
            test.assertNoOutstandingRequests();
        }
    }

    @Test
    void collisionTimeoutRetiresBothRequestLookupsBeforeSendAndReceiveThrows() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport);
        try {
            connection.sequenceWindow.creditsGranted(8);
            Request unrelated = new Request(new SMB2Echo(SMB2Dialect.SMB_3_1_1), 99, UUID.randomUUID());
            connection.outstandingRequests.registerOutstanding(unrelated);

            assertThrows(TransportException.class,
                    () -> connection.sendAndReceive(new SMB2Echo(SMB2Dialect.SMB_3_1_1), messageId -> false));
            assertSame(unrelated, connection.outstandingRequests.getRequestByMessageId(99L));
            assertFalse(unrelated.getPromise().isFulfilled());
            assertEquals(1, connection.sequenceWindow.available(), "A failed batch leaves a credit for unrelated traffic");
            assertEquals(8, connection.nextMessageId(), "Every unacknowledged probe MID remains burned");

            respondToEcho(connection, 0);
            assertEquals(1, connection.sequenceWindow.available(), "A late retired reply cannot grant credits");
            doAnswer(invocation -> {
                SMB2Packet sent = invocation.getArgument(0);
                respondToEcho(connection, sent.getHeader().getMessageId());
                return null;
            }).when(transport).write(any());
            SMB2Echo response = connection.sendAndReceive(new SMB2Echo(SMB2Dialect.SMB_3_1_1), messageId -> true);
            assertEquals(8, response.getHeader().getMessageId());
            assertSame(unrelated, connection.outstandingRequests.getRequestByMessageId(99L));
            connection.outstandingRequests.remove(99L);
            assertNoOutstandingRequests(connection);
        } finally {
            connection.close(true);
        }
    }

    @Test
    void pipelinesAtMost32ProbesAndWaitsForEveryReplyBeforePublishingTheRequest() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport, 5000);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        List<SMB2Packet> writes = new CopyOnWriteArrayList<>();
        CountDownLatch firstBatch = new CountDownLatch(32);
        AtomicBoolean released = new AtomicBoolean();
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1), unrelated = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        try {
            connection.sequenceWindow.creditsGranted(64);
            doAnswer(invocation -> {
                SMB2Packet packet = invocation.getArgument(0); writes.add(packet);
                if (packet == request || packet == unrelated || released.get()) respondToEcho(connection, packet.getHeader().getMessageId());
                else firstBatch.countDown();
                return null;
            }).when(transport).write(any());
            Future<SMB2Echo> response = worker.submit(() -> connection.sendAndReceive(request, mid -> mid >= 40));
            assertTrue(firstBatch.await(5, TimeUnit.SECONDS), "Several probes must be sent before the first reply");
            assertEquals(32, writes.size(), "Bounded unanswered batch");
            assertEquals(32, connection.sendAndReceive(unrelated).getHeader().getMessageId(), "Another sender can allocate while probes wait");
            for (long mid = 31; mid > 0; mid--) respondToEcho(connection, mid);
            assertFalse(response.isDone()); assertFalse(writes.contains(request), "One missing probe still prevents publication");
            released.set(true); respondToEcho(connection, 0);
            assertEquals(40, response.get(5, TimeUnit.SECONDS).getHeader().getMessageId());
            assertEquals(41, writes.size());
            for (int index = 0; index < writes.size(); index++) assertEquals(index, writes.get(index).getHeader().getMessageId());
            assertNoOutstandingRequests(connection);
        } finally { worker.shutdownNow(); connection.close(true); }
    }

    @Test
    void oneCreditConnectionWaitsForEachProbeAndResumesWhenCreditsReturn() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport, 5000);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        List<SMB2Packet> writes = new CopyOnWriteArrayList<>();
        CountDownLatch firstProbe = new CountDownLatch(1);
        AtomicBoolean released = new AtomicBoolean();
        try {
            doAnswer(invocation -> {
                SMB2Packet packet = invocation.getArgument(0);
                writes.add(packet);
                if (released.get()) respondToEcho(connection, packet.getHeader().getMessageId());
                else firstProbe.countDown();
                return null;
            }).when(transport).write(any());
            Future<SMB2Echo> response = worker.submit(() -> connection.sendAndReceive(new SMB2Echo(SMB2Dialect.SMB_3_1_1), mid -> mid >= 3));
            assertTrue(firstProbe.await(5, TimeUnit.SECONDS));
            assertEquals(1, writes.size());
            assertEquals(1, connection.nextMessageId());
            assertEquals(0, connection.sequenceWindow.available());
            released.set(true);
            respondToEcho(connection, 0);
            assertEquals(3, response.get(5, TimeUnit.SECONDS).getHeader().getMessageId());
            assertEquals(4, writes.size());
            assertEquals(1, connection.sequenceWindow.available());
            assertNoOutstandingRequests(connection);
        } finally {
            worker.shutdownNow();
            connection.close(true);
        }
    }

    @Test
    void acceptedButUnpublishedReservationStaysBurnedWhenItsProbeBatchTimesOut() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport);
        Session signingState = new Session(null, null, null, null, null, null, null);
        signingState.initializeOriginalKeyMessageIdReservation(2);
        List<SMB2Packet> writes = new ArrayList<>();
        doAnswer(invocation -> { writes.add(invocation.getArgument(0)); return null; }).when(transport).write(any());
        SMB2Echo request = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        try {
            connection.sequenceWindow.creditsGranted(8);
            assertThrows(TransportException.class, () -> connection.sendAndReceive(request, signingState::reserveOriginalKeyMessageId));
            assertEquals(2, writes.size()); assertFalse(writes.contains(request));
            assertEquals(3, connection.nextMessageId());
            assertFalse(signingState.reserveOriginalKeyMessageId(2), "An allocated request is burned even if probe failure prevents signing/writing");
            assertNoOutstandingRequests(connection);
        } finally { connection.close(true); }
    }

    @Test
    void interruptRetiresTheWholeBatchAndPreservesTheInterruptFlag() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport, 5000);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        CountDownLatch written = new CountDownLatch(8);
        AtomicReference<Thread> sender = new AtomicReference<>();
        AtomicBoolean interrupted = new AtomicBoolean();
        try {
            connection.sequenceWindow.creditsGranted(8);
            doAnswer(invocation -> { written.countDown(); return null; }).when(transport).write(any());
            Future<?> response = worker.submit(() -> {
                sender.set(Thread.currentThread());
                try { return connection.sendAndReceive(new SMB2Echo(SMB2Dialect.SMB_3_1_1), mid -> false); }
                finally { interrupted.set(Thread.currentThread().isInterrupted()); }
            });
            assertTrue(written.await(5, TimeUnit.SECONDS)); sender.get().interrupt();
            ExecutionException failure = assertThrows(ExecutionException.class, () -> response.get(5, TimeUnit.SECONDS));
            assertTrue(failure.getCause() instanceof TransportException); assertTrue(interrupted.get());
            assertEquals(1, connection.sequenceWindow.available()); assertNoOutstandingRequests(connection);
        } finally { worker.shutdownNow(); connection.close(true); }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void reservationFailureRetiresOnlyItsPendingBatch(boolean error) throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport);
        Throwable failure = error ? new AssertionError("Reservation failed") : new IllegalStateException("Reservation failed");
        try {
            connection.sequenceWindow.creditsGranted(8);
            assertSame(failure, assertThrows(failure.getClass(), () -> connection.sendAndReceive(new SMB2Echo(SMB2Dialect.SMB_3_1_1), mid -> {
                if (mid == 5) {
                    if (error) throw (AssertionError) failure;
                    throw (IllegalStateException) failure;
                }
                return false;
            })));
            assertEquals(5, connection.nextMessageId()); assertEquals(4, connection.sequenceWindow.available());
            assertNoOutstandingRequests(connection); verify(transport, never()).disconnect();
        } finally { connection.close(true); }
    }

    @Test
    void abortRetiresAnOutstandingCollisionEcho() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        CountDownLatch written = new CountDownLatch(1);
        try {
            connection.sequenceWindow.creditsGranted(8);
            doAnswer(invocation -> {
                written.countDown();
                return null;
            }).when(transport).write(any());
            Future<SMB2Echo> response = worker.submit(() -> connection.sendAndReceive(new SMB2Echo(SMB2Dialect.SMB_3_1_1), messageId -> false));
            assertTrue(written.await(5, TimeUnit.SECONDS));

            connection.handleError(new TransportException("Abort during collision ECHO"));

            ExecutionException failure = assertThrows(ExecutionException.class, () -> response.get(5, TimeUnit.SECONDS));
            assertTrue(failure.getCause() instanceof TransportException);
            assertNoOutstandingRequests(connection);
        } finally {
            worker.shutdownNow();
            connection.close(true);
        }
    }

    @Test
    void terminalMessageIdFailsWithoutSendingAnEchoOrWrapping() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport);
        try {
            Field lowestAvailableField = SequenceWindow.class.getDeclaredField("lowestAvailable");
            lowestAvailableField.setAccessible(true);
            ((AtomicLong) lowestAvailableField.get(connection.sequenceWindow)).set(-1);
            connection.sequenceWindow.creditsGranted(8);

            assertThrows(TransportException.class,
                    () -> connection.sendAndReceive(new SMB2Echo(SMB2Dialect.SMB_3_1_1), messageId -> false));

            verify(transport, never()).write(any());
            assertNoOutstandingRequests(connection);
        } finally {
            connection.close(true);
        }
    }

    @Test
    void terminalMessageIdRetiresAnEarlierProbeInTheBatchWithoutWrapping() throws Exception {
        TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        when(transport.isConnected()).thenReturn(true);
        Connection connection = connectionWithTransport(transport);
        List<SMB2Packet> writes = new ArrayList<>();
        doAnswer(invocation -> { writes.add(invocation.getArgument(0)); return null; }).when(transport).write(any());
        try {
            Field lowestAvailableField = SequenceWindow.class.getDeclaredField("lowestAvailable");
            lowestAvailableField.setAccessible(true);
            ((AtomicLong) lowestAvailableField.get(connection.sequenceWindow)).set(-2);
            connection.sequenceWindow.creditsGranted(8);
            assertThrows(TransportException.class,
                    () -> connection.sendAndReceive(new SMB2Echo(SMB2Dialect.SMB_3_1_1), mid -> false));
            assertEquals(1, writes.size());
            assertEquals(-2, writes.get(0).getHeader().getMessageId());
            assertEquals(-1, connection.nextMessageId());
            assertNoOutstandingRequests(connection);
        } finally {
            connection.close(true);
        }
    }

    @Test
    void collisionEchoConsumesOneCreditBeforeAMultiCreditRequest() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            List<SMB2Packet> writes = new ArrayList<>();
            TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
            when(transport.isConnected()).thenReturn(true);
            doAnswer(invocation -> {
                SMB2Packet sent = invocation.getArgument(0);
                writes.add(sent);
                SMB2Echo response = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
                response.getHeader().setMessageId(sent.getHeader().getMessageId());
                response.getHeader().setCreditResponse(1);
                response.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
                byte[] frame = AbortTestConnection.frame(response);
                test.connection.handle(new SMB2PacketData(Arrays.copyOfRange(frame, 4, frame.length)));
                return null;
            }).when(transport).write(any());
            test.connection.transport.disconnect();
            test.connection.transport = transport;
            test.connection.getConnectionContext().getServerCapabilities().add(com.hierynomus.mssmb2.SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU);
            test.connection.sequenceWindow.creditsGranted(16);
            Field lowestAvailableField = SequenceWindow.class.getDeclaredField("lowestAvailable");
            lowestAvailableField.setAccessible(true);
            AtomicLong lowestAvailable = (AtomicLong) lowestAvailableField.get(test.connection.sequenceWindow);
            long initialMessageId = lowestAvailable.get();

            SMB2Echo request = spy(new SMB2Echo(SMB2Dialect.SMB_3_1_1));
            when(request.getMaxPayloadSize()).thenReturn(3 * SMB2Packet.SINGLE_CREDIT_PAYLOAD_SIZE);
            SMB2Echo response = test.connection.sendAndReceive(request, messageId -> messageId >= initialMessageId + 1);

            assertEquals(initialMessageId + 1, response.getHeader().getMessageId());
            assertEquals(2, writes.size(), writes.toString());
            assertEquals(1, writes.get(0).getHeader().getCreditCharge());
            assertSame(request, writes.get(1));
            assertEquals(3, request.getCreditsAssigned());
            assertEquals(initialMessageId + 4, lowestAvailable.get());
            test.assertNoOutstandingRequests();
        }
    }

    private static Connection connectionWithTransport(TransportLayer<SMBPacket<?, ?>> transport) throws Exception {
        return connectionWithTransport(transport, 20);
    }

    private static Connection connectionWithTransport(TransportLayer<SMBPacket<?, ?>> transport, long timeoutMillis) throws Exception {
        SmbConfig config = SmbConfig.builder().withTransactTimeout(timeoutMillis, TimeUnit.MILLISECONDS)
                .withTransportLayerFactory((handlers, settings) -> transport).build();
        Connection connection = new Connection(config, null, new SMBEventBus(), new ServerList());
        ConnectionContext context = mock(ConnectionContext.class);
        when(context.getServer()).thenReturn(new Server("localhost", 445));
        when(context.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
        Field contextField = Connection.class.getDeclaredField("connectionContext");
        contextField.setAccessible(true);
        contextField.set(connection, context);
        return connection;
    }

    private static void respondToEcho(Connection connection, long messageId) throws Exception {
        SMB2Echo response = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        response.getHeader().setMessageId(messageId);
        response.getHeader().setCreditResponse(1);
        response.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
        byte[] frame = AbortTestConnection.frame(response);
        connection.handle(new SMB2PacketData(Arrays.copyOfRange(frame, 4, frame.length)));
    }

    private static void assertNoOutstandingRequests(Connection connection) throws Exception {
        for (String name : new String[] {"lookup", "cancelLookup"}) {
            Field field = OutstandingRequests.class.getDeclaredField(name);
            field.setAccessible(true);
            assertTrue(((Map<?, ?>) field.get(connection.outstandingRequests)).isEmpty(), name);
        }
    }
}
