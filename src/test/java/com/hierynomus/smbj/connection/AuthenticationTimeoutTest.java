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
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB2MessageConverter;
import com.hierynomus.smbj.connection.packet.SMB2AsyncResponsePacketHandler;
import com.hierynomus.smbj.connection.packet.SMB2ProcessResponsePacketHandler;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode;
import com.hierynomus.mssmb2.SMB2GlobalCapability;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;
import java.util.EnumSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuthenticationTimeoutTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void abandonedSetupRetiresOnlyItsRequestAndPreservesInterruption(boolean interrupt) throws Exception {
        try (Fixture fixture = new Fixture()) {
            Request other = fixture.registerOther();
            fixture.interruptOnWrite = interrupt;
            try {
                assertThrows(TransportException.class, () -> fixture.connection.sendAndReceive(setup()));
                assertEquals(interrupt, Thread.currentThread().isInterrupted());
            } finally { Thread.interrupted(); }
            Request abandoned = fixture.sent.get();
            assertNotNull(abandoned);
            assertFalse(fixture.connection.outstandingRequests.isOutstanding(abandoned.getMessageId()));
            assertNull(fixture.connection.outstandingRequests.getRequestByCancelId(abandoned.getCancelId()));
            assertTrue(abandoned.getPromise().isFulfilled());
            assertThrows(ExecutionException.class, () -> abandoned.getFuture(() -> { }).get(1, TimeUnit.SECONDS));
            assertSame(other, fixture.connection.outstandingRequests.getRequestByMessageId(99L));
            assertFalse(other.getPromise().isFulfilled());
            assertEquals(8, fixture.connection.sequenceWindow.available(), "Cleanup must not invent missing response credits");
            assertTrue(fixture.transport.isConnected());
        }
    }

    @Test
    void lateSetupAfterTimeoutIsIgnoredWithoutClosingTransportOrAcceptingCredits() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.registerOther();
            assertThrows(TransportException.class, () -> fixture.connection.sendAndReceive(setup()));
            fixture.connection.handle(new SMB2PacketData(setupResponse(0)));
            assertFalse(fixture.connection.outstandingRequests.isOutstanding(0L));
            assertTrue(fixture.sent.get().getPromise().isFulfilled());
            assertThrows(ExecutionException.class, () -> fixture.sent.get().getFuture(() -> { }).get(1, TimeUnit.SECONDS));
            assertSame(fixture.older, fixture.connection.getSessionTable().find(47L));
            assertEquals(8, fixture.connection.sequenceWindow.available());
            verify(fixture.transport, never()).disconnect();
        }
    }

    @Test
    void ordinaryOperationTimeoutKeepsItsOutstandingResponseContract() throws Exception {
        try (Fixture fixture = new Fixture()) {
            assertThrows(TransportException.class, () -> fixture.connection.sendAndReceive(new SMB2Echo(SMB2Dialect.SMB_3_1_1)));
            assertSame(fixture.sent.get(), fixture.connection.outstandingRequests.getRequestByMessageId(0L));
            assertFalse(fixture.sent.get().getPromise().isFulfilled());
        }
    }

    @Test
    void timeoutDuringResponseParsingCannotCompleteOrAbortAnAbandonedRequest() throws Exception {
        OutstandingRequests requests = new OutstandingRequests();
        Request request = new Request(setup(), 0, UUID.randomUUID());
        requests.registerOutstanding(request);
        SMB2PacketData data = new SMB2PacketData(setupResponse(0));
        SMB2MessageConverter converter = mock(SMB2MessageConverter.class);
        CountDownLatch parsing = new CountDownLatch(1), release = new CountDownLatch(1);
        when(converter.readPacket(same(request.getPacket()), same(data))).thenAnswer(call -> {
            parsing.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            return new SMB2SessionSetup();
        });
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            Future<?> processing = worker.submit(() -> {
                new SMB2ProcessResponsePacketHandler(converter, requests).handle(data); return null;
            });
            assertTrue(parsing.await(5, TimeUnit.SECONDS));
            assertSame(request, requests.remove(0L));
            request.getPromise().deliverError(new TimeoutException("abandoned authentication"));
            release.countDown(); processing.get(5, TimeUnit.SECONDS);
            assertFalse(request.getPromise().isDelivered());
            assertTrue(request.getPromise().isFulfilled());
            assertNull(requests.getRequestByCancelId(request.getCancelId()));
            assertNull(requests.remove(0L));
            assertThrows(SMBRuntimeException.class, () -> requests.receivedResponseFor(0L));
        } finally {
            release.countDown(); worker.shutdownNow();
            assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void requestRetiredBeforeLaterPipelineLookupIsIgnored() throws Exception {
        OutstandingRequests requests = new OutstandingRequests();
        SMB2PacketData data = new SMB2PacketData(setupResponse(0));
        SMB2MessageConverter converter = mock(SMB2MessageConverter.class);
        new SMB2AsyncResponsePacketHandler(requests).handle(data);
        new SMB2ProcessResponsePacketHandler(converter, requests).handle(data);
        verifyNoInteractions(converter);
    }

    private static SMB2SessionSetup setup() {
        return new SMB2SessionSetup(SMB2Dialect.SMB_3_1_1, EnumSet.of(SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED),
                EnumSet.noneOf(SMB2GlobalCapability.class));
    }

    private static byte[] setupResponse(long mid) {
        ByteBuffer bytes = ByteBuffer.allocate(72).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putInt(0, 0x424d53fe); bytes.putShort(4, (short) 64);
        bytes.putShort(12, (short) 1); bytes.putShort(14, (short) 64);
        bytes.putInt(16, 1); bytes.putLong(24, mid); bytes.putLong(40, 47);
        bytes.putShort(64, (short) 9); bytes.putShort(68, (short) 72);
        return bytes.array();
    }

    private static final class Fixture implements AutoCloseable {
        final TransportLayer<SMBPacket<?, ?>> transport;
        final Connection connection;
        final Session older = mock(Session.class);
        boolean interruptOnWrite;
        final AtomicReference<Request> sent = new AtomicReference<>();

        @SuppressWarnings("unchecked")
        Fixture() throws Exception {
            transport = mock(TransportLayer.class);
            when(transport.isConnected()).thenReturn(true);
            SmbConfig config = SmbConfig.builder().withTransactTimeout(20, TimeUnit.MILLISECONDS)
                    .withTransportLayerFactory((handlers, settings) -> transport).build();
            connection = new Connection(config, null, new SMBEventBus(), new ServerList());
            ConnectionContext context = mock(ConnectionContext.class);
            when(context.getServer()).thenReturn(new Server("localhost", 445));
            when(context.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
            Field field = Connection.class.getDeclaredField("connectionContext"); field.setAccessible(true); field.set(connection, context);
            connection.sequenceWindow.creditsGranted(8);
            connection.getSessionTable().registerSession(47L, older);
            doAnswer(call -> {
                SMB2Packet packet = call.getArgument(0);
                sent.set(connection.outstandingRequests.getRequestByMessageId(packet.getHeader().getMessageId()));
                if (interruptOnWrite) Thread.currentThread().interrupt();
                return null;
            }).when(transport).write(any());
        }

        Request registerOther() throws Exception {
            Request other = new Request(new SMB2Echo(SMB2Dialect.SMB_3_1_1), 99, UUID.randomUUID());
            connection.outstandingRequests.registerOutstanding(other); return other;
        }

        @Override public void close() throws Exception { connection.close(true); }
    }
}
