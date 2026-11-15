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
import com.hierynomus.mssmb2.messages.SMB2Logoff;
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
import org.junit.jupiter.params.provider.CsvSource;

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
    @CsvSource({"false,false,false", "true,false,false", "false,true,false", "true,true,false",
            "false,false,true", "true,false,true", "false,true,true", "true,true,true"})
    void abandonedExchangeRetiresOnlyItsRequestAndPreservesInterruption(boolean interrupt, boolean withSession, boolean logoff) throws Exception {
        try (Fixture fixture = new Fixture()) {
            Request other = fixture.registerOther();
            fixture.interruptOnWrite = interrupt;
            when(fixture.older.send(any(SMB2Packet.class), same(fixture.connection)))
                    .thenAnswer(call -> fixture.connection.send(call.getArgument(0)));
            SMB2Packet packet = logoff ? new SMB2Logoff(SMB2Dialect.SMB_3_1_1, 47) : setup();
            try {
                assertThrows(TransportException.class, () -> {
                    if (withSession) fixture.connection.sendAndReceive(fixture.older, packet);
                    else fixture.connection.sendAndReceive(packet);
                });
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

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void lateExchangeAfterTimeoutIsIgnoredWithoutClosingTransportOrAcceptingCredits(boolean logoff) throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.registerOther();
            SMB2Packet packet = logoff ? new SMB2Logoff(SMB2Dialect.SMB_3_1_1, 47) : setup();
            assertThrows(TransportException.class, () -> fixture.connection.sendAndReceive(packet));
            fixture.connection.handle(new SMB2PacketData(response(0, logoff)));
            assertFalse(fixture.connection.outstandingRequests.isOutstanding(0L));
            assertTrue(fixture.sent.get().getPromise().isFulfilled());
            assertThrows(ExecutionException.class, () -> fixture.sent.get().getFuture(() -> { }).get(1, TimeUnit.SECONDS));
            assertSame(fixture.older, fixture.connection.getSessionTable().find(47L));
            assertEquals(8, fixture.connection.sequenceWindow.available());
            verify(fixture.transport, never()).disconnect();
        }
    }

    @Test
    void sessionCloseRetiresItsLogoffAndIgnoresTheLateReplyAfterRemovingItsKeys() throws Exception {
        try (Fixture fixture = new Fixture()) {
            Session closing = new Session(fixture.connection, fixture.config, null, fixture.bus, null, new NoSignatory(), null);
            closing.setSessionId(48);
            fixture.connection.getSessionTable().registerSession(48L, closing);
            assertThrows(TransportException.class, closing::close);
            Request request = fixture.sent.get();
            assertTrue(request.getPacket() instanceof SMB2Logoff);
            assertNull(fixture.connection.outstandingRequests.getRequestByMessageId(request.getMessageId()));
            assertNull(fixture.connection.outstandingRequests.getRequestByCancelId(request.getCancelId()));
            assertTrue(request.getPromise().isFulfilled());
            assertNull(fixture.connection.getSessionTable().find(48L));
            byte[] late = response(request.getMessageId(), true);
            ByteBuffer.wrap(late).order(ByteOrder.LITTLE_ENDIAN).putLong(40, 48);
            fixture.connection.handle(new SMB2PacketData(late));
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

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void timeoutDuringResponseParsingCannotCompleteOrAbortAnAbandonedRequest(boolean logoff) throws Exception {
        OutstandingRequests requests = new OutstandingRequests();
        Request request = new Request(logoff ? new SMB2Logoff(SMB2Dialect.SMB_3_1_1, 47) : setup(), 0, UUID.randomUUID());
        requests.registerOutstanding(request);
        SMB2PacketData data = new SMB2PacketData(response(0, logoff));
        SMB2MessageConverter converter = mock(SMB2MessageConverter.class);
        CountDownLatch parsing = new CountDownLatch(1), release = new CountDownLatch(1);
        when(converter.readPacket(same(request.getPacket()), same(data))).thenAnswer(call -> {
            parsing.countDown();
            assertTrue(release.await(5, TimeUnit.SECONDS));
            return logoff ? new SMB2Logoff(SMB2Dialect.SMB_3_1_1, 47) : new SMB2SessionSetup();
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

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void requestRetiredBeforeLaterPipelineLookupIsIgnored(boolean logoff) throws Exception {
        OutstandingRequests requests = new OutstandingRequests();
        SMB2PacketData data = new SMB2PacketData(response(0, logoff));
        SMB2MessageConverter converter = mock(SMB2MessageConverter.class);
        new SMB2AsyncResponsePacketHandler(requests).handle(data);
        new SMB2ProcessResponsePacketHandler(converter, requests).handle(data);
        verifyNoInteractions(converter);
    }

    private static SMB2SessionSetup setup() {
        return new SMB2SessionSetup(SMB2Dialect.SMB_3_1_1, EnumSet.of(SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED),
                EnumSet.noneOf(SMB2GlobalCapability.class));
    }

    private static byte[] response(long mid, boolean logoff) {
        ByteBuffer bytes = ByteBuffer.allocate(72).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putInt(0, 0x424d53fe); bytes.putShort(4, (short) 64);
        bytes.putShort(12, (short) (logoff ? 2 : 1)); bytes.putShort(14, (short) 64);
        bytes.putInt(16, 1); bytes.putLong(24, mid); bytes.putLong(40, 47);
        bytes.putShort(64, (short) (logoff ? 4 : 9)); bytes.putShort(68, (short) 72);
        return bytes.array();
    }

    private static final class Fixture implements AutoCloseable {
        final TransportLayer<SMBPacket<?, ?>> transport;
        final Connection connection;
        final SMBEventBus bus = new SMBEventBus();
        final SmbConfig config;
        final Session older = mock(Session.class);
        boolean interruptOnWrite;
        final AtomicReference<Request> sent = new AtomicReference<>();

        @SuppressWarnings("unchecked")
        Fixture() throws Exception {
            transport = mock(TransportLayer.class);
            when(transport.isConnected()).thenReturn(true);
            config = SmbConfig.builder().withTransactTimeout(20, TimeUnit.MILLISECONDS)
                    .withTransportLayerFactory((handlers, settings) -> transport).build();
            connection = new Connection(config, null, bus, new ServerList());
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
