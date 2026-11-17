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

import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ChannelRequestsTest {
    @Test
    void creditStarvationAndAbortOfOneSharedSessionChannelLeaveTheOtherUsable() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.primary.sequenceWindow.get(fixture.primary.sequenceWindow.available());
            java.util.concurrent.atomic.AtomicReference<Thread> thread = new java.util.concurrent.atomic.AtomicReference<>();
            java.util.concurrent.FutureTask<TransportException> blocked = AbortTestConnection.task(() -> {
                thread.set(Thread.currentThread());
                return assertThrows(TransportException.class, () -> fixture.session.send(fixture.echo(), fixture.primary));
            });
            AbortTestConnection.await(() -> thread.get() != null && thread.get().getState() == Thread.State.TIMED_WAITING);
            SMB2Echo healthy = fixture.echo();
            Future<SMB2Packet> response = fixture.session.send(healthy, fixture.secondary);
            fixture.reply(fixture.secondary, healthy);
            response.get(1, TimeUnit.SECONDS);
            assertFalse(blocked.isDone());
            fixture.primary.close(true);
            assertNotNull(blocked.get(1, TimeUnit.SECONDS));
            assertEquals(1, fixture.session.getChannelCount());
            healthy = fixture.echo();
            response = fixture.session.send(healthy);
            fixture.reply(fixture.secondary, healthy);
            response.get(1, TimeUnit.SECONDS);
            assertTrue(fixture.secondary.isConnected());
            verify(fixture.primaryTransport, never()).write(any());
        }
    }

    // Behavioral regression: go-smb2 7f69f658, TestSessionChannelsRespectIndependentCreditWindows.
    @Test
    void creditsMessageIdsAndOutstandingRequestsBelongToEachConnection() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.primary.sequenceWindow.creditsGranted(2);
            SMB2Echo first = fixture.echo();
            SMB2Echo second = fixture.echo();
            Future<SMB2Packet> firstReply = fixture.session.send(first, fixture.primary);
            Future<SMB2Packet> secondReply = fixture.session.send(second, fixture.secondary);
            assertEquals(0, first.getHeader().getMessageId());
            assertEquals(first.getHeader().getMessageId(), second.getHeader().getMessageId());
            assertEquals(2, fixture.primary.sequenceWindow.available());
            assertEquals(0, fixture.secondary.sequenceWindow.available());
            assertNotSame(fixture.primary.outstandingRequests, fixture.secondary.outstandingRequests);
            fixture.reply(fixture.primary, first);
            firstReply.get(1, TimeUnit.SECONDS);
            assertEquals(4, fixture.primary.sequenceWindow.available());
            assertEquals(0, fixture.secondary.sequenceWindow.available());
            assertFalse(secondReply.isDone());
            assertTrue(fixture.secondary.outstandingRequests.isOutstanding(0L));
            fixture.reply(fixture.secondary, second);
            secondReply.get(1, TimeUnit.SECONDS);
            assertEquals(2, fixture.secondary.sequenceWindow.available());
        }
    }

    // Behavioral regression: go-smb2 7f69f658, TestBoundRequestCancellationUsesOriginalChannel.
    @Test
    void cancellationKeepsTheOwningMessageIdTransportAndCurrentSequence() throws Exception {
        try (Fixture fixture = new Fixture()) {
            SMB2Echo request = fixture.echo();
            Future<SMB2Packet> future = fixture.session.send(request, fixture.secondary);
            fixture.primary.close(true);
            assertTrue(future.cancel(true));
            ArgumentCaptor<SMBPacket> packets = ArgumentCaptor.forClass(SMBPacket.class);
            verify(fixture.secondaryTransport, times(2)).write(packets.capture());
            SMB2Packet cancel = (SMB2Packet) packets.getAllValues().get(1);
            assertEquals(SMB2MessageCommandCode.SMB2_CANCEL, cancel.getHeader().getMessage());
            assertEquals(request.getHeader().getMessageId(), cancel.getHeader().getMessageId());
            assertEquals(1, cancel.getHeader().getChannelSequence());
            verify(fixture.primaryTransport, never()).write(any());
        }
    }

    // Behavioral regression: go-smb2 7f69f658, TestBoundWriteIsNotReplayedAfterConnectionLoss.
    @Test
    void lostWriteResponseFailsOnlyItsConnectionAndIsNeverReplayed() throws Exception {
        try (Fixture fixture = new Fixture()) {
            SMB2WriteRequest write = new SMB2WriteRequest(SMB2Dialect.SMB_3_1_1,
                    new SMB2FileId(new byte[8], new byte[8]), 47, 1, new ArrayByteChunkProvider(new byte[]{1}, 0), 1);
            Future<SMB2Packet> response = fixture.session.send(write, fixture.secondary);
            fixture.secondary.handleError(new TransportException("Response lost after WRITE"));
            ExecutionException failure = assertThrows(ExecutionException.class, () -> response.get(1, TimeUnit.SECONDS));
            Throwable cause = failure;
            while (cause.getCause() != null) cause = cause.getCause();
            assertInstanceOf(TransportException.class, cause);
            assertEquals("Response lost after WRITE", cause.getMessage());
            verify(fixture.secondaryTransport, times(1)).write(write);
            verify(fixture.primaryTransport, never()).write(any());
            SMB2Echo next = fixture.echo();
            Future<SMB2Packet> reply = fixture.session.send(next);
            verify(fixture.primaryTransport).write(next);
            fixture.reply(fixture.primary, next);
            reply.get(1, TimeUnit.SECONDS);
            assertEquals(1, fixture.session.getChannelCount());
        }
    }

    @Test
    void gracefulCloseLogsOffThroughTheLastSurvivingChannel() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.primary.close(true);
            doAnswer(call -> {
                SMB2Packet request = call.getArgument(0);
                assertEquals(SMB2MessageCommandCode.SMB2_LOGOFF, request.getHeader().getMessage());
                com.hierynomus.mssmb2.messages.SMB2Logoff response = new com.hierynomus.mssmb2.messages.SMB2Logoff(SMB2Dialect.SMB_3_1_1, 47);
                response.getHeader().setMessageId(request.getHeader().getMessageId());
                response.getHeader().setCreditRequest(1);
                response.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
                SMBBuffer buffer = new SMBBuffer();
                response.write(buffer);
                fixture.secondary.handle(new SMB2PacketData(buffer.getCompactData()));
                return null;
            }).when(fixture.secondaryTransport).write(any());
            fixture.secondary.close();
            verify(fixture.secondaryTransport).write(any());
            assertTrue(fixture.secondary.isClosed());
            assertEquals(0, fixture.session.getChannelCount());
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void outstandingDurableV2CreateReplaysOnSurvivorWithOriginalPromise(boolean losePrimary) throws Exception {
        try (Fixture fixture = new Fixture()) {
            Connection lost = losePrimary ? fixture.primary : fixture.secondary;
            Connection survivor = losePrimary ? fixture.secondary : fixture.primary;
            TransportLayer<SMBPacket<?, ?>> survivorTransport = losePrimary ? fixture.secondaryTransport : fixture.primaryTransport;
            com.hierynomus.mssmb2.messages.SMB2CreateRequest create = durableCreate();
            SMBBuffer before = new SMBBuffer();
            create.write(before);
            byte[] body = Arrays.copyOfRange(before.getCompactData(), 64, before.wpos());
            Future<SMB2Packet> future = fixture.session.send(create, lost);
            long oldMid = create.getHeader().getMessageId();
            // Give the survivor a distinct MID space so the transfer cannot accidentally reuse ownership.
            survivor.sequenceWindow.get(1);
            survivor.sequenceWindow.creditsGranted(2);
            lost.handleError(new TransportException("Lost durable CREATE response"));
            AbortTestConnection.await(() -> survivor.outstandingRequests.isOutstanding(1L));
            verify(survivorTransport, timeout(2000)).write(argThat(packet -> ((SMB2Packet) packet).getPacket() == create));
            assertFalse(lost.outstandingRequests.isOutstanding(oldMid));
            assertTrue(create.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_REPLAY_OPERATION));
            assertEquals(47, create.getHeader().getSessionId());
            assertEquals(1, create.getHeader().getTreeId());
            assertEquals(1, create.getHeader().getChannelSequence());
            assertEquals(1, fixture.session.getChannelCount());
            assertSame(survivor, fixture.session.getConnection());
            SMBBuffer after = new SMBBuffer();
            create.write(after);
            assertArrayEquals(body, Arrays.copyOfRange(after.getCompactData(), 64, after.wpos()));
            Request replay = survivor.outstandingRequests.getRequestByMessageId(1L);
            fixture.createReply(survivor, 1);
            SMB2Packet response = future.get(2, TimeUnit.SECONDS);
            assertInstanceOf(com.hierynomus.mssmb2.messages.SMB2CreateResponse.class, response);
            fixture.createReply(survivor, 1); // duplicate replay response is discarded
            fixture.createReply(lost, oldMid); // late original response cannot complete twice
            assertSame(response, future.get(1, TimeUnit.SECONDS));
            // Duplicate closure must neither replay the completed CREATE nor advance the sequence twice.
            lost.handleError(new TransportException("Duplicate closure"));
            assertEquals(1, fixture.session.getChannelCount());
            assertTrue(replay.getPromise().isFulfilled());
            verify(survivorTransport, times(1)).write(argThat(packet -> ((SMB2Packet) packet).getPacket() == create));
            SMB2Echo next = fixture.echo();
            fixture.session.send(next, survivor);
            assertEquals(1, next.getHeader().getChannelSequence());
        }
    }

    @Test
    void completedDurableCreateIsNotReplayed() throws Exception {
        try (Fixture fixture = new Fixture()) {
            com.hierynomus.mssmb2.messages.SMB2CreateRequest create = durableCreate();
            Future<SMB2Packet> future = fixture.session.send(create, fixture.primary);
            SMB2Packet response = new com.hierynomus.mssmb2.messages.SMB2CreateResponse();
            fixture.primary.outstandingRequests.receivedResponseFor(create.getHeader().getMessageId()).getPromise().deliver(response);
            fixture.primary.close(true);
            assertSame(response, future.get(1, TimeUnit.SECONDS));
            verify(fixture.secondaryTransport, never()).write(any());
        }
    }

    @Test
    void durableCreateFailsWhenNoChannelSurvives() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.secondary.close(true);
            Future<SMB2Packet> future = fixture.session.send(durableCreate(), fixture.primary);
            fixture.primary.close(true);
            assertThrows(ExecutionException.class, () -> future.get(2, TimeUnit.SECONDS));
            assertEquals(0, fixture.session.getChannelCount());
            assertThrows(TransportException.class, () -> fixture.session.send(fixture.echo()));
        }
    }

    @Test
    void replayedCreateCancellationUsesSurvivingOwner() throws Exception {
        try (Fixture fixture = new Fixture()) {
            com.hierynomus.mssmb2.messages.SMB2CreateRequest create = durableCreate();
            Future<SMB2Packet> future = fixture.session.send(create, fixture.primary);
            fixture.primary.close(true);
            verify(fixture.secondaryTransport, timeout(2000)).write(argThat(packet -> ((SMB2Packet) packet).getPacket() == create));
            assertTrue(future.cancel(true));
            ArgumentCaptor<SMBPacket> packets = ArgumentCaptor.forClass(SMBPacket.class);
            verify(fixture.secondaryTransport, times(2)).write(packets.capture());
            SMB2Packet cancel = (SMB2Packet) packets.getAllValues().get(1);
            assertEquals(SMB2MessageCommandCode.SMB2_CANCEL, cancel.getHeader().getMessage());
            assertEquals(create.getHeader().getMessageId(), cancel.getHeader().getMessageId());
        }
    }

    @Test
    void cancelledDurableCreateIsNotReplayed() throws Exception {
        try (Fixture fixture = new Fixture()) {
            Future<SMB2Packet> future = fixture.session.send(durableCreate(), fixture.primary);
            assertTrue(future.cancel(true));
            fixture.primary.close(true);
            assertThrows(ExecutionException.class, () -> future.get(1, TimeUnit.SECONDS));
            verify(fixture.secondaryTransport, never()).write(any());
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"false,true", "true,true", "true,false"})
    void plaintextReceiveUsesTheReceivingChannelKeyAndRejectsTampering(boolean secondary, boolean valid) throws Exception {
        try (Fixture fixture = new Fixture()) {
            javax.crypto.SecretKey channelKey = new SecretKeySpec(new byte[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "AesCmac");
            fixture.session.addChannel(fixture.secondary, channelKey);
            Connection receiver = secondary ? fixture.secondary : fixture.primary;
            Signatory signatory = mock(Signatory.class);
            javax.crypto.SecretKey expected = secondary ? channelKey : fixture.session.getSessionContext().getSigningKey();
            when(signatory.verify(any(), eq(expected))).thenReturn(valid);
            com.hierynomus.smbj.connection.packet.IncomingPacketHandler next = mock(com.hierynomus.smbj.connection.packet.IncomingPacketHandler.class);
            com.hierynomus.smbj.connection.packet.SMB2SignatureVerificationPacketHandler handler =
                    new com.hierynomus.smbj.connection.packet.SMB2SignatureVerificationPacketHandler(receiver.getSessionTable(), signatory, receiver);
            handler.setNext(next);
            SMB2Echo reply = fixture.echo();
            reply.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SIGNED);
            SMBBuffer wire = new SMBBuffer();
            reply.write(wire);
            SMB2PacketData data = new SMB2PacketData(wire.getCompactData());
            handler.handle(data);
            verify(signatory).verify(data, expected);
            if (valid) verify(next).handle(data);
            else verify(next).handle(isA(DeadLetterPacketData.class));
        }
    }

    private static com.hierynomus.mssmb2.messages.SMB2CreateRequest durableCreate() {
        return new com.hierynomus.mssmb2.messages.SMB2CreateRequest(SMB2Dialect.SMB_3_1_1, 47, 1,
                com.hierynomus.mssmb2.SMB2ImpersonationLevel.Impersonation,
                java.util.EnumSet.of(com.hierynomus.msdtyp.AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_CREATE, null, new com.hierynomus.smbj.common.SmbPath("localhost", "share", "durable"),
                SMB2OplockLevel.SMB2_OPLOCK_LEVEL_BATCH, java.util.Collections.singletonList(
                new com.hierynomus.mssmb2.messages.create.SMB2CreateContext(new byte[]{'D', 'H', '2', 'Q'}, new byte[32])));
    }

    private static class Fixture implements AutoCloseable {
        @SuppressWarnings("unchecked")
        final TransportLayer<SMBPacket<?, ?>> primaryTransport = mock(TransportLayer.class);
        @SuppressWarnings("unchecked")
        final TransportLayer<SMBPacket<?, ?>> secondaryTransport = mock(TransportLayer.class);
        final Connection primary;
        final Connection secondary;
        final Session session;

        Fixture() throws Exception {
            Queue<TransportLayer<SMBPacket<?, ?>>> transports = new ArrayDeque<>(Arrays.asList(primaryTransport, secondaryTransport));
            SmbConfig config = SmbConfig.builder()
                    .withTransportLayerFactory((handlers, settings) -> transports.remove()).build();
            SMBEventBus bus = new SMBEventBus();
            primary = new Connection(config, null, bus, new ServerList());
            secondary = new Connection(config, null, bus, new ServerList());
            Field context = Connection.class.getDeclaredField("connectionContext");
            context.setAccessible(true);
            for (Connection connection : Arrays.asList(primary, secondary)) {
                ConnectionContext state = mock(ConnectionContext.class);
                when(state.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
                when(state.getServer()).thenReturn(new Server("localhost", 445));
                context.set(connection, state);
            }
            when(primaryTransport.isConnected()).thenReturn(true);
            when(secondaryTransport.isConnected()).thenReturn(true);
            session = new Session(primary, config, null, bus, null, new NoSignatory(), null);
            session.setSessionId(47);
            session.getSessionContext().setSigningKey(new SecretKeySpec(new byte[16], "AesCmac"));
            session.addChannel(secondary, new SecretKeySpec(new byte[16], "AesCmac"));
            primary.getSessionTable().registerSession(47L, session);
            secondary.getSessionTable().registerSession(47L, session);
        }

        SMB2Echo echo() {
            SMB2Echo result = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
            result.getHeader().setSessionId(47);
            return result;
        }

        void createReply(Connection connection, long messageId) throws Exception {
            SMB2PacketHeader header = new SMB2PacketHeader();
            header.setDialect(SMB2Dialect.SMB_3_1_1);
            header.setMessageType(SMB2MessageCommandCode.SMB2_CREATE);
            header.setMessageId(messageId);
            header.setSessionId(47);
            header.setTreeId(1);
            header.setCreditRequest(1);
            header.setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
            SMBBuffer wire = new SMBBuffer();
            header.writeTo(wire);
            wire.putUInt16(89);
            wire.putByte((byte) 0);
            wire.putByte((byte) 0);
            wire.putUInt32(1);
            wire.putReserved(56);
            wire.putRawBytes(new byte[16]);
            wire.putUInt32(0);
            wire.putUInt32(0);
            connection.handle(new SMB2PacketData(wire.getCompactData()));
        }

        void reply(Connection connection, SMB2Echo request) throws Exception {
            SMB2Echo response = echo();
            response.getHeader().setMessageId(request.getHeader().getMessageId());
            response.getHeader().setCreditRequest(1);
            response.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
            SMBBuffer buffer = new SMBBuffer();
            response.write(buffer);
            connection.handle(new SMB2PacketData(buffer.getCompactData()));
        }

        @Override
        public void close() throws Exception {
            try { primary.close(true); }
            finally { secondary.close(true); }
        }
    }
}
