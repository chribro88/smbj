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
    void forcedEncryptionUsesSurvivingChannelAndRejectsPlainFinalResponse() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.session.getSessionContext().setEncryptionKey(new SecretKeySpec(new byte[16], "AES"));
            fixture.primary.close(true);
            SMB2Echo request = fixture.echo();
            Future<SMB2Packet> response = fixture.session.send(request, true);
            assertTrue(fixture.secondary.outstandingRequests.getRequestByMessageId(request.getSequenceNumber()).isEncrypted());
            ArgumentCaptor<SMBPacket> packets = ArgumentCaptor.forClass(SMBPacket.class);
            verify(fixture.secondaryTransport).write(packets.capture());
            SMBBuffer wire = new SMBBuffer();
            packets.getValue().write(wire);
            assertArrayEquals(SMB2TransformHeader.ENCRYPTED_PROTOCOL_ID, Arrays.copyOf(wire.array(), 4));
            verify(fixture.primaryTransport, never()).write(any());
            TransportException failure = assertThrows(TransportException.class, () -> fixture.reply(fixture.secondary, request));
            assertTrue(failure.getMessage().contains("Unencrypted final response"));
            assertSame(failure, AbortTestConnection.transportFailure(response));
            assertTrue(fixture.secondary.isClosed());
        }
    }

    @Test
    void forcedEncryptionCannotBypassSessionInvalidation() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.session.getSessionContext().setEncryptionKey(new SecretKeySpec(new byte[16], "AES"));
            fixture.session.failChannels(new TransportException("uncertain write"));
            assertThrows(TransportException.class, () -> fixture.session.send(fixture.echo(), true));
            verify(fixture.primaryTransport, never()).write(any());
            verify(fixture.secondaryTransport, never()).write(any());
        }
    }

    @Test
    void secondaryResponseUsesItsChannelSigningKey() throws Exception {
        try (Fixture fixture = new Fixture()) {
            byte[] keyBytes = new byte[16];
            Arrays.fill(keyBytes, (byte) 7);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AesCmac");
            fixture.session.addChannel(fixture.secondary, key);
            fixture.session.getSessionContext().setSigningRequired(true);
            SMB2Echo request = fixture.echo();
            Future<SMB2Packet> response = fixture.session.send(request, fixture.secondary);
            SMB2Echo reply = fixture.echo();
            reply.getHeader().setMessageId(request.getSequenceNumber());
            reply.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
            SMBBuffer wire = new SMBBuffer();
            new PacketSignatory(SmbConfig.createDefaultConfig().getSecurityProvider()).sign(reply, key).write(wire);
            fixture.secondary.handle(new SMB2PacketData(wire.getCompactData()));
            assertEquals(request.getSequenceNumber(), response.get(1, TimeUnit.SECONDS).getSequenceNumber());
        }
    }

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
            PacketEncryptor encryptor = new PacketEncryptor(config.getSecurityProvider());
            when(primary.getConnectionContext().getCipherId()).thenReturn(SMB3EncryptionCipher.AES_128_GCM);
            encryptor.init(primary.getConnectionContext());
            session = new Session(primary, config, null, bus, null, new NoSignatory(), encryptor);
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
