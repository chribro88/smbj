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
package com.hierynomus.smbj.share;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smb.*;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.*;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.testing.StubAuthenticator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SMBChannelAdmissionTest {
    private static final int MIB = 1048576;
    private static final int K128 = 131072;
    private static final SMB2Dialect DIALECT = SMB2Dialect.SMB_3_1_1;
    private static final SMB2FileId FILE_ID = new SMB2FileId(new byte[8], new byte[8]);

    enum Operation { READ, WRITE, TRANSACT }

    static Stream<Arguments> limits() {
        // Adapted invariant: go-smb2 7f69f658, x/protocol/channel.go validateChannel.
        // SMBJ uses min(original configuration, original negotiation), rather than Go's raw maxima.
        return Arrays.stream(Operation.values()).flatMap(operation -> Stream.of(
                Arguments.of(operation, MIB, MIB, K128, K128, false),
                Arguments.of(operation, MIB, MIB, MIB, K128, true),
                Arguments.of(operation, MIB, K128, K128, K128, true),
                Arguments.of(operation, MIB, K128, MIB, MIB, true),
                Arguments.of(operation, K128, MIB, K128, MIB, true),
                Arguments.of(operation, MIB, MIB, MIB - 1, MIB, false),
                Arguments.of(operation, MIB, MIB, MIB - 1, K128, false)));
    }

    @ParameterizedTest
    @MethodSource("limits")
    void checksEstablishedLimitsAndActualCandidateWire(Operation operation, int originalMax, int originalConfig,
            int candidateMax, int candidateConfig, boolean admitted) throws Exception {
        try (Fixture fixture = new Fixture(operation, originalMax, originalConfig, candidateMax, candidateConfig)) {
            DiskShare before = (DiskShare) fixture.session.connectShare("before");
            File existing = fixture.open(before);
            int expected = Math.min(originalMax, originalConfig);
            if (!admitted) {
                IOException failure = assertThrows(IOException.class, () -> fixture.candidate.bind(fixture.session));
                assertTrue(failure.getMessage().contains("SMB channel"));
                assertEquals(0, fixture.candidateWire.bindings);
                verifyNoInteractions(fixture.candidateSigner);
                assertTrue(fixture.candidateTable().activeSessions().isEmpty());
                assertEquals(1, fixture.session.getChannelCount());
                assertFalse(fixture.candidate.isClosed(), "Direct bind does not own the rejected candidate");
                fixture.request(operation, before, existing, expected, fixture.primaryWire);
            } else {
                assertSame(fixture.session, fixture.candidate.bind(fixture.session));
                assertEquals(1, fixture.candidateWire.bindings);
                assertEquals(2, fixture.session.getChannelCount());
                // Pin the actual request to the admitted connection. Primary-only traffic cannot prove this case.
                doAnswer(call -> fixture.session.send(call.getArgument(0), fixture.candidate))
                        .when(fixture.session).send(any());
                fixture.request(operation, before, existing, expected, fixture.candidateWire);
                DiskShare after = (DiskShare) fixture.session.connectShare("after");
                fixture.request(operation, after, fixture.open(after), expected, fixture.candidateWire);
            }
            assertEquals(Math.min(fixture.config.getWriteBufferSize(), fixture.primary.getNegotiatedProtocol().getMaxWriteSize()),
                    existing.getWriteRequestSize());
            // The original open still writes and reads after either admission outcome.
            byte[] bytes = {3, 7, 11, 19};
            assertEquals(bytes.length, existing.writeRequest(bytes, 0, 0, bytes.length).get(1, TimeUnit.SECONDS).getBytesWritten());
            assertArrayEquals(bytes, existing.readAsync(0, bytes.length).get(1, TimeUnit.SECONDS).getData());
        }
    }

    @Test
    void gmacRejectionLeavesExistingFileUsableAndCallerOwnedCandidateOpen() throws Exception {
        try (Fixture fixture = new Fixture(Operation.WRITE, MIB, MIB, MIB, MIB)) {
            DiskShare share = (DiskShare) fixture.session.connectShare("before");
            File file = fixture.open(share);
            set(fixture.primary.getConnectionContext(), "signingAlgorithm", SMB3SigningAlgorithm.AES_GMAC);
            set(fixture.candidate.getConnectionContext(), "signingAlgorithm", SMB3SigningAlgorithm.AES_GMAC);
            fixture.session.getSessionContext().setSigningKey(new SecretKeySpec(new byte[16], "AES-GMAC"));
            IOException failure = assertThrows(IOException.class, () -> fixture.candidate.bind(fixture.session));
            assertTrue(failure.getMessage().contains("nonce uniqueness"));
            assertEquals(0, fixture.candidateWire.bindings);
            verifyNoInteractions(fixture.candidateSigner);
            assertTrue(fixture.candidateTable().activeSessions().isEmpty());
            assertFalse(fixture.candidate.isClosed());
            assertEquals(1, fixture.session.getChannelCount());
            byte[] bytes = {31, 41, 59};
            assertEquals(bytes.length, file.writeRequest(bytes, 0, 0, bytes.length).get(1, TimeUnit.SECONDS).getBytesWritten());
            assertArrayEquals(bytes, file.readAsync(0, bytes.length).get(1, TimeUnit.SECONDS).getData());
        }
    }

    // WindowsProtocolTestSuites 29ddb4238, MultipleChannel_SecondChannelSessionSetupFailAtFirstTime.
    @Test
    void failedBindThenFreshTranscriptRetryKeepsTheExistingOpenUsable() throws Exception {
        try (Fixture fixture = new Fixture(Operation.WRITE, MIB, MIB, MIB, MIB)) {
            File file = fixture.open((DiskShare) fixture.session.connectShare("before"));
            javax.crypto.SecretKey originalKey = fixture.session.getSessionContext().getSigningKey();
            fixture.candidateWire.rejectNextBinding = true;
            assertThrows(SMBApiException.class, () -> fixture.candidate.bind(fixture.session));
            assertTrue(fixture.candidateTable().activeSessions().isEmpty());
            byte[] bytes = {2, 3, 5, 7};
            assertEquals(bytes.length, file.writeRequest(bytes, 0, 0, bytes.length).get(1, TimeUnit.SECONDS).getBytesWritten());
            assertArrayEquals(bytes, file.readAsync(0, bytes.length).get(1, TimeUnit.SECONDS).getData());
            fixture.candidate.bind(fixture.session);
            doAnswer(call -> fixture.session.send(call.getArgument(0), fixture.candidate)).when(fixture.session).send(any());
            bytes[0] = 11;
            assertEquals(bytes.length, file.writeRequest(bytes, 0, 0, bytes.length).get(1, TimeUnit.SECONDS).getBytesWritten());
            assertArrayEquals(bytes, file.readAsync(0, bytes.length).get(1, TimeUnit.SECONDS).getData());
            assertEquals(2, fixture.candidateWire.bindings);
            assertSame(originalKey, fixture.session.getSessionContext().getSigningKey());
        }
    }

    @Test
    void heldWriteResponseDoesNotStopAnotherChannelUsingTheSameOpen() throws Exception {
        try (Fixture fixture = new Fixture(Operation.WRITE, MIB, MIB, MIB, MIB)) {
            File file = fixture.open((DiskShare) fixture.session.connectShare("before"));
            fixture.candidate.bind(fixture.session);
            doAnswer(call -> fixture.session.send(call.getArgument(0), fixture.primary)).when(fixture.session).send(any());
            fixture.primaryWire.holdNextResponse = true;
            Future<SMB2WriteResponse> held = file.writeRequest(new byte[]{13}, 0, 0, 1);
            assertFalse(held.isDone());
            doAnswer(call -> fixture.session.send(call.getArgument(0), fixture.candidate)).when(fixture.session).send(any());
            assertEquals(1, file.writeRequest(new byte[]{17}, 1, 0, 1).get(1, TimeUnit.SECONDS).getBytesWritten());
            assertArrayEquals(new byte[]{13, 17}, file.readAsync(0, 2).get(1, TimeUnit.SECONDS).getData());
            assertFalse(held.isDone(), "Candidate I/O completed before the primary response was released");
            fixture.primary.handle(new SMB2PacketData(fixture.primaryWire.heldResponse));
            assertEquals(1, held.get(1, TimeUnit.SECONDS).getBytesWritten());
        }
    }

    private static class Fixture implements AutoCloseable {
        final SmbConfig config;
        final Connection primary;
        final Connection candidate;
        final Session session;
        final Signatory candidateSigner;
        final Wire primaryWire = new Wire();
        final Wire candidateWire = new Wire();

        Fixture(Operation operation, int originalMax, int originalConfig, int candidateMax, int candidateConfig) throws Exception {
            config = configuration(operation, originalConfig).withTransportLayerFactory((h, c) -> primaryWire).build();
            SmbConfig secondary = configuration(operation, candidateConfig).withClientGuid(config.getClientGuid())
                    .withTransportLayerFactory((h, c) -> candidateWire).build();
            SMBEventBus bus = new SMBEventBus();
            primary = connection(config, primaryWire, operation, originalMax, bus);
            candidate = connection(secondary, candidateWire, operation, candidateMax, bus);
            candidateWire.data = primaryWire.data;
            candidateSigner = spy((Signatory) get(candidate, "signatory"));
            set(candidate, "signatory", candidateSigner);
            session = spy(new Session(primary, config, null, bus, PathResolver.LOCAL, (Signatory) get(primary, "signatory"), null));
            session.setSessionId(47);
            SMB2SessionSetup established = new SMB2SessionSetup();
            established.setSessionFlags(Collections.emptySet());
            session.getSessionContext().established(established);
            session.getSessionContext().setSigningKey(new SecretKeySpec(new byte[16], "AesCmac"));
            java.lang.reflect.Method register = SessionTable.class.getDeclaredMethod("registerSession", Long.class, Session.class);
            register.setAccessible(true);
            register.invoke(get(primary, "sessionTable"), 47L, session);
        }

        static SmbConfig.Builder configuration(Operation operation, int size) {
            SmbConfig.Builder builder = SmbConfig.builder().withDialects(DIALECT).withTimeout(1, TimeUnit.SECONDS)
                    .withReadBufferSize(MIB).withWriteBufferSize(MIB).withTransactBufferSize(MIB)
                    .withSecurityProvider(new BCSecurityProvider()).withAuthenticators(new StubAuthenticator.Factory());
            switch (operation) {
                case READ: return builder.withReadBufferSize(size);
                case WRITE: return builder.withWriteBufferSize(size);
                default: return builder.withTransactBufferSize(size);
            }
        }

        static Connection connection(SmbConfig config, Wire wire, Operation operation, int max, SMBEventBus bus) throws Exception {
            Connection connection = new Connection(config, null, bus, new ServerList());
            wire.connection = connection;
            Constructor<ConnectionContext> constructor = ConnectionContext.class.getDeclaredConstructor(UUID.class, String.class, int.class, SmbConfig.class);
            constructor.setAccessible(true);
            ConnectionContext context = constructor.newInstance(config.getClientGuid(), "server", 445, config);
            context.getServer().init(new UUID(0, 1), DIALECT, 1,
                    EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL, SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU));
            set(context, "negotiatedProtocol", new NegotiatedProtocol(DIALECT,
                    operation == Operation.TRANSACT ? max : MIB, operation == Operation.READ ? max : MIB,
                    operation == Operation.WRITE ? max : MIB, true));
            set(context, "preauthIntegrityHashId", SMB3HashAlgorithm.SHA_512);
            set(context, "preauthIntegrityHashValue", new byte[64]);
            set(connection, "connectionContext", context);
            Field window = Connection.class.getDeclaredField("sequenceWindow");
            window.setAccessible(true);
            ((SequenceWindow) window.get(connection)).creditsGranted(63);
            return connection;
        }

        SessionTable candidateTable() throws Exception {
            Field field = Connection.class.getDeclaredField("sessionTable");
            field.setAccessible(true);
            return (SessionTable) field.get(candidate);
        }

        File open(DiskShare share) {
            return share.openFile("existing.bin", EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN_IF, EnumSet.noneOf(SMB2CreateOptions.class));
        }

        void request(Operation operation, DiskShare share, File file, int expected, Wire wire) throws Exception {
            Future<? extends SMB2Packet> response;
            switch (operation) {
                case READ: response = file.readAsync(0, MIB); break;
                case WRITE: response = share.writeAsync(FILE_ID, new com.hierynomus.smbj.io.ArrayByteChunkProvider(new byte[MIB], 0)); break;
                default: response = share.ioctlAsync(FILE_ID, 0, true, null, -1);
            }
            response.get(1, TimeUnit.SECONDS);
            assertEquals(operation == Operation.TRANSACT ? SMB2MessageCommandCode.SMB2_IOCTL
                    : operation == Operation.READ ? SMB2MessageCommandCode.SMB2_READ : SMB2MessageCommandCode.SMB2_WRITE, wire.lastCommand);
            assertEquals(expected, wire.lastSize);
        }

        public void close() throws Exception {
            try { primary.close(true); } finally { candidate.close(true); }
        }
    }

    private static Object get(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static void set(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    // Real Connection flow control/response matching and real Share/File sizing; only the remote server is simulated.
    private static class Wire implements TransportLayer<SMBPacket<?, ?>> {
        Connection connection;
        boolean connected = true;
        int bindings;
        boolean rejectNextBinding;
        boolean holdNextResponse;
        byte[] heldResponse;
        SMB2MessageCommandCode lastCommand;
        int lastSize;
        byte[] data = new byte[MIB];

        public void connect(InetSocketAddress address) { connected = true; }
        public boolean isConnected() { return connected; }
        public void disconnect() { connected = false; }

        public void write(SMBPacket<?, ?> packet) {
            try {
                SMBBuffer serialized = new SMBBuffer();
                packet.write(serialized);
                byte[] request = serialized.getCompactData();
                ByteBuffer input = ByteBuffer.wrap(request).order(ByteOrder.LITTLE_ENDIAN);
                SMB2Packet smb = (SMB2Packet) packet;
                lastCommand = smb.getHeader().getMessage();
                int bodySize = 4;
                int readSize = 0;
                switch (lastCommand) {
                    case SMB2_SESSION_SETUP: bindings++; bodySize = 9; break;
                    case SMB2_TREE_CONNECT: bodySize = 16; break;
                    case SMB2_CREATE: bodySize = 88; break;
                    case SMB2_WRITE:
                        lastSize = input.getInt(68); bodySize = 16;
                        System.arraycopy(request, Short.toUnsignedInt(input.getShort(66)), data, (int) input.getLong(72), lastSize);
                        break;
                    case SMB2_READ: lastSize = input.getInt(68); readSize = lastSize; bodySize = 16 + readSize; break;
                    case SMB2_IOCTL: lastSize = input.getInt(108); bodySize = 48; break;
                    default: break;
                }
                byte[] reply = new byte[64 + bodySize];
                ByteBuffer output = ByteBuffer.wrap(reply).order(ByteOrder.LITTLE_ENDIAN);
                output.putInt(0x424d53fe).putShort((short) 64).putShort((short) 1).putInt(0)
                        .putShort((short) smb.getHeader().getMessage().getValue()).putShort((short) 64)
                        .putInt(lastCommand == SMB2MessageCommandCode.SMB2_SESSION_SETUP ? 9 : 1).putInt(0)
                        .putLong(smb.getHeader().getMessageId()).putInt(0).putInt(1).putLong(47).put(new byte[16]);
                switch (lastCommand) {
                    case SMB2_SESSION_SETUP:
                        output.putShort((short) 9).putShort((short) 0).putShort((short) 72).putShort((short) 1).put((byte) 0x60);
                        if (rejectNextBinding) {
                            rejectNextBinding = false;
                            output.putInt(8, (int) com.hierynomus.mserref.NtStatus.STATUS_ACCESS_DENIED.getValue());
                            output.putInt(16, 1);
                            Arrays.fill(reply, 64, reply.length, (byte) 0);
                            output.putShort(64, (short) 9);
                        } else {
                            signBinding(reply, request);
                        }
                        break;
                    case SMB2_TREE_CONNECT: output.putShort((short) 16).put((byte) 1).put((byte) 0); break;
                    case SMB2_CREATE: output.putShort((short) 89); break;
                    case SMB2_WRITE: output.putShort((short) 17).putShort((short) 0).putInt(lastSize); break;
                    case SMB2_READ:
                        output.putShort((short) 17).put((byte) 80).put((byte) 0).putInt(readSize).putInt(0).putInt(0)
                                .put(data, (int) input.getLong(72), readSize); break;
                    case SMB2_IOCTL: output.putShort((short) 49); break;
                    default: output.putShort((short) 4);
                }
                if (holdNextResponse) {
                    holdNextResponse = false;
                    heldResponse = reply;
                } else {
                    connection.handle(new SMB2PacketData(reply));
                }
            } catch (Exception failure) {
                throw new AssertionError(failure);
            }
        }

        private static void signBinding(byte[] response, byte[] request) throws Exception {
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(new byte[64]);
            ByteArrayOutputStream input = new ByteArrayOutputStream();
            input.write(new byte[]{0, 0, 0, 1});
            input.write("SMBSigningKey\0".getBytes(StandardCharsets.US_ASCII));
            input.write(0);
            input.write(hash.digest(request));
            input.write(new byte[]{0, 0, 0, (byte) 128});
            Mac kdf = Mac.getInstance("HmacSHA256");
            kdf.init(new SecretKeySpec(com.hierynomus.protocol.commons.ByteArrayUtils.parseHex("09921d4431b171b977370bf8910900f9"), "HmacSHA256"));
            CMac mac = new CMac(AESEngine.newInstance());
            mac.init(new KeyParameter(Arrays.copyOf(kdf.doFinal(input.toByteArray()), 16)));
            mac.update(response, 0, response.length);
            byte[] signature = new byte[16];
            mac.doFinal(signature, 0);
            System.arraycopy(signature, 0, response, 48, 16);
        }
    }
}
