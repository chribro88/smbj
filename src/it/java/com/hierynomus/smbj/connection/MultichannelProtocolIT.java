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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2Close;
import com.hierynomus.mssmb2.messages.SMB2LockRequest;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.mssmb2.messages.submodule.SMB2LockElement;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static com.hierynomus.smbj.testing.MultichannelTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class MultichannelProtocolIT {
    private static final SMB2Dialect DIALECT = dialect();

    // Behavioral regression: Pike bcbb343c5, MultiChannelTest.test_open_bind_close.
    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#configurations")
    void openOnPrimaryBindAndCloseSameHandleOnSecondary(String port, boolean encryption, boolean writeThrough) throws Exception {
        try (Fixture fixture = new Fixture(port, encryption, writeThrough)) {
            Connection secondary = fixture.bind();
            SMB2Close close = new SMB2Close(DIALECT, fixture.session.getSessionId(), fixture.treeId(), fixture.file.getFileId());
            SMB2Packet response = fixture.session.send(close, secondary).get(5, TimeUnit.SECONDS);
            assertEquals(NtStatus.STATUS_SUCCESS.getValue(), response.getHeader().getStatusCode());
            assertEquals(2, fixture.session.getChannelCount());
        }
    }

    // Behavioral regression: WindowsProtocolTestSuites 29ddb4238, MultipleChannel_LockUnlockOnDiffChannel.
    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#configurations")
    void lockOnPrimaryAndUnlockSameHandleOnSecondary(String port, boolean encryption, boolean writeThrough) throws Exception {
        try (Fixture fixture = new Fixture(port, encryption, writeThrough)) {
            Connection secondary = fixture.bind();
            SMB2LockRequest lock = new SMB2LockRequest(DIALECT, fixture.session.getSessionId(), fixture.treeId(), (short) 0, 0,
                    fixture.file.getFileId(), Collections.singletonList(new SMB2LockElement(0, 1,
                    EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_EXCLUSIVE_LOCK, SMB2LockFlag.SMB2_LOCKFLAG_FAIL_IMMEDIATELY))));
            assertEquals(0, fixture.session.send(lock, fixture.primary).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
            SMB2LockRequest unlock = new SMB2LockRequest(DIALECT, fixture.session.getSessionId(), fixture.treeId(), (short) 1, 0,
                    fixture.file.getFileId(), Collections.singletonList(new SMB2LockElement(0, 1, EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_UNLOCK))));
            assertEquals(0, fixture.session.send(unlock, secondary).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
            assertEquals(1, fixture.file.write(new byte[]{7}, 0));
        }
    }

    // Behavioral regression: Pike bcbb343c5, MultiChannelTest.test_write_fence_reject_stale.
    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#configurations")
    void staleWriteCannotReplaceNewerData(String port, boolean encryption, boolean writeThrough) throws Exception {
        try (Fixture fixture = new Fixture(port, encryption, writeThrough)) {
            Connection secondary = fixture.bind();
            assertEquals(0, fixture.writeOn(secondary, "stale".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 1, true));
            assertEquals(0, fixture.writeOn(secondary, "fresh".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 1, false));
            assertEquals(NtStatus.STATUS_FILE_NOT_AVAILABLE.getValue(), fixture.writeOn(fixture.primary,
                    "stale".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, false));
            byte[] actual = new byte[5];
            assertEquals(actual.length, fixture.file.read(actual, 0));
            assertArrayEquals("fresh".getBytes(java.nio.charset.StandardCharsets.US_ASCII), actual);
        }
    }

    // Behavioral regression: go-smb2 7f69f658, TestBindChannelRejectsAnotherServer.
    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#configurations")
    void rejectsAnotherServerAndPreservesExistingSession(String port, boolean encryption, boolean writeThrough) throws Exception {
        assumeTrue(port != null);
        String other = Arrays.stream(System.getenv().getOrDefault("SMB_TEST_OTHER_PORT", System.getenv().getOrDefault("SMB_TEST_PORTS", port)).split(","))
                .map(String::trim).filter(candidate -> !candidate.equals(port)).findFirst().orElse(null);
        assumeTrue(other != null, "Two independent server ports enable server identity rejection");
        try (Fixture fixture = new Fixture(port, encryption, writeThrough)) {
            com.hierynomus.protocol.transport.TransportException failure = assertThrows(com.hierynomus.protocol.transport.TransportException.class,
                    () -> fixture.client.openChannel(fixture.session, hostname(), Integer.parseInt(other)));
            assertTrue(failure.getMessage().contains("Different server found"));
            assertEquals(1, fixture.session.getChannelCount());
            assertEquals(1, fixture.file.write(new byte[]{9}, 0));
            fixture.bind();
            byte[] actual = new byte[1];
            assertEquals(1, fixture.file.read(actual, 0));
            assertEquals(9, actual[0]);
        }
    }

    // Behavioral regression: go-smb2 7f69f658, TestBindChannelFailurePreservesExistingSession.
    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#rejectedBindingConfigurations")
    void serverBindingRejectionPreservesPrimarySession(String port, boolean encryption, boolean writeThrough) throws Exception {
        try (Fixture fixture = new Fixture(port, encryption, writeThrough)) {
            SMBApiException failure = assertThrows(SMBApiException.class, fixture::bind);
            assertEquals(NtStatus.STATUS_ACCESS_DENIED.getValue(), failure.getStatusCode());
            assertEquals(1, fixture.session.getChannelCount());
            assertEquals(3, fixture.file.write(new byte[]{3, 2, 1}, 0));
            byte[] actual = new byte[3];
            assertEquals(actual.length, fixture.file.read(actual, 0));
            assertArrayEquals(new byte[]{3, 2, 1}, actual);
        }
    }

    // Behavioral regression: go-smb2 7f69f658, TestConcurrentBindChannels and TestSessionChannelsAbortClosesEveryConnection.
    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#configurations")
    void concurrentBindingsPublishIndependentChannelsAndClientClosesAll(String port, boolean encryption, boolean writeThrough) throws Exception {
        try (Fixture fixture = new Fixture(port, encryption, writeThrough)) {
            java.util.concurrent.ExecutorService workers = java.util.concurrent.Executors.newFixedThreadPool(2);
            try {
                java.util.concurrent.Future<Connection> first = workers.submit(() -> fixture.client.openChannel(fixture.session, hostname(), fixture.port));
                java.util.concurrent.Future<Connection> second = workers.submit(() -> fixture.client.openChannel(fixture.session, hostname(), fixture.port));
                Connection a = first.get(10, TimeUnit.SECONDS);
                Connection b = second.get(10, TimeUnit.SECONDS);
                assertNotSame(a, b);
                assertEquals(3, fixture.session.getChannelCount());
                for (Connection channel : new Connection[]{fixture.primary, a, b}) {
                    com.hierynomus.mssmb2.messages.SMB2Echo echo = new com.hierynomus.mssmb2.messages.SMB2Echo(DIALECT);
                    echo.getHeader().setSessionId(fixture.session.getSessionId());
                    assertEquals(0, fixture.session.send(echo, channel).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
                }
                fixture.file.close();
                fixture.share.close();
                fixture.client.close();
                fixture.closed = true;
                for (Connection channel : new Connection[]{fixture.primary, a, b}) assertFalse(channel.isConnected());
            } finally {
                workers.shutdownNow();
                assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
            }
        }
    }

    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#configurations")
    void negotiatedMultiCreditWritesRemainAvailableOnBothChannels(String port, boolean encryption, boolean writeThrough) throws Exception {
        try (Fixture fixture = new Fixture(port, encryption, writeThrough)) {
            Connection secondary = fixture.bind();
            int size = fixture.file.getWriteRequestSize();
            assertEquals(1048576, size, "The default negotiated write size must not be reduced to one credit");
            byte[] bytes = new byte[size];
            for (int i = 0; i < size; i++) bytes[i] = (byte) (i * 31 + 7);
            long before = fixture.primary.getWriteRequestCount() + secondary.getWriteRequestCount();
            assertEquals(size, fixture.file.write(bytes, 0));
            assertEquals(size, fixture.file.write(bytes, size));
            assertEquals(2, fixture.primary.getWriteRequestCount() + secondary.getWriteRequestCount() - before);
            assertTrue(fixture.primary.getWriteRequestCount() > 0);
            assertTrue(secondary.getWriteRequestCount() > 0);
            byte[] read = new byte[size];
            for (int offset : new int[]{0, size}) {
                assertEquals(size, fixture.file.read(read, offset));
                assertArrayEquals(bytes, read);
            }
        }
    }

    private static class Fixture implements AutoCloseable {
        final SMBClient client;
        final Connection primary;
        final Session session;
        final DiskShare share;
        final File file;
        final int port;
        final boolean encryption;
        boolean closed;

        Fixture(String port, boolean encryption, boolean writeThrough) throws Exception {
            assumeTrue(port != null, "SMB_TEST_PORT or SMB_TEST_PORTS enables live multichannel tests");
            this.port = Integer.parseInt(port);
            this.encryption = encryption;
            client = new SMBClient(config(encryption));
            try {
                primary = client.connect(hostname(), this.port);
                assertEquals(DIALECT, primary.getNegotiatedProtocol().getDialect());
                session = primary.authenticate(authentication());
                share = (DiskShare) session.connectShare(shareName());
                EnumSet<SMB2CreateOptions> options = EnumSet.of(SMB2CreateOptions.FILE_DELETE_ON_CLOSE);
                if (writeThrough) options.add(SMB2CreateOptions.FILE_WRITE_THROUGH);
                file = share.openFile("multichannel-" + UUID.randomUUID() + ".bin",
                        EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE, AccessMask.DELETE),
                        EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, options);
            } catch (Exception | Error failure) {
                client.close();
                throw failure;
            }
        }

        Connection bind() throws Exception {
            Connection result = client.openChannel(session, hostname(), port);
            assertEquals(2, session.getChannelCount());
            return result;
        }

        long treeId() { return share.getTreeConnect().getTreeId(); }

        long writeOn(Connection channel, byte[] bytes, int sequence, boolean replay) throws Exception {
            SMB2WriteRequest request = new SMB2WriteRequest(DIALECT, file.getFileId(), session.getSessionId(), treeId(),
                    new ArrayByteChunkProvider(bytes, 0), bytes.length);
            request.getHeader().setChannelSequence(sequence);
            if (replay) request.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_REPLAY_OPERATION);
            SMB2Packet packet = encryption
                    ? sessionEncryptor().encrypt(request, session.getSessionContext().getEncryptionKey())
                    : new PacketSignatory(config(false).getSecurityProvider()).sign(request, session.getSigningKey(request.getHeader(), true, channel));
            // Deliberately bypass Session's current sequence for the stale-request negative test.
            return channel.send(packet).get(5, TimeUnit.SECONDS).getHeader().getStatusCode();
        }

        PacketEncryptor sessionEncryptor() throws ReflectiveOperationException {
            // Even deliberately stale requests must share the session's encryption nonce allocator.
            java.lang.reflect.Field field = Session.class.getDeclaredField("encryptor");
            field.setAccessible(true);
            return (PacketEncryptor) field.get(session);
        }

        @Override
        public void close() throws Exception {
            if (closed) return;
            closed = true;
            Exception failure = null;
            for (AutoCloseable resource : new AutoCloseable[]{file, share, session, client}) {
                try { resource.close(); }
                catch (Exception error) {
                    if (failure == null) failure = error;
                    else failure.addSuppressed(error);
                }
            }
            if (failure != null) throw failure;
        }
    }
}
