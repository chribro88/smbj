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
import com.hierynomus.mssmb2.messages.*;
import com.hierynomus.mssmb2.messages.create.SMB2CreateContext;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.testing.StubAuthenticator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static com.hierynomus.smbj.connection.ResponseTestPackets.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(15)
class ProtocolRecoveryTest {
    @ParameterizedTest
    @ValueSource(ints = {2, 4, 32})
    void durableCreateReplaysAndCompletesTheOriginalFuture(int count) throws Exception {
        try (Fixture f = new Fixture(count)) {
            SMB2CreateRequest create = f.create(true);
            Future<SMB2Packet> future = f.session.send(create, f.primary());
            Sent original = f.sent.poll(1, TimeUnit.SECONDS);
            f.primary().close(true);
            Sent replay = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(replay);
            assertNotSame(original.channel, replay.channel);
            assertEquals(count - 1, f.session.getChannelCount());
            assertNotSame(original.channel, f.session.getConnection());
            assertTrue(replay.data.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_REPLAY_OPERATION));
            assertEquals(1, (replay.bytes[8] & 255) | (replay.bytes[9] & 255) << 8);
            assertArrayEquals(Arrays.copyOfRange(original.bytes, 64, original.bytes.length),
                Arrays.copyOfRange(replay.bytes, 64, replay.bytes.length));
            assertTrue(f.signatory.verify(replay.data, f.keys.get(replay.channel)));
            assertFalse(future.isDone());
            byte[] body = new byte[88]; body[0] = 89; body[64] = 17;
            f.reply(replay, NtStatus.STATUS_SUCCESS, body);
            SMB2CreateResponse response = (SMB2CreateResponse) future.get(2, TimeUnit.SECONDS);
            assertNotNull(response.getFileId());
            assertFalse(replay.channel.outstandingRequests.isOutstanding(replay.data.getSequenceNumber()));
            assertNull(f.sent.poll());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 4, 32})
    void ordinaryCreatesAndUncertainWritesAreFailedWithoutReplay(int count) throws Exception {
        try (Fixture f = new Fixture(count)) {
            Future<SMB2Packet> create = f.session.send(f.create(false), f.primary());
            Future<SMB2Packet> write = f.session.send(f.write(), f.primary());
            f.sent.clear();
            f.primary().handleError(new java.io.IOException("Lost transport"));
            assertThrows(ExecutionException.class, () -> create.get(1, TimeUnit.SECONDS));
            assertThrows(ExecutionException.class, () -> write.get(1, TimeUnit.SECONDS));
            assertNull(f.sent.poll(100, TimeUnit.MILLISECONDS));
            assertEquals(Math.max(1, count) - 1, f.session.getChannelCount());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void durableCreateWithoutASurvivorFails(int count) throws Exception {
        try (Fixture f = new Fixture(count)) {
            Future<SMB2Packet> create = f.session.send(f.create(true), f.primary());
            f.sent.clear(); f.primary().close(true);
            assertThrows(ExecutionException.class, () -> create.get(1, TimeUnit.SECONDS));
            assertNull(f.sent.poll());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 4, 32})
    void verifiedExpiryReauthenticatesAndRetriesTheExactWrite(int count) throws Exception {
        try (Fixture f = new Fixture(count)) {
            SecretKey signing = f.session.getSessionContext().getSigningKey();
            SecretKey encryption = new SecretKeySpec(new byte[16], "AES");
            f.session.getSessionContext().setEncryptionKey(encryption);
            byte[] transcript = new byte[64]; transcript[0] = 23;
            f.session.getSessionContext().setPreauthIntegrityHashValue(transcript);
            f.session.send(f.echo());
            f.reply(f.sent.poll(1, TimeUnit.SECONDS), NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});
            Connection channel = f.channels.get(f.channels.size() - 1);
            Future<SMB2Packet> future = f.session.send(f.write(), channel);
            Sent original = f.sent.poll(1, TimeUnit.SECONDS);
            f.reply(original, NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            Sent first = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(first);
            assertEquals(SMB2MessageCommandCode.SMB2_SESSION_SETUP, first.data.getHeader().getMessage());
            assertFalse(first.data.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_REPLAY_OPERATION));
            assertTrue(f.signatory.verify(first.data, f.keys.get(first.channel)));
            f.reply(first, NtStatus.STATUS_MORE_PROCESSING_REQUIRED, setup());
            Sent last = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(last);
            assertEquals(SMB2MessageCommandCode.SMB2_SESSION_SETUP, last.data.getHeader().getMessage());
            f.reply(last, NtStatus.STATUS_SUCCESS, setup());
            Sent retried = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(retried);
            assertEquals(SMB2MessageCommandCode.SMB2_WRITE, retried.data.getHeader().getMessage());
            assertArrayEquals(Arrays.copyOfRange(original.bytes, 64, original.bytes.length),
                Arrays.copyOfRange(retried.bytes, 64, retried.bytes.length));
            assertTrue(f.signatory.verify(retried.data, f.keys.get(retried.channel)));
            assertFalse(retried.data.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_REPLAY_OPERATION));
            f.reply(retried, NtStatus.STATUS_SUCCESS, new byte[] {17, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
            assertEquals(3, ((SMB2WriteResponse) future.get(2, TimeUnit.SECONDS)).getBytesWritten());
            assertSame(signing, f.session.getSessionContext().getSigningKey());
            assertSame(encryption, f.session.getSessionContext().getEncryptionKey());
            assertArrayEquals(transcript, f.session.getSessionContext().getPreauthIntegrityHashValue());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 4, 32})
    void failedReauthenticationTerminatesOnlyTheExpiredSession(int count) throws Exception {
        try (Fixture f = new Fixture(count)) {
            Future<SMB2Packet> first = f.session.send(f.echo());
            Sent original = f.sent.poll(1, TimeUnit.SECONDS);
            Future<SMB2Packet> other = f.session.send(f.echo());
            f.sent.clear();
            f.reply(original, NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            Sent setup = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(setup);
            f.reply(setup, NtStatus.STATUS_LOGON_FAILURE, error());
            assertThrows(ExecutionException.class, () -> first.get(2, TimeUnit.SECONDS));
            Sent logoff = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(logoff);
            assertEquals(SMB2MessageCommandCode.SMB2_LOGOFF, logoff.data.getHeader().getMessage());
            assertThrows(ExecutionException.class, () -> other.get(2, TimeUnit.SECONDS));
            await(() -> f.session.getChannelCount() == 0);
            assertThrows(TransportException.class, () -> f.session.send(f.echo()));
            for (Connection channel : f.channels) {
                assertTrue(channel.isConnected(), "Borrowed transports remain usable by other sessions");
                assertNull(channel.getSessionTable().find(SESSION_ID));
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 4, 32})
    void signedMalformedEchoAndCompoundFailTheirRequests(int count) throws Exception {
        try (Fixture f = new Fixture(count)) {
            Future<SMB2Packet> echo = f.session.send(f.echo());
            Sent request = f.sent.poll(1, TimeUnit.SECONDS);
            f.reply(request, NtStatus.STATUS_SUCCESS, new byte[] {3, 0, 0, 0});
            assertInvalid(echo);
            Future<SMB2Packet> compound = f.session.send(f.echo());
            request = f.sent.poll(1, TimeUnit.SECONDS);
            byte[] wire = f.response(request, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});
            putUInt32(wire, 20, 1);
            f.sign(wire, f.keys.get(request.channel));
            int credits = request.channel.sequenceWindow.available();
            request.channel.handle(new SMB2PacketData(wire));
            assertInvalid(compound);
            assertEquals(credits, request.channel.sequenceWindow.available());
            assertTrue(request.channel.isConnected());
        }
    }

    @Test
    void replayedCreateCancellationUsesTheSurvivingChannelAndMessageId() throws Exception {
        try (Fixture f = new Fixture(2)) {
            Future<SMB2Packet> future = f.session.send(f.create(true), f.primary());
            f.sent.clear(); f.primary().close(true);
            Sent replay = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(replay);
            assertTrue(future.cancel(false));
            Sent cancel = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(cancel);
            assertSame(replay.channel, cancel.channel);
            assertEquals(SMB2MessageCommandCode.SMB2_CANCEL, cancel.data.getHeader().getMessage());
            assertEquals(replay.data.getSequenceNumber(), cancel.data.getSequenceNumber());
        }
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(SMB3EncryptionCipher.class)
    void encryptedWriteRetryRetainsEncryptionAndUsesAFreshNonce(SMB3EncryptionCipher cipher) throws Exception {
        try (Fixture f = new Fixture(2, cipher)) {
            f.session.getSessionContext().setEncryptionKey(f.encryptionKey);
            f.session.getSessionContext().setDecryptionKey(f.encryptionKey);
            Future<SMB2Packet> future = f.session.send(f.write(), true);
            Sent original = f.sent.poll(1, TimeUnit.SECONDS);
            assertTrue(original.encrypted());
            f.reply(original, NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            Sent authentication = f.sent.poll(2, TimeUnit.SECONDS);
            assertFalse(authentication.encrypted());
            f.reply(authentication, NtStatus.STATUS_SUCCESS, setup());
            Sent retry = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(retry); assertTrue(retry.encrypted());
            assertArrayEquals(Arrays.copyOfRange(original.bytes, 64, original.bytes.length),
                Arrays.copyOfRange(retry.bytes, 64, retry.bytes.length));
            assertFalse(Arrays.equals(Arrays.copyOfRange(original.wire, 20, 36), Arrays.copyOfRange(retry.wire, 20, 36)));
            f.reply(retry, NtStatus.STATUS_SUCCESS, new byte[] {17, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
            assertEquals(3, ((SMB2WriteResponse) future.get(2, TimeUnit.SECONDS)).getBytesWritten());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 4, 32})
    void durableCreateReplayRetainsShareRequiredEncryption(int count) throws Exception {
        try (Fixture f = new Fixture(count)) {
            f.session.getSessionContext().setEncryptionKey(f.encryptionKey);
            f.session.getSessionContext().setDecryptionKey(f.encryptionKey);
            Future<SMB2Packet> future = f.session.send(f.create(true), true);
            Sent original = f.sent.poll(1, TimeUnit.SECONDS);
            f.primary().close(true);
            Sent replay = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(replay); assertTrue(replay.encrypted());
            assertTrue(replay.data.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_REPLAY_OPERATION));
            assertArrayEquals(Arrays.copyOfRange(original.bytes, 64, original.bytes.length),
                Arrays.copyOfRange(replay.bytes, 64, replay.bytes.length));
            f.reply(replay, NtStatus.STATUS_SUCCESS, new byte[88]);
            assertInstanceOf(SMB2CreateResponse.class, future.get(2, TimeUnit.SECONDS));
        }
    }

    @Test
    void concurrentExpiriesShareOneAuthenticationExchange() throws Exception {
        try (Fixture f = new Fixture(2)) {
            Future<SMB2Packet> first = f.session.send(f.echo(), f.channels.get(0));
            Sent firstRequest = f.sent.poll(1, TimeUnit.SECONDS);
            Future<SMB2Packet> second = f.session.send(f.echo(), f.channels.get(1));
            Sent secondRequest = f.sent.poll(1, TimeUnit.SECONDS);
            f.reply(firstRequest, NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            Sent authentication = f.sent.poll(2, TimeUnit.SECONDS);
            f.reply(secondRequest, NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            f.reply(authentication, NtStatus.STATUS_SUCCESS, setup());
            for (int i = 0; i < 2; i++) {
                Sent retry = f.sent.poll(2, TimeUnit.SECONDS);
                assertNotNull(retry);
                assertEquals(SMB2MessageCommandCode.SMB2_ECHO, retry.data.getHeader().getMessage());
                f.reply(retry, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});
            }
            first.get(2, TimeUnit.SECONDS); second.get(2, TimeUnit.SECONDS);
            assertEquals(1, f.authentications.get());
        }
    }

    @Test
    void closeDoesNotWaitForTheAuthenticationTimeout() throws Exception {
        try (Fixture f = new Fixture(2)) {
            Future<SMB2Packet> future = f.session.send(f.echo());
            Sent original = f.sent.poll(1, TimeUnit.SECONDS);
            f.reply(original, NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            assertNotNull(f.sent.poll(2, TimeUnit.SECONDS));
            ExecutorService closer = Executors.newSingleThreadExecutor();
            try {
                Future<?> closing = closer.submit(() -> { f.session.close(); return null; });
                Sent logoff = f.sent.poll(1, TimeUnit.SECONDS);
                assertNotNull(logoff);
                assertEquals(SMB2MessageCommandCode.SMB2_LOGOFF, logoff.data.getHeader().getMessage());
                f.reply(logoff, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});
                closing.get(1, TimeUnit.SECONDS);
                assertThrows(ExecutionException.class, () -> future.get(1, TimeUnit.SECONDS));
                assertEquals(0, f.session.getChannelCount());
            } finally {
                closer.shutdownNow(); assertTrue(closer.awaitTermination(2, TimeUnit.SECONDS));
            }
        }
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(value = SMB2Dialect.class, names = {"SMB_2_0_2", "SMB_2_1", "SMB_3_0", "SMB_3_0_2", "SMB_3_1_1"})
    void reauthenticationRetainsExistingKeysForEverySupportedDialect(SMB2Dialect dialect) throws Exception {
        try (Fixture f = new Fixture(1, dialect, SMB3EncryptionCipher.AES_128_CCM)) {
            f.session.getSessionContext().setSessionKey(new SecretKeySpec(f.keys.get(f.primary()).getEncoded(), "HmacSHA256"));
            SecretKey key = f.session.getSessionContext().getSessionKey();
            Future<SMB2Packet> future = f.session.send(f.echo());
            f.reply(f.sent.poll(1, TimeUnit.SECONDS), NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            Sent authentication = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(authentication);
            f.reply(authentication, NtStatus.STATUS_SUCCESS, setup());
            Sent retry = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(retry);
            f.reply(retry, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});
            future.get(2, TimeUnit.SECONDS);
            assertSame(key, f.session.getSessionContext().getSessionKey());
            await(() -> f.authenticatorCloses.get() == 1);
        }
    }

    @Test
    void forgedExpiryAndAuthenticationRepliesHaveNoCreditOrRetryEffects() throws Exception {
        try (Fixture f = new Fixture(2)) {
            Future<SMB2Packet> future = f.session.send(f.echo());
            Sent original = f.sent.poll(1, TimeUnit.SECONDS);
            byte[] expiry = f.response(original, NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            expiry[48] ^= 1;
            int credits = original.channel.sequenceWindow.available();
            original.channel.handle(new SMB2PacketData(expiry));
            assertEquals(credits, original.channel.sequenceWindow.available());
            assertEquals(0, f.authentications.get()); assertFalse(future.isDone());
            f.reply(original, NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            Sent authentication = f.sent.poll(2, TimeUnit.SECONDS);
            byte[] response = f.response(authentication, NtStatus.STATUS_SUCCESS, setup());
            response[48] ^= 1;
            credits = authentication.channel.sequenceWindow.available();
            authentication.channel.handle(new SMB2PacketData(response));
            assertEquals(credits, authentication.channel.sequenceWindow.available());
            assertFalse(future.isDone()); assertNull(f.sent.poll());
            f.reply(authentication, NtStatus.STATUS_SUCCESS, setup());
            Sent retry = f.sent.poll(2, TimeUnit.SECONDS);
            f.reply(retry, NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});
            future.get(2, TimeUnit.SECONDS);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"guest", "no-key", "round-limit"})
    void authenticationDowngradeOrFailureCannotRetryTheOperation(String fault) throws Exception {
        try (Fixture f = new Fixture(2)) {
            f.exportKey = !fault.equals("no-key");
            Future<SMB2Packet> future = f.session.send(f.echo());
            f.reply(f.sent.poll(1, TimeUnit.SECONDS), NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            int rounds = fault.equals("round-limit") ? 16 : 1;
            for (int i = 0; i < rounds; i++) {
                Sent authentication = f.sent.poll(2, TimeUnit.SECONDS);
                assertNotNull(authentication);
                assertEquals(SMB2MessageCommandCode.SMB2_SESSION_SETUP, authentication.data.getHeader().getMessage());
                byte[] body = setup(); if (fault.equals("guest")) body[2] = 1;
                f.reply(authentication, fault.equals("round-limit") ? NtStatus.STATUS_MORE_PROCESSING_REQUIRED : NtStatus.STATUS_SUCCESS, body);
            }
            assertThrows(ExecutionException.class, () -> future.get(2, TimeUnit.SECONDS));
            Sent logoff = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(logoff);
            assertEquals(SMB2MessageCommandCode.SMB2_LOGOFF, logoff.data.getHeader().getMessage());
            await(() -> f.session.getChannelCount() == 0);
            assertEquals(1, f.authenticatorCloses.get());
        }
    }

    @Test
    void spnegoAuthenticationContextIsDisposedOnce() throws Exception {
        com.hierynomus.smbj.auth.SpnegoAuthenticator authenticator = new com.hierynomus.smbj.auth.SpnegoAuthenticator();
        org.ietf.jgss.GSSContext context = mock(org.ietf.jgss.GSSContext.class);
        Field field = authenticator.getClass().getDeclaredField("gssContext"); field.setAccessible(true); field.set(authenticator, context);
        authenticator.close(); authenticator.close();
        verify(context).dispose();
    }

    @Test
    void repeatedChannelLossKeepsTheOriginalCreateCompletion() throws Exception {
        try (Fixture f = new Fixture(4)) {
            Future<SMB2Packet> future = f.session.send(f.create(true), f.primary());
            Sent previous = f.sent.poll(1, TimeUnit.SECONDS);
            byte[] body = Arrays.copyOfRange(previous.bytes, 64, previous.bytes.length);
            for (int sequence = 1; sequence < 4; sequence++) {
                previous.channel.close(true);
                Sent replay = f.sent.poll(2, TimeUnit.SECONDS);
                assertNotNull(replay);
                assertNotSame(previous.channel, replay.channel);
                assertArrayEquals(body, Arrays.copyOfRange(replay.bytes, 64, replay.bytes.length));
                assertEquals(sequence, (replay.bytes[8] & 255) | (replay.bytes[9] & 255) << 8);
                previous = replay;
            }
            f.reply(previous, NtStatus.STATUS_SUCCESS, new byte[88]);
            assertInstanceOf(SMB2CreateResponse.class, future.get(2, TimeUnit.SECONDS));
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void sendFailureReturnsTheRecoverableCreateFuture(boolean serialized) throws Exception {
        try (Fixture f = new Fixture(2)) {
            doAnswer(call -> {
                if (serialized) ((SMBPacket<?, ?>) call.getArgument(0)).write(new SMBBuffer());
                throw new TransportException("Injected send failure");
            }).when(f.primary().transport).write(any());
            Future<SMB2Packet> future = f.session.send(f.create(true), f.primary());
            Sent replay = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(replay);
            f.reply(replay, NtStatus.STATUS_SUCCESS, new byte[88]);
            assertInstanceOf(SMB2CreateResponse.class, future.get(2, TimeUnit.SECONDS));
        }
    }

    @Test
    void expiredIoctlRetainsItsConsumedInput() throws Exception {
        try (Fixture f = new Fixture(2)) {
            SMB2IoctlRequest request = new SMB2IoctlRequest(SMB2Dialect.SMB_3_1_1, SESSION_ID, 9,
                0x0011c017L, new SMB2FileId(new byte[8], new byte[8]),
                new ArrayByteChunkProvider(new byte[] {1, 2, 3}, 0), true, 65536);
            Future<SMB2Packet> future = f.session.send(request);
            Sent original = f.sent.poll(1, TimeUnit.SECONDS);
            f.reply(original, NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
            f.reply(f.sent.poll(2, TimeUnit.SECONDS), NtStatus.STATUS_SUCCESS, setup());
            Sent retry = f.sent.poll(2, TimeUnit.SECONDS);
            assertNotNull(retry);
            assertArrayEquals(Arrays.copyOfRange(original.bytes, 64, original.bytes.length),
                Arrays.copyOfRange(retry.bytes, 64, retry.bytes.length));
            f.reply(retry, NtStatus.STATUS_ACCESS_DENIED, error());
            assertEquals(NtStatus.STATUS_ACCESS_DENIED.getValue(), future.get(2, TimeUnit.SECONDS).getHeader().getStatusCode());
        }
    }

    @Test
    void unboundChannelFinalSetupIsVerifiedByTheSessionBuilder() throws Exception {
        try (Fixture f = new Fixture(1)) {
            Session binding = new Session(mock(Connection.class), SmbConfig.createDefaultConfig(), null, null, null, null, null);
            binding.setSessionId(SESSION_ID);
            binding.getSessionContext().setSigningKey(f.keys.get(f.primary()));
            binding.getSessionContext().setSigningRequired(true);
            f.primary().getSessionTable().registerSession(SESSION_ID, binding);
            SMB2SessionSetup request = new SMB2SessionSetup(SMB2Dialect.SMB_3_1_1,
                EnumSet.of(SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED), EnumSet.noneOf(SMB2GlobalCapability.class));
            request.getHeader().setSessionId(SESSION_ID);
            request.setSecurityBuffer(new byte[0]);
            Future<SMB2Packet> future = f.primary().send(request);
            Sent sent = f.sent.poll(1, TimeUnit.SECONDS);
            byte[] response = f.response(sent, NtStatus.STATUS_SUCCESS, setup());
            byte[] newKey = new byte[16]; newKey[0] = 99;
            f.sign(response, new SecretKeySpec(newKey, "AesCmac"));
            f.primary().handle(new SMB2PacketData(response));
            assertInstanceOf(SMB2SessionSetup.class, future.get(1, TimeUnit.SECONDS));
            f.primary().getSessionTable().registerSession(SESSION_ID, f.session);
        }
    }

    @Test
    void failedReauthenticationClosesCachedShares() throws Exception {
        try (Fixture f = new Fixture(2)) {
            ExecutorService application = Executors.newSingleThreadExecutor();
            try {
                Future<com.hierynomus.smbj.share.Share> connected = application.submit(() -> f.session.connectShare("share"));
                Sent tree = f.sent.poll(1, TimeUnit.SECONDS);
                assertNotNull(tree);
                byte[] body = new byte[16]; body[0] = 16; body[2] = 1;
                f.reply(tree, NtStatus.STATUS_SUCCESS, body);
                com.hierynomus.smbj.share.Share share = connected.get(2, TimeUnit.SECONDS);
                assertTrue(share.isConnected());
                Future<SMB2Packet> pending = f.session.send(f.echo());
                f.reply(f.sent.poll(1, TimeUnit.SECONDS), NtStatus.STATUS_NETWORK_SESSION_EXPIRED, error());
                f.reply(f.sent.poll(2, TimeUnit.SECONDS), NtStatus.STATUS_LOGON_FAILURE, error());
                assertThrows(ExecutionException.class, () -> pending.get(2, TimeUnit.SECONDS));
                await(() -> !share.isConnected());
            } finally {
                application.shutdownNow(); assertTrue(application.awaitTermination(2, TimeUnit.SECONDS));
            }
        }
    }

    private static byte[] error() { return new byte[] {9, 0, 0, 0, 0, 0, 0, 0}; }
    private static byte[] setup() { return new byte[] {9, 0, 0, 0, 72, 0, 0, 0}; }

    private static void assertInvalid(Future<?> future) {
        ExecutionException failure = assertThrows(ExecutionException.class, () -> future.get(2, TimeUnit.SECONDS));
        assertTrue(failure.getCause().getMessage().contains("Invalid network response"));
    }

    private static void await(BooleanSupplier done) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (!done.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue(done.getAsBoolean());
    }

    private static final class Sent {
        final Connection channel;
        final byte[] bytes;
        final SMB2PacketData data;
        final byte[] wire;
        Sent(Connection channel, byte[] bytes, byte[] wire) throws Exception {
            this.channel = channel; this.bytes = bytes; this.wire = wire; this.data = new SMB2PacketData(bytes);
        }
        boolean encrypted() { return wire[0] == (byte) 0xFD; }
    }

    private static final class Fixture implements AutoCloseable {
        final List<Connection> channels = new ArrayList<>();
        final Map<Connection, SecretKey> keys = new HashMap<>();
        final BlockingQueue<Sent> sent = new LinkedBlockingQueue<>();
        final PacketSignatory signatory = new PacketSignatory(new BCSecurityProvider());
        final PacketEncryptor encryptor = new PacketEncryptor(new BCSecurityProvider());
        final SecretKey encryptionKey = new SecretKeySpec(new byte[16], "AES");
        final Session session;
        final SMB2Dialect dialect;
        final AtomicInteger authentications = new AtomicInteger();
        final AtomicInteger authenticatorCloses = new AtomicInteger();
        volatile boolean exportKey = true;

        @SuppressWarnings("unchecked")
        Fixture(int requested) throws Exception {
            this(requested, SMB2Dialect.SMB_3_1_1, SMB3EncryptionCipher.AES_128_GCM);
        }

        @SuppressWarnings("unchecked")
        Fixture(int requested, SMB3EncryptionCipher cipher) throws Exception {
            this(requested, SMB2Dialect.SMB_3_1_1, cipher);
        }

        @SuppressWarnings("unchecked")
        Fixture(int requested, SMB2Dialect dialect, SMB3EncryptionCipher cipher) throws Exception {
            this.dialect = dialect;
            List<TransportLayer<SMBPacket<?, ?>>> transports = new ArrayList<>();
            for (int i = 0; i < Math.max(1, requested); i++) transports.add(mock(TransportLayer.class));
            Queue<TransportLayer<SMBPacket<?, ?>>> pending = new ArrayDeque<>(transports);
            SmbConfig config = SmbConfig.builder().withSigningRequired(true).withTransactTimeout(2, TimeUnit.SECONDS)
                .withTransportLayerFactory((handlers, settings) -> pending.remove())
                .withAuthenticators(new StubAuthenticator.Factory() {
                    @Override public StubAuthenticator create() {
                        authentications.incrementAndGet(); return new TrackingAuthenticator();
                    }
                }).build();
            SMBEventBus bus = new SMBEventBus();
            for (int i = 0; i < transports.size(); i++) {
                Connection channel = new Connection(config, null, bus, new ServerList());
                ConnectionContext context = mock(ConnectionContext.class);
                when(context.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(dialect, 65536, 65536, 65536, true));
                when(context.getServer()).thenReturn(new Server("localhost", 445));
                when(context.getCipherId()).thenReturn(cipher);
                when(context.getGssNegotiateToken()).thenReturn(new byte[0]);
                when(context.getClientCapabilities()).thenReturn(EnumSet.noneOf(SMB2GlobalCapability.class));
                when(context.getServerCapabilities()).thenReturn(requested == 0 ? EnumSet.noneOf(SMB2GlobalCapability.class)
                    : EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL));
                Field field = Connection.class.getDeclaredField("connectionContext"); field.setAccessible(true); field.set(channel, context);
                Field encryption = Connection.class.getDeclaredField("encryptor"); encryption.setAccessible(true);
                ((PacketEncryptor) encryption.get(channel)).init(context);
                encryptor.init(context);
                channel.sequenceWindow.creditsGranted(64);
                channel.sequenceWindow.get(i + 1);
                TransportLayer<SMBPacket<?, ?>> transport = transports.get(i);
                when(transport.isConnected()).thenReturn(true);
                doAnswer(call -> {
                    SMBPacket<?, ?> packet = call.getArgument(0);
                    SMBBuffer buffer = new SMBBuffer(); packet.write(buffer);
                    byte[] wire = buffer.getCompactData();
                    byte[] plain = wire[0] == (byte) 0xFD ? encryptor.decrypt(new SMB3EncryptedPacketData(wire), encryptionKey) : wire;
                    sent.add(new Sent(channel, plain, wire));
                    return null;
                }).when(transport).write(any());
                channels.add(channel);
                byte[] key = new byte[16]; key[0] = (byte) (i + 1);
                keys.put(channel, new SecretKeySpec(key, dialect.isSmb3x() ? "AesCmac" : "HmacSHA256"));
            }
            session = new Session(primary(), config, new AuthenticationContext("user", new char[0], "domain"),
                bus, com.hierynomus.smbj.paths.PathResolver.LOCAL, signatory, encryptor);
            session.setSessionId(SESSION_ID);
            session.getSessionContext().setSigningKey(keys.get(primary()));
            session.getSessionContext().setSigningRequired(true);
            for (Connection channel : channels) {
                if (channel != primary()) session.addChannel(channel, keys.get(channel));
                channel.getSessionTable().registerSession(SESSION_ID, session);
            }
        }

        private final class TrackingAuthenticator extends StubAuthenticator implements java.io.Closeable {
            @Override public com.hierynomus.smbj.auth.AuthenticateResponse authenticate(AuthenticationContext context,
                    byte[] token, ConnectionContext connectionContext) throws java.io.IOException {
                com.hierynomus.smbj.auth.AuthenticateResponse response = super.authenticate(context, token, connectionContext);
                if (!exportKey) response.setSessionKey(null);
                return response;
            }
            @Override public void close() { authenticatorCloses.incrementAndGet(); }
        }

        Connection primary() { return channels.get(0); }
        SMB2Echo echo() {
            SMB2Echo echo = new SMB2Echo(dialect); echo.getHeader().setSessionId(SESSION_ID); return echo;
        }
        SMB2WriteRequest write() {
            return new SMB2WriteRequest(dialect, new SMB2FileId(new byte[8], new byte[8]), SESSION_ID, 9,
                new ArrayByteChunkProvider(new byte[] {11, 22, 33}, 37), 65536);
        }
        SMB2CreateRequest create(boolean durable) {
            return new SMB2CreateRequest(dialect, SESSION_ID, 9,
                SMB2ImpersonationLevel.Identification, EnumSet.of(AccessMask.GENERIC_READ),
                EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN_IF,
                EnumSet.noneOf(SMB2CreateOptions.class), new SmbPath("localhost", "share", "durable.bin"),
                SMB2OplockLevel.SMB2_OPLOCK_LEVEL_BATCH, durable ? Collections.singletonList(
                    new SMB2CreateContext("DH2Q".getBytes(StandardCharsets.US_ASCII), new byte[32])) : Collections.emptyList());
        }
        void reply(Sent request, NtStatus status, byte[] body) throws Exception {
            byte[] bytes = response(request, status, body);
            if (request.encrypted()) {
                SMB2Packet packet = new SMB2Packet() {
                    @Override public void write(SMBBuffer buffer) { buffer.putRawBytes(bytes); }
                    @Override public SMB2PacketHeader getHeader() { return request.data.getHeader(); }
                };
                SMBBuffer buffer = new SMBBuffer(); encryptor.encrypt(packet, encryptionKey).write(buffer);
                request.channel.handle(new SMB3EncryptedPacketData(buffer.getCompactData()));
            } else {
                request.channel.handle(new SMB2PacketData(bytes));
            }
        }
        byte[] response(Sent request, NtStatus status, byte[] body) throws Exception {
            byte[] bytes = frame(ResponseTestPackets.response(request.data.getSequenceNumber(), request.data.getHeader().getMessage(),
                SESSION_ID, true, status, body));
            sign(bytes, keys.get(request.channel)); return bytes;
        }
        void sign(byte[] bytes, SecretKey key) throws Exception {
            Arrays.fill(bytes, 48, 64, (byte) 0);
            com.hierynomus.security.Mac mac = new BCSecurityProvider().getMac(key.getAlgorithm());
            mac.init(key.getEncoded()); mac.update(bytes);
            System.arraycopy(mac.doFinal(), 0, bytes, 48, 16);
        }
        @Override public void close() throws Exception {
            for (Connection channel : channels) channel.close(true);
        }
    }
}
