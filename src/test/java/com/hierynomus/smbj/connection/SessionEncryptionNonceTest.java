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
import com.hierynomus.mssmb2.SMB3EncryptionCipher;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.session.Session;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@Timeout(30)
class SessionEncryptionNonceTest {
    static Stream<Arguments> ciphers() {
        return Stream.of(
                Arguments.of("BC GCM", new BCSecurityProvider(), SMB3EncryptionCipher.AES_128_GCM),
                Arguments.of("BC CCM", new BCSecurityProvider(), SMB3EncryptionCipher.AES_128_CCM),
                Arguments.of("default JCE GCM", new JceSecurityProvider(), SMB3EncryptionCipher.AES_128_GCM),
                Arguments.of("JCE/BC GCM", new JceSecurityProvider(new BouncyCastleProvider()), SMB3EncryptionCipher.AES_128_GCM),
                Arguments.of("JCE/BC CCM", new JceSecurityProvider(new BouncyCastleProvider()), SMB3EncryptionCipher.AES_128_CCM));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("ciphers")
    void concurrentChannelsAndReplacementKeepOneNonceSequence(String name, SecurityProvider provider,
            SMB3EncryptionCipher cipher) throws Exception {
        try (Fixture f = new Fixture(provider, cipher)) {
            ExecutorService workers = Executors.newFixedThreadPool(4);
            try {
                CountDownLatch ready = new CountDownLatch(4), start = new CountDownLatch(1);
                Future<?>[] sent = new Future<?>[4];
                for (int i = 0; i < sent.length; i++) {
                    sent[i] = workers.submit(() -> {
                        ready.countDown(); start.await();
                        for (int j = 0; j < 32; j++) f.send();
                        return null;
                    });
                }
                assertTrue(ready.await(5, TimeUnit.SECONDS));
                start.countDown();
                for (Future<?> result : sent) result.get(20, TimeUnit.SECONDS);
            } finally {
                workers.shutdownNow();
                assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
            }
            assertEquals(128, f.nonces.size());
            assertEquals(2, f.usedChannels.size());
            when(f.primary.isClosed()).thenReturn(true);
            Connection replacement = f.channel();
            f.session.addChannel(replacement, f.key);
            f.encryptor.init(f.context);
            f.send(); f.send();
            assertEquals(2, f.session.getChannelCount());
            assertTrue(f.usedChannels.contains(replacement));
            assertEquals(130, f.nonces.size());
            for (long nonce = 0; nonce < 130; nonce++) assertTrue(f.nonces.contains(nonce));
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("ciphers")
    void providerFailureConsumesItsNonceBeforeAnotherChannelSends(String name, SecurityProvider provider,
            SMB3EncryptionCipher cipher) throws Exception {
        SecurityProvider failing = mock(SecurityProvider.class);
        AtomicInteger attempts = new AtomicInteger();
        when(failing.getAEADBlockCipher(anyString())).thenAnswer(call -> {
            if (attempts.getAndIncrement() == 0) throw new com.hierynomus.security.SecurityException("injected");
            return provider.getAEADBlockCipher(call.getArgument(0));
        });
        try (Fixture f = new Fixture(failing, cipher)) {
            assertThrows(SMBRuntimeException.class, f::send);
            assertTrue(f.nonces.isEmpty());
            f.send();
            assertEquals(java.util.Collections.singleton(1L), f.nonces);
            assertTrue(f.usedChannels.contains(f.secondary));
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("ciphers")
    void concurrentExhaustionIssuesTheLastNonceOnceAndNeverWraps(String name, SecurityProvider provider,
            SMB3EncryptionCipher cipher) throws Exception {
        try (Fixture f = new Fixture(provider, cipher)) {
            Field field = PacketEncryptor.class.getDeclaredField("nonceCounter");
            field.setAccessible(true);
            AtomicLong counter = (AtomicLong) field.get(f.encryptor);
            counter.set(Long.MAX_VALUE);
            ExecutorService workers = Executors.newFixedThreadPool(4);
            AtomicInteger accepted = new AtomicInteger();
            CountDownLatch ready = new CountDownLatch(4), start = new CountDownLatch(1);
            try {
                Future<?>[] sent = new Future<?>[4];
                for (int i = 0; i < sent.length; i++) {
                    sent[i] = workers.submit(() -> {
                        ready.countDown();
                        start.await();
                        try { f.send(); accepted.incrementAndGet(); }
                        catch (IllegalStateException expected) {
                            assertTrue(expected.getMessage().contains("nonce space exhausted"));
                        }
                        return null;
                    });
                }
                assertTrue(ready.await(5, TimeUnit.SECONDS));
                start.countDown();
                for (Future<?> result : sent) result.get(20, TimeUnit.SECONDS);
            } finally {
                workers.shutdownNow();
                assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
            }
            assertEquals(1, accepted.get());
            assertEquals(java.util.Collections.singleton(Long.MAX_VALUE), f.nonces);
            for (int i = 0; i < 4; i++) assertThrows(IllegalStateException.class, f::send);
            assertEquals(Long.MIN_VALUE, counter.get());
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("ciphers")
    void reinstallingKeyMaterialDoesNotReuseAnEarlierNonce(String name, SecurityProvider provider,
            SMB3EncryptionCipher cipher) throws Exception {
        try (Fixture f = new Fixture(provider, cipher)) {
            f.send();
            byte[] different = new byte[16]; different[0] = 1;
            SecretKey other = new SecretKeySpec(different, "AES");
            f.session.getSessionContext().setEncryptionKey(other);
            f.send();
            f.session.getSessionContext().setEncryptionKey(new SecretKeySpec(new byte[16], "AES"));
            f.send();
            assertEquals(2, f.noncesByKey.get(f.key).size());
            assertEquals(1, f.noncesByKey.get(other).size());
        }
    }

    private static class Fixture implements AutoCloseable {
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final Set<Long> nonces = ConcurrentHashMap.newKeySet();
        final Map<SecretKey, Set<Long>> noncesByKey = new ConcurrentHashMap<>();
        final Set<Connection> usedChannels = ConcurrentHashMap.newKeySet();
        final AtomicLong mids = new AtomicLong();
        final NegotiatedProtocol protocol = new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true);
        final ConnectionContext context = mock(ConnectionContext.class);
        final SMB3EncryptionCipher cipher;
        final PacketEncryptor encryptor;
        final Connection primary, secondary;
        final Session session;

        Fixture(SecurityProvider provider, SMB3EncryptionCipher cipher) throws Exception {
            this.cipher = cipher;
            when(context.getNegotiatedProtocol()).thenReturn(protocol);
            when(context.getCipherId()).thenReturn(cipher);
            encryptor = new PacketEncryptor(provider);
            encryptor.init(context);
            primary = channel(); secondary = channel();
            session = new Session(primary, SmbConfig.builder().withSecurityProvider(provider).build(),
                    null, null, null, null, encryptor);
            session.setSessionId(47);
            session.getSessionContext().setEncryptData(true);
            session.getSessionContext().setEncryptionKey(key);
            session.addChannel(secondary, key);
        }

        Connection channel() throws Exception {
            Connection channel = mock(Connection.class, withSettings().stubOnly());
            when(channel.getNegotiatedProtocol()).thenReturn(protocol);
            when(channel.getConnectionContext()).thenReturn(context);
            when(channel.isConnected()).thenReturn(true);
            when(channel.send(any(SMB2Packet.class))).thenAnswer(call -> {
                SMB2Packet packet = call.getArgument(0);
                SMBBuffer buffer = new SMBBuffer(); packet.write(buffer);
                byte[] wire = buffer.getCompactData();
                byte[] nonce = Arrays.copyOfRange(wire, 20, 20 + cipher.getNonceLength());
                for (int i = 20 + cipher.getNonceLength(); i < 36; i++) assertEquals(0, wire[i]);
                byte[] tagged = Arrays.copyOfRange(wire, 52, wire.length + 16);
                System.arraycopy(wire, 4, tagged, tagged.length - 16, 16);
                Cipher oracle = cipher == SMB3EncryptionCipher.AES_128_GCM
                        ? Cipher.getInstance(cipher.getAlgorithmName())
                        : Cipher.getInstance(cipher.getAlgorithmName(), new BouncyCastleProvider());
                SecretKey actualKey = session.getSessionContext().getEncryptionKey();
                oracle.init(Cipher.DECRYPT_MODE, actualKey, new GCMParameterSpec(128, nonce));
                oracle.updateAAD(wire, 20, 32);
                byte[] plain = oracle.doFinal(tagged);
                SMBBuffer expected = new SMBBuffer(); packet.getPacket().write(expected);
                assertArrayEquals(expected.getCompactData(), plain);
                assertEquals(plain.length, ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN).getInt(36));
                assertEquals(47L, ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN).getLong(44));
                long value = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN).getLong();
                assertTrue(noncesByKey.computeIfAbsent(actualKey, key -> ConcurrentHashMap.newKeySet()).add(value),
                        "reused transform nonce under the same key");
                nonces.add(value);
                usedChannels.add(channel);
                return CompletableFuture.completedFuture(null);
            });
            return channel;
        }

        void send() throws Exception {
            SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
            packet.getHeader().setSessionId(47);
            packet.getHeader().setMessageId(mids.getAndIncrement());
            session.send(packet);
        }

        @Override public void close() {
            session.failChannels(new java.io.IOException("fixture finished"));
        }
    }
}
