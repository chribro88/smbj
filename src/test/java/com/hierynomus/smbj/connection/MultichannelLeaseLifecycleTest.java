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
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.*;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.TreeConnect;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(10)
class MultichannelLeaseLifecycleTest {
    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false"})
    void secondaryBreakReachesSharedLeaseAndSendsOneSignedAck(boolean legacyRegistry, boolean retirePrimary) throws Exception {
        try (Fixture fixture = new Fixture()) {
            LeaseManager owner = legacyRegistry ? fixture.primary.getLeaseManager() : fixture.session.getLeaseManager();
            LeaseEntry lease = fixture.register(owner);
            if (retirePrimary) {
                fixture.primary.close(true);
                assertSame(lease, owner.lookup(lease.getLeaseKey()));
                assertNotNull(lease.getCache().serve("directory", FileIdBothDirectoryInformation.class, null));
            }
            fixture.secondary.handle(notification(lease.getLeaseKey()));
            drain(owner);
            assertTrue(lease.isBroken());
            assertEquals(1, lease.getCacheGeneration());
            assertNull(lease.getCache().serve("directory", FileIdBothDirectoryInformation.class, null));
            assertEquals(1, fixture.first.acknowledgements.get() + fixture.second.acknowledgements.get());
            fixture.secondary.handle(notification(lease.getLeaseKey()));
            drain(owner);
            assertEquals(1, lease.getCacheGeneration());
            assertEquals(1, fixture.first.acknowledgements.get() + fixture.second.acknowledgements.get());
            if (retirePrimary) {
                assertEquals(1, fixture.second.acknowledgements.get());
            }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void forcedChannelRetirementDoesNotCloseCacheHandleThroughSurvivor(boolean legacyRegistry) throws Exception {
        try (Fixture fixture = new Fixture()) {
            LeaseManager owner = legacyRegistry ? fixture.primary.getLeaseManager() : fixture.session.getLeaseManager();
            LeaseEntry lease = fixture.register(owner);
            Directory directory = fixture.cacheDirectory(lease);
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                worker.submit(() -> {
                    fixture.primary.close(true);
                    return null;
                }).get(1, TimeUnit.SECONDS);
                assertTrue(fixture.primary.isClosed());
                assertTrue(fixture.secondary.isConnected());
                assertEquals(0, fixture.second.closes.get());
                if (legacyRegistry) {
                    assertNull(lease.getCacheDirectory());
                    assertNull(owner.lookup(lease.getLeaseKey()));
                } else {
                    assertSame(directory, lease.getCacheDirectory());
                    assertSame(lease, owner.lookup(lease.getLeaseKey()));
                }
                fixture.secondary.close(true);
                assertNull(lease.getCacheDirectory());
                assertNull(owner.lookup(lease.getLeaseKey()));
                assertEquals(0, fixture.first.closes.get() + fixture.second.closes.get());
                assertThrows(IllegalStateException.class, () -> owner.register(lease));
                assertDoesNotThrow(() -> owner.dispatchBreak(new com.hierynomus.mssmb2.messages.SMB2LeaseBreakNotification()));
            } finally {
                worker.shutdownNow();
                assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS));
            }
        }
    }

    private static class Fixture implements AutoCloseable {
        final RecordingTransport first = new RecordingTransport(0);
        final RecordingTransport second = new RecordingTransport(1);
        final SMBEventBus bus = new SMBEventBus();
        final SmbConfig config;
        final Connection primary;
        final Connection secondary;
        final Session session;

        Fixture() throws Exception {
            Queue<RecordingTransport> transports = new ArrayDeque<>(Arrays.asList(first, second));
            config = SmbConfig.builder().withTransactTimeout(30, TimeUnit.SECONDS)
                    .withTransportLayerFactory((handlers, settings) -> transports.remove()).build();
            primary = new Connection(config, null, bus, new ServerList());
            secondary = new Connection(config, null, bus, new ServerList());
            for (Connection connection : Arrays.asList(primary, secondary)) {
                ConnectionContext context = new ConnectionContext(config.getClientGuid(), "review.invalid", 445, config);
                context.getServer().init(new UUID(1, 2), SMB2Dialect.SMB_3_1_1, 1,
                        EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL,
                                SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU,
                                SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING));
                set(context, "negotiatedProtocol", new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
                set(connection, "connectionContext", context);
            }
            session = new Session(primary, config, null, bus, PathResolver.LOCAL,
                    new PacketSignatory(config.getSecurityProvider()), null);
            session.setSessionId(47);
            session.getSessionContext().setSigningKey(first.key);
            session.addChannel(secondary, second.key);
            primary.getSessionTable().registerSession(47L, session);
            secondary.getSessionTable().registerSession(47L, session);
        }

        LeaseEntry register(LeaseManager owner) {
            LeaseKey key = owner.leaseKeyForPath("directory");
            LeaseEntry entry = new LeaseEntry(key, null, SMB2LeaseState.readHandle(), "directory");
            entry.setGranted(true);
            entry.setGrantedState(SMB2LeaseState.readHandle());
            entry.setOwner(session, 13, SMB2Dialect.SMB_3_1_1);
            entry.getCache().populate("directory", FileIdBothDirectoryInformation.class, null, Collections.emptyList());
            owner.register(entry);
            return entry;
        }

        Directory cacheDirectory(LeaseEntry lease) throws Exception {
            SmbPath sharePath = new SmbPath("review.invalid", "share");
            TreeConnect tree = new TreeConnect(13, sharePath, session, Collections.emptySet(), config,
                    primary.getConnectionContext(), bus, Collections.<AccessMask>emptySet(), Collections.emptySet());
            DiskShare share = new DiskShare(sharePath, tree, null);
            Constructor<Directory> constructor = Directory.class.getDeclaredConstructor(
                    SMB2FileId.class, DiskShare.class, SmbPath.class, LeaseEntry.class);
            constructor.setAccessible(true);
            Directory directory = constructor.newInstance(new SMB2FileId(new byte[8], new byte[8]), share,
                    new SmbPath(sharePath, "directory"), lease);
            lease.setCacheDirectory(directory);
            return directory;
        }

        public void close() throws Exception {
            try {
                primary.close(true);
            } finally {
                secondary.close(true);
            }
        }
    }

    private static class RecordingTransport implements TransportLayer<SMBPacket<?, ?>> {
        final SecretKeySpec key;
        final AtomicInteger acknowledgements = new AtomicInteger();
        final AtomicInteger closes = new AtomicInteger();
        volatile boolean connected = true;

        RecordingTransport(int value) {
            byte[] bytes = new byte[16];
            bytes[0] = (byte) value;
            key = new SecretKeySpec(bytes, "AesCmac");
        }

        public void write(SMBPacket<?, ?> packet) {
            SMB2PacketHeader header = (SMB2PacketHeader) packet.getHeader();
            if (header.getMessage() == SMB2MessageCommandCode.SMB2_CLOSE) {
                closes.incrementAndGet();
            }
            if (header.getMessage() == SMB2MessageCommandCode.SMB2_OPLOCK_BREAK) {
                SMBBuffer buffer = new SMBBuffer();
                packet.write(buffer);
                byte[] wire = buffer.getCompactData();
                byte[] signature = Arrays.copyOfRange(wire, 48, 64);
                Arrays.fill(wire, 48, 64, (byte) 0);
                CMac oracle = new CMac(AESEngine.newInstance());
                oracle.init(new KeyParameter(key.getEncoded()));
                oracle.update(wire, 0, wire.length);
                byte[] expected = new byte[16];
                oracle.doFinal(expected, 0);
                assertTrue(header.isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SIGNED));
                assertArrayEquals(expected, signature);
                acknowledgements.incrementAndGet();
            }
        }

        public void connect(InetSocketAddress address) { connected = true; }
        public void disconnect() { connected = false; }
        public boolean isConnected() { return connected; }
    }

    private static SMB2PacketData notification(LeaseKey key) throws Exception {
        SMBBuffer buffer = new SMBBuffer();
        buffer.putRawBytes(new byte[]{(byte) 0xfe, 0x53, 0x4d, 0x42});
        buffer.putUInt16(64); buffer.putUInt16(0); buffer.putUInt32(0);
        buffer.putUInt16(0x12); buffer.putUInt16(0); buffer.putUInt32(1); buffer.putUInt32(0);
        buffer.putLong(-1L); buffer.putUInt32(0); buffer.putUInt32(0); buffer.putLong(0); buffer.putReserved(16);
        buffer.putUInt16(44); buffer.putUInt16(1); buffer.putUInt32(1);
        buffer.putRawBytes(key.getBytes());
        buffer.putUInt32(SMB2LeaseState.readHandle()); buffer.putUInt32(0); buffer.putReserved(12);
        return new SMB2PacketData(buffer.getCompactData());
    }

    private static void drain(LeaseManager manager) throws Exception {
        Field field = LeaseManager.class.getDeclaredField("breakExecutor");
        field.setAccessible(true);
        ((ExecutorService) field.get(manager)).submit(() -> { }).get(2, TimeUnit.SECONDS);
    }

    private static void set(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
