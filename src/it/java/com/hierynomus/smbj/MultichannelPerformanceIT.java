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
package com.hierynomus.smbj;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.*;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.PacketSignatory;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransportFactory;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.SecretKey;
import java.util.stream.Collectors;

import static com.hierynomus.smbj.testing.MultichannelTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Opt-in end-to-end transfer measurements, not a microbenchmark or a sustained throughput guarantee. */
class MultichannelPerformanceIT {
    private static final int REQUEST = 1048576;
    private static final int BLOCKS = 32;
    private static final int WORKERS = 4;

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 4})
    void measuresTheSameVerifiedWorkload(int channelCount) throws Exception {
        assumeTrue(Boolean.parseBoolean(System.getenv("SMB_TEST_PERFORMANCE")), "Opt-in SMB_TEST_PERFORMANCE");
        String port = System.getenv("SMB_TEST_PORT");
        assertNotNull(port, "SMB_TEST_PORT must identify the dedicated performance fixture");
        boolean encryption = Boolean.parseBoolean(System.getenv().getOrDefault("SMB_TEST_PERF_ENCRYPTION", "true"));
        List<MeteredTransport> transports = new CopyOnWriteArrayList<>();
        AtomicInteger activeChannels = new AtomicInteger();
        AtomicInteger peakChannels = new AtomicInteger();
        SmbConfig settings = SmbConfig.builder(config(encryption)).withReadBufferSize(REQUEST).withWriteBufferSize(REQUEST)
                .withTransportLayerFactory((handlers, configuration) -> {
                    MeteredTransport transport = new MeteredTransport(new DirectTcpTransport<>(configuration.getSocketFactory(),
                            configuration.getSoTimeout(), handlers), activeChannels, peakChannels, transports, null, null);
                    transports.add(transport);
                    return transport;
                }).build();
        String name = "perf-" + UUID.randomUUID() + ".bin";
        try (SMBClient client = new SMBClient(settings);
             Connection primary = client.connect(hostname(), Integer.parseInt(port));
             Session session = primary.authenticate(authentication());
             DiskShare share = (DiskShare) session.connectShare(shareName())) {
            try (File file = share.openFile(name, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE,
                    EnumSet.noneOf(SMB2CreateOptions.class))) {
                for (int i = 1; i < channelCount; i++) client.openChannel(session, hostname(), Integer.parseInt(port));
                assertEquals(channelCount, session.getChannelCount());
                assertEquals(REQUEST, file.getWriteRequestSize());
                // Same warmup and same bounded workload for every channel count. Report every sample.
                byte[] warmup = new byte[REQUEST];
                for (int i = 0; i < WORKERS; i++) assertEquals(REQUEST, file.write(warmup, (long) i * REQUEST));
                com.sun.management.OperatingSystemMXBean os = (com.sun.management.OperatingSystemMXBean)
                        ManagementFactory.getOperatingSystemMXBean();
                for (int sample = 1; sample <= 3; sample++) {
                    transports.forEach(MeteredTransport::reset);
                    peakChannels.set(0);
                    long cpuStart = os.getProcessCpuTime();
                    long start = System.nanoTime();
                    writeAll(file);
                    file.flush();
                    long elapsed = System.nanoTime() - start;
                    long cpu = os.getProcessCpuTime() - cpuStart;
                    byte[] actual = new byte[REQUEST];
                    byte[] expected = new byte[REQUEST];
                    for (int block = 0; block < BLOCKS; block++) {
                        Arrays.fill(expected, pattern(block));
                        assertEquals(REQUEST, file.read(actual, (long) block * REQUEST));
                        assertArrayEquals(expected, actual, "Block " + block);
                    }
                    long bytes = transports.stream().mapToLong(transport -> transport.bytes.get()).sum();
                    assertEquals((long) REQUEST * BLOCKS, bytes);
                    assertEquals(channelCount, transports.size());
                    for (MeteredTransport transport : transports) assertTrue(transport.bytes.get() > 0);
                    if (channelCount > 1) assertTrue(peakChannels.get() > 1, "Write calls must overlap across physical channels");
                    System.out.printf(Locale.ROOT, "PERF channels=%d sample=%d payloadBytes=%d verifiedBytes=%d requestBytes=%d workers=%d "
                                    + "encryption=%s dialect=%s elapsedNanos=%d clientCpuNanos=%d MiBps=%.2f "
                                    + "writeBytesByConnection=%s writeRequestsByConnection=%s peakActiveChannels=%d%n",
                            channelCount, sample, bytes, (long) REQUEST * BLOCKS, REQUEST, WORKERS, encryption, dialect(), elapsed, cpu,
                            bytes * 1e9 / elapsed / REQUEST,
                            transports.stream().map(transport -> transport.bytes.toString()).collect(Collectors.joining(",")),
                            transports.stream().map(transport -> transport.writes.toString()).collect(Collectors.joining(",")), peakChannels.get());
                }
            } finally {
                share.rm(name);
            }
        }
    }

    @ParameterizedTest
    @CsvSource({"false,false,false", "false,true,false", "true,false,false", "true,true,false",
            "false,false,true", "false,true,true", "true,false,true", "true,true,true"})
    @Timeout(value = 10, unit = TimeUnit.MINUTES)
    void sustainedBindingChurnKeepsResourcesBounded(boolean async, boolean jce, boolean encryption) throws Exception {
        assumeTrue(Boolean.parseBoolean(System.getenv("SMB_TEST_CHURN")), "Opt-in native channel churn");
        int port = Integer.parseInt(System.getenv("SMB_TEST_PORTS"));
        int cycles = Integer.parseInt(System.getenv().getOrDefault("SMB_TEST_CHURN_CYCLES", "64"));
        assertTrue(cycles > 0 && cycles <= 10000, "Explicit bounded churn workload");
        ChurnProbe probe = new ChurnProbe();
        List<MeteredTransport> transports = new CopyOnWriteArrayList<>();
        AtomicInteger active = new AtomicInteger(), peak = new AtomicInteger();
        AtomicInteger sessions = new AtomicInteger(), connections = new AtomicInteger();
        SMBEventBus bus = new SMBEventBus() {
            @Override public void subscribe(Object listener) {
                super.subscribe(listener);
                if (listener instanceof Session) sessions.incrementAndGet();
                if (listener instanceof Connection) connections.incrementAndGet();
            }
            @Override public boolean unsubscribe(Object listener) {
                boolean removed = super.unsubscribe(listener);
                if (removed && listener instanceof Session) sessions.decrementAndGet();
                if (removed && listener instanceof Connection) connections.decrementAndGet();
                return removed;
            }
        };
        SmbConfig settings = SmbConfig.builder(config(encryption)).withDirectoryLeasingEnabled(false)
                .withSecurityProvider(jce ? new JceSecurityProvider() : new BCSecurityProvider())
                .withAuthenticators(new NtlmAuthenticator.Factory())
                .withTransportLayerFactory((handlers, configuration) -> {
                    TransportLayer<SMBPacket<?, ?>> delegate = async
                            ? new AsyncDirectTcpTransportFactory().createTransportLayer(handlers, configuration)
                            : new DirectTcpTransport<>(configuration.getSocketFactory(), configuration.getSoTimeout(), handlers);
                    MeteredTransport transport = new MeteredTransport(delegate, active, peak, transports, probe,
                            (Connection) handlers.getReceiver());
                    transports.add(transport);
                    return transport;
                }).build();
        String name = "churn-" + UUID.randomUUID() + ".bin";
        List<Long> bindTimes = new ArrayList<>();
        long started = System.nanoTime(), cpuBefore = cpuNanos(), gcBefore = gcCount();
        long fdBefore, fdAfter, heapBefore, heapAfter, firstEchoes = -1, lastEchoes = -1;
        int failures = 0, collected, threadsBefore, threadsAfter;
        SMB3EncryptionCipher selectedCipher;
        ExecutorService binder = Executors.newSingleThreadExecutor();
        try (SMBClient client = new SMBClient(settings, bus);
             Connection primary = client.connect(hostname(), port);
             Session session = primary.authenticate(authentication());
             DiskShare share = (DiskShare) session.connectShare(shareName())) {
            probe.sessionId = session.getSessionId();
            probe.originalKey = session.getSessionContext().getSigningKey().getEncoded().clone();
            probe.encryptor = field(session, "encryptor");
            probe.encryptionKey = session.getSessionContext().getEncryptionKey();
            selectedCipher = primary.getConnectionContext().getCipherId();
            if (encryption) {
                assertEquals(SMB3EncryptionCipher.AES_128_GCM, selectedCipher);
                assertNotNull(probe.encryptionKey);
            } else assertNull(selectedCipher);
            probe.bound(session, primary);
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, primary.getConnectionContext().getSigningAlgorithm());
            probe.bound(session, client.openChannel(session, hostname(), port));
            try (File file = share.openFile(name, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE,
                    EnumSet.noneOf(SMB2CreateOptions.class))) {
                writeAll(file, 65536, WORKERS, 0); verifyAll(file, 65536, WORKERS, 0);
                assertSteadyState(session, client, transports, sessions, connections);
                System.gc(); fdBefore = openDescriptors(); heapBefore = usedHeap();
                threadsBefore = ManagementFactory.getThreadMXBean().getThreadCount();
                for (int cycle = 1; cycle <= cycles; cycle++) {
                    if (cycle % 8 == 0) {
                        probe.failBinding.set(true);
                        assertThrows(IOException.class, () -> client.openChannel(session, hostname(), port));
                        assertFalse(probe.failBinding.get(), "The prepared binding fault must be reached");
                        failures++;
                        assertSteadyState(session, client, transports, sessions, connections);
                    }
                    long echoesBefore = probe.echoes.get();
                    long elapsed = churnOnce(client, session, file, port, binder, probe, cycle);
                    bindTimes.add(elapsed);
                    long echoes = probe.echoes.get() - echoesBefore;
                    if (firstEchoes < 0) firstEchoes = echoes;
                    lastEchoes = echoes;
                    assertSteadyState(session, client, transports, sessions, connections);
                    assertArrayEquals(probe.originalKey, session.getSessionContext().getSigningKey().getEncoded());
                    assertSame(probe.encryptor, field(session, "encryptor"));
                    assertSame(probe.encryptionKey, session.getSessionContext().getEncryptionKey());
                    assertTrue(openDescriptors() <= fdBefore + 4, "Retired sockets must release descriptors");
                    System.out.printf("GMAC_CHURN_SAMPLE transport=%s provider=%s encrypt=%s cycle=%d bindNanosExcludingGate=%d collisionEchoes=%d cursor=%s descriptors=%d%n",
                            async ? "async" : "direct", jce ? "default-JCE" : "BC", encryption,
                            cycle, elapsed, echoes, Long.toUnsignedString(cursor(session)), openDescriptors());
                }
                for (int attempt = 0; attempt < 3 && probe.reachableRetired() != 0; attempt++) System.gc();
                collected = probe.retired.size() - probe.reachableRetired();
                assertEquals(probe.retired.size(), collected, "Retired Connection objects must be collectible");
                fdAfter = openDescriptors(); heapAfter = usedHeap();
                threadsAfter = ManagementFactory.getThreadMXBean().getThreadCount();
                assertTrue(threadsAfter <= threadsBefore + 8, "Live thread growth must not follow replacement history");
            } finally { share.rm(name); }
        } finally {
            probe.gate.set(null);
            binder.shutdownNow(); assertTrue(binder.awaitTermination(10, TimeUnit.SECONDS));
        }
        assertTrue(transports.isEmpty());
        assertEquals(0, sessions.get()); assertEquals(0, connections.get());
        Collections.sort(bindTimes);
        System.out.printf("GMAC_CHURN_COMPLETE java=%s provider=%s transport=%s signing=AES_GMAC encrypt=%s cipher=%s cycles=%d preparedFailures=%d "
                        + "bindP50Nanos=%d bindP99Nanos=%d firstCollisionEchoes=%d lastCollisionEchoes=%d totalCollisionEchoes=%d "
                        + "originalKeyInputs=%d freshChannelKeys=%d retiredCollected=%d descriptorsBefore=%d descriptorsAfter=%d heapBefore=%d heapAfter=%d threadsBefore=%d threadsAfter=%d "
                        + "elapsedNanos=%d cpuNanos=%d gcCollections=%d payloadBytes=%d processors=%d maxHeap=%d%n",
                System.getProperty("java.version"), jce ? "default-JCE" : "BC", async ? "async" : "direct", encryption,
                selectedCipher, cycles, failures,
                bindTimes.get(bindTimes.size() / 2), bindTimes.get(Math.min(bindTimes.size() - 1, (int) Math.ceil(bindTimes.size() * .99) - 1)),
                firstEchoes, lastEchoes, probe.echoes.get(), probe.originalMids.size(), probe.boundKeys.size(), collected, fdBefore, fdAfter, heapBefore, heapAfter, threadsBefore, threadsAfter,
                System.nanoTime() - started, cpuNanos() - cpuBefore, gcCount() - gcBefore,
                (long) cycles * WORKERS * 65536, Runtime.getRuntime().availableProcessors(), Runtime.getRuntime().maxMemory());
    }

    private static long churnOnce(SMBClient client, Session session, File file, int port,
            ExecutorService binder, ChurnProbe probe, int generation) throws Exception {
        Gate gate = new Gate(); probe.gate.set(gate);
        long start = System.nanoTime();
        Future<Connection> opening = binder.submit(() -> client.openChannel(session, hostname(), port));
        Connection candidate = null;
        try {
            assertTrue(gate.entered.await(20, TimeUnit.SECONDS), "Binding must reach its reserved first request");
            long beforeIo = cursor(session);
            writeAll(file, 65536, WORKERS, generation); verifyAll(file, 65536, WORKERS, generation);
            assertEquals(beforeIo, cursor(session), "Application I/O cannot advance the original-key binding cursor");
            gate.releasedAt = System.nanoTime(); gate.release.countDown();
            candidate = opening.get(20, TimeUnit.SECONDS);
            long elapsed = System.nanoTime() - start - (gate.releasedAt - gate.enteredAt);
            assertEquals(3, session.getChannelCount());
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, candidate.getConnectionContext().getSigningAlgorithm());
            probe.bound(session, candidate);
            com.hierynomus.mssmb2.messages.SMB2Echo echo = new com.hierynomus.mssmb2.messages.SMB2Echo(SMB2Dialect.SMB_3_1_1);
            echo.getHeader().setSessionId(session.getSessionId());
            assertEquals(0, session.<SMB2Packet>send(echo, candidate).get(5, TimeUnit.SECONDS).getHeader().getStatusCode());
            return elapsed;
        } finally {
            gate.release.countDown(); probe.gate.set(null);
            if (candidate != null) candidate.close(true);
        }
    }

    private static void assertSteadyState(Session session, SMBClient client, List<MeteredTransport> transports,
            AtomicInteger sessions, AtomicInteger connections) throws Exception {
        assertEquals(2, session.getChannelCount()); assertEquals(2, transports.size());
        assertEquals(1, sessions.get()); assertEquals(2, connections.get());
        assertEquals(2, ((Map<?, ?>) field(session, "channelKeys")).size());
        assertEquals(1, ((Set<?>) field(session, "ownedChannels")).size());
        assertTrue(((Map<?, ?>) field(session, "pendingChannels")).isEmpty());
        assertEquals(1, ((Collection<?>) field(client, "channelConnections")).size());
        assertEquals(1, ((Map<?, ?>) field(client, "connectionTable")).size());
        assertTrue(((Set<?>) field(session, "bootstrapMessageIds")).size() <= 16);
    }

    private static Object field(Object owner, String name) throws Exception {
        Field field = owner.getClass().getDeclaredField(name); field.setAccessible(true); return field.get(owner);
    }
    private static long cursor(Session session) throws Exception { return ((AtomicLong) field(session, "originalKeyMessageIdReservation")).get(); }
    private static long openDescriptors() { return ((com.sun.management.UnixOperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean()).getOpenFileDescriptorCount(); }
    private static long cpuNanos() { return ((com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean()).getProcessCpuTime(); }
    private static long gcCount() { return ManagementFactory.getGarbageCollectorMXBeans().stream().mapToLong(gc -> Math.max(0, gc.getCollectionCount())).sum(); }
    private static long usedHeap() { return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed(); }

    private static final class Gate {
        final CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        final AtomicBoolean claimed = new AtomicBoolean();
        volatile long enteredAt, releasedAt;
    }

    private static final class ChurnProbe {
        final AtomicLong echoes = new AtomicLong();
        final Set<Long> originalMids = ConcurrentHashMap.newKeySet();
        final Set<String> boundKeys = ConcurrentHashMap.newKeySet();
        final List<WeakReference<Connection>> retired = new CopyOnWriteArrayList<>();
        final AtomicBoolean failBinding = new AtomicBoolean();
        final AtomicReference<Gate> gate = new AtomicReference<>();
        volatile long sessionId;
        volatile byte[] originalKey;
        Object encryptor;
        SecretKey encryptionKey;
        final Field signingKey;
        ChurnProbe() throws Exception {
            signingKey = PacketSignatory.SignedPacketWrapper.class.getDeclaredField("secretKey"); signingKey.setAccessible(true);
        }
        int reachableRetired() { return (int) retired.stream().filter(reference -> reference.get() != null).count(); }
        void bound(Session session, Connection channel) throws Exception {
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, channel.getConnectionContext().getSigningAlgorithm());
            assertEquals(encryptionKey == null ? null : SMB3EncryptionCipher.AES_128_GCM, channel.getConnectionContext().getCipherId());
            com.hierynomus.mssmb2.messages.SMB2Echo echo = new com.hierynomus.mssmb2.messages.SMB2Echo(SMB2Dialect.SMB_3_1_1);
            byte[] key = session.getSigningKey(echo.getHeader(), false, channel).getEncoded();
            assertFalse(Arrays.equals(originalKey, key));
            assertTrue(boundKeys.add(Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(key))),
                    "Every verified operational channel has fresh actual signing-key bytes");
        }
        void beforeWrite(SMB2Packet packet) throws TransportException {
            if (packet.getHeader().getMessage() == SMB2MessageCommandCode.SMB2_ECHO && packet.getHeader().getSessionId() == 0) echoes.incrementAndGet();
            if (sessionId == 0 || packet.getHeader().getSessionId() != sessionId
                    || packet.getHeader().getMessage() != SMB2MessageCommandCode.SMB2_SESSION_SETUP) return;
            try { assertArrayEquals(originalKey, ((SecretKey) signingKey.get(packet)).getEncoded()); }
            catch (IllegalAccessException failure) { throw new AssertionError(failure); }
            assertTrue(originalMids.add(packet.getHeader().getMessageId()), "Prepared original-key binding inputs cannot reuse a MID");
            if (failBinding.getAndSet(false)) throw new TransportException("Injected prepared binding write failure");
            Gate held = gate.get();
            if (held != null && held.claimed.compareAndSet(false, true)) {
                held.enteredAt = System.nanoTime(); held.entered.countDown();
                try { assertTrue(held.release.await(60, TimeUnit.SECONDS), "Application I/O must release the binding gate"); }
                catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new TransportException(failure); }
            }
        }
    }

    private static byte pattern(int block) { return (byte) (block * 7 + 3); }

    private static void writeAll(File file) throws Exception {
        writeAll(file, REQUEST, BLOCKS, 0);
    }

    private static void fill(byte[] bytes, int block, int generation) {
        Arrays.fill(bytes, pattern(block));
        if (generation != 0) java.nio.ByteBuffer.wrap(bytes).putInt(generation);
    }

    private static void verifyAll(File file, int request, int blocks, int generation) throws Exception {
        byte[] expected = new byte[request], actual = new byte[request];
        for (int block = 0; block < blocks; block++) {
            fill(expected, block, generation);
            assertEquals(request, file.read(actual, (long) block * request)); assertArrayEquals(expected, actual);
        }
    }

    private static void writeAll(File file, int request, int blocks, int generation) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(WORKERS);
        CountDownLatch ready = new CountDownLatch(WORKERS);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<?>> writes = new ArrayList<>();
            for (int worker = 0; worker < WORKERS; worker++) {
                final int index = worker;
                writes.add(executor.submit(() -> {
                    byte[] bytes = new byte[request];
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    for (int block = index; block < blocks; block += WORKERS) {
                        fill(bytes, block, generation);
                        assertEquals(request, file.write(bytes, (long) block * request));
                    }
                    return null;
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            for (Future<?> write : writes) write.get(60, TimeUnit.SECONDS);
        } finally {
            start.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    // Observe already credit-sized packets; do not serialize/consume a WRITE provider a second time.
    private static class MeteredTransport implements TransportLayer<SMBPacket<?, ?>> {
        final TransportLayer<SMBPacket<?, ?>> delegate;
        final AtomicLong bytes = new AtomicLong();
        final AtomicInteger writes = new AtomicInteger();
        final AtomicInteger activeChannels;
        final AtomicInteger peakChannels;
        final List<MeteredTransport> registry;
        final ChurnProbe probe;
        final WeakReference<Connection> owner;
        private int activeCalls;

        MeteredTransport(TransportLayer<SMBPacket<?, ?>> delegate, AtomicInteger activeChannels, AtomicInteger peakChannels,
                List<MeteredTransport> registry, ChurnProbe probe, Connection owner) {
            this.delegate = delegate;
            this.activeChannels = activeChannels;
            this.peakChannels = peakChannels;
            this.registry = registry; this.probe = probe; this.owner = new WeakReference<>(owner);
        }

        public void connect(InetSocketAddress address) throws IOException { delegate.connect(address); }
        public boolean isConnected() { return delegate.isConnected(); }
        public void disconnect() throws IOException {
            try { delegate.disconnect(); }
            finally { if (registry.remove(this) && probe != null) probe.retired.add(owner); }
        }
        void reset() { bytes.set(0); writes.set(0); }

        public void write(SMBPacket<?, ?> packet) throws TransportException {
            if (probe != null) probe.beforeWrite((SMB2Packet) packet);
            if (!(packet instanceof SMB2Packet) || ((SMB2Packet) packet).getHeader().getMessage() != SMB2MessageCommandCode.SMB2_WRITE) {
                delegate.write(packet);
                return;
            }
            SMB2Packet smb = (SMB2Packet) packet;
            int payload = Math.min(smb.getMaxPayloadSize(), smb.getCreditsAssigned() * SMB2Packet.SINGLE_CREDIT_PAYLOAD_SIZE);
            synchronized (this) {
                if (++activeCalls == 1) peakChannels.accumulateAndGet(activeChannels.incrementAndGet(), Math::max);
            }
            try {
                delegate.write(packet);
                bytes.addAndGet(payload);
                writes.incrementAndGet();
            } finally {
                synchronized (this) {
                    if (--activeCalls == 0) activeChannels.decrementAndGet();
                }
            }
        }
    }
}
