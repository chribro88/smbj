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
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
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
                            configuration.getSoTimeout(), handlers), activeChannels, peakChannels);
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

    private static byte pattern(int block) { return (byte) (block * 7 + 3); }

    private static void writeAll(File file) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(WORKERS);
        CountDownLatch ready = new CountDownLatch(WORKERS);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<?>> writes = new ArrayList<>();
            for (int worker = 0; worker < WORKERS; worker++) {
                final int index = worker;
                writes.add(executor.submit(() -> {
                    byte[] bytes = new byte[REQUEST];
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    for (int block = index; block < BLOCKS; block += WORKERS) {
                        Arrays.fill(bytes, pattern(block));
                        assertEquals(REQUEST, file.write(bytes, (long) block * REQUEST));
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
        private int activeCalls;

        MeteredTransport(TransportLayer<SMBPacket<?, ?>> delegate, AtomicInteger activeChannels, AtomicInteger peakChannels) {
            this.delegate = delegate;
            this.activeChannels = activeChannels;
            this.peakChannels = peakChannels;
        }

        public void connect(InetSocketAddress address) throws IOException { delegate.connect(address); }
        public boolean isConnected() { return delegate.isConnected(); }
        public void disconnect() throws IOException { delegate.disconnect(); }
        void reset() { bytes.set(0); writes.set(0); }

        public void write(SMBPacket<?, ?> packet) throws TransportException {
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
