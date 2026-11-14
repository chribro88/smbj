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

import com.hierynomus.protocol.transport.*;
import com.hierynomus.smb.*;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static com.hierynomus.smbj.connection.TransportLifecycleReviewTest.*;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class ConnectionBoundaryReviewTest {
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void abortAroundRealTransportInitializationRejectsNegotiation(boolean beforeEntry) throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.transport.pauseBeforeConnect = beforeEntry;
            fixture.transport.pauseAfterConnect = true;
            FutureTask<IOException> connecting = task(() -> assertThrows(IOException.class,
                    () -> fixture.connection.connect("127.0.0.1", 445)));
            try {
                if (beforeEntry) {
                    await(fixture.transport.entered);
                    fixture.connection.close(true);
                    fixture.transport.enter.countDown();
                    assertNotNull(result(connecting));
                    assertNull(reader(fixture.transport.real));
                    assertEquals(1, fixture.factory.dialing.getCount(), "closed transport must not call the factory");
                } else {
                    await(fixture.transport.initialized);
                    fixture.connection.close(true);
                    assertTrue(fixture.socket.closed);
                }
                fixture.transport.resume.countDown();
                assertNotNull(result(connecting));
                assertFalse(fixture.connection.isConnected());
                if (!beforeEntry) assertTrue(fixture.socket.closed);
                assertEquals(0, fixture.transport.writes.get());
            } finally {
                fixture.transport.enter.countDown();
                fixture.transport.resume.countDown();
                result(connecting);
            }
        }
    }

    @Test
    void closeBetweenSendAdmissionAndTransportWriteCannotTransmitNegotiate() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.transport.pauseWrite = true;
            FutureTask<IOException> connecting = task(() -> assertThrows(IOException.class,
                    () -> fixture.connection.connect("127.0.0.1", 445)));
            try {
                await(fixture.transport.writing);
                fixture.connection.close(true);
                fixture.transport.resumeWrite.countDown();
                assertNotNull(result(connecting));
                assertEquals(1, fixture.transport.writes.get());
                assertEquals(1, fixture.socket.writing.getCount(), "no bytes may reach closed socket");
                assertTrue(fixture.socket.closed);
            } finally {
                fixture.transport.resumeWrite.countDown();
                result(connecting);
            }
        }
    }

    @ParameterizedTest
    @CsvSource({"true,true", "true,false", "false,true", "false,false"})
    void overlappingCloseWaitsForPhysicalTeardownAndPreservesInterrupt(boolean firstForce, boolean force) throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.transport.real.connect(new InetSocketAddress("127.0.0.1", 445));
            fixture.transport.pauseDisconnect = true;
            FutureTask<Void> first = task(() -> { fixture.connection.close(firstForce); return null; });
            java.util.concurrent.atomic.AtomicReference<Thread> waiter = new java.util.concurrent.atomic.AtomicReference<>();
            FutureTask<Boolean> second = null;
            try {
                await(fixture.transport.disconnecting);
                second = task(() -> {
                    waiter.set(Thread.currentThread());
                    fixture.connection.close(force);
                    assertTrue(fixture.socket.closed);
                    return Thread.currentThread().isInterrupted();
                });
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                while (System.nanoTime() < deadline && (waiter.get() == null || waiter.get().getState() != Thread.State.WAITING)) {
                    assertFalse(second.isDone(), "second close returned before physical teardown");
                    Thread.yield();
                }
                assertNotNull(waiter.get());
                assertEquals(Thread.State.WAITING, waiter.get().getState());
                waiter.get().interrupt();
                FutureTask<Boolean> waiting = second;
                // Interrupting a close waiter must not turn it into an early successful close.
                assertThrows(TimeoutException.class, () -> waiting.get(100, TimeUnit.MILLISECONDS));
                assertFalse(fixture.connection.isConnected());
                assertFalse(fixture.socket.closed, "first closer still owns physical cleanup");
                assertFalse(first.isDone());
            } finally {
                fixture.transport.resumeDisconnect.countDown();
                result(first);
                if (second != null) assertTrue(result(second));
            }
            assertTrue(fixture.socket.closed);
        }
    }

    static void await(CountDownLatch latch) throws InterruptedException {
        assertTrue(latch.await(3, TimeUnit.SECONDS), "review barrier timed out");
    }

    @Test
    void teardownFailureIsReportedToEveryCloserWithoutBlockingErrorCallbacks() throws Exception {
        Fixture fixture = new Fixture();
        IOException failure = new IOException("controlled disconnect failure");
        fixture.transport.disconnectFailure = failure;
        fixture.transport.pauseDisconnect = true;
        FutureTask<IOException> first = task(() -> assertThrows(IOException.class, () -> fixture.connection.close(true)));
        FutureTask<IOException> second = null;
        try {
            await(fixture.transport.disconnecting);
            second = task(() -> assertThrows(IOException.class, () -> fixture.connection.close(true)));
            FutureTask<IOException> waiting = second;
            assertThrows(TimeoutException.class, () -> waiting.get(100, TimeUnit.MILLISECONDS));
            result(task(() -> { fixture.connection.handleError(new IOException("reader error during teardown")); return null; }));
        } finally {
            fixture.transport.resumeDisconnect.countDown();
            assertSame(failure, result(first));
            if (second != null) assertSame(failure, result(second));
            assertSame(failure, assertThrows(IOException.class, fixture::close));
        }
        assertTrue(fixture.socket.closed);
    }

    static class Fixture implements AutoCloseable {
        final ControlledSocket socket = new ControlledSocket(false);
        final ControlledFactory factory = new ControlledFactory(socket, false);
        final GateTransport transport = new GateTransport(new DirectTcpTransport<>(factory, 0, HANDLERS));
        final SmbConfig config = SmbConfig.builder().withTransportLayerFactory((handlers, settings) -> transport).build();
        final Connection connection = new Connection(config, null, new SMBEventBus(), new ServerList());

        public void close() throws Exception {
            transport.enter.countDown();
            transport.resume.countDown();
            transport.resumeWrite.countDown();
            transport.resumeDisconnect.countDown();
            socket.close();
            connection.close(true);
            transport.real.disconnect();
            Thread reader = reader(transport.real);
            if (reader != null) { reader.join(3000); assertFalse(reader.isAlive()); }
        }
    }

    static class GateTransport implements TransportLayer<SMBPacket<?, ?>> {
        final DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> real;
        final CountDownLatch entered = new CountDownLatch(1), enter = new CountDownLatch(1);
        final CountDownLatch initialized = new CountDownLatch(1), resume = new CountDownLatch(1);
        final CountDownLatch writing = new CountDownLatch(1), resumeWrite = new CountDownLatch(1);
        final CountDownLatch disconnecting = new CountDownLatch(1), resumeDisconnect = new CountDownLatch(1);
        final AtomicInteger writes = new AtomicInteger();
        boolean pauseBeforeConnect, pauseAfterConnect, pauseWrite, pauseDisconnect;
        IOException disconnectFailure;
        GateTransport(DirectTcpTransport<SMBPacketData<?>, SMBPacket<?, ?>> real) { this.real = real; }
        static void gate(CountDownLatch signal, CountDownLatch resume) throws IOException {
            signal.countDown();
            try {
                if (!resume.await(5, TimeUnit.SECONDS)) throw new IOException("review barrier timed out");
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IOException(interrupted);
            }
        }
        public void connect(InetSocketAddress address) throws IOException {
            if (pauseBeforeConnect) gate(entered, enter);
            real.connect(address);
            initialized.countDown();
            if (pauseAfterConnect) gate(initialized, resume);
        }
        public void disconnect() throws IOException {
            if (pauseDisconnect) gate(disconnecting, resumeDisconnect);
            real.disconnect();
            if (disconnectFailure != null) throw disconnectFailure;
        }
        public boolean isConnected() { return real.isConnected(); }
        public void write(SMBPacket<?, ?> packet) throws TransportException {
            writes.incrementAndGet();
            try { if (pauseWrite) gate(writing, resumeWrite); }
            catch (IOException failure) { throw new TransportException(failure); }
            real.write(packet);
        }
    }
}
