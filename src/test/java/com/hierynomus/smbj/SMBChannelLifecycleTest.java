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

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SMBChannelLifecycleTest {
    // Behavioral regression: go-smb2 7f69f658, TestCloseAndAbortInterruptPendingBind.
    @ParameterizedTest
    @CsvSource({"false,false,false", "false,true,false", "true,false,false", "true,true,false", "false,false,true", "true,false,true"})
    void shutdownInterruptsPendingNegotiateWithoutPublishingChannel(boolean closeClient, boolean holdWrite, boolean holdConnect) throws Exception {
        WaitingTransport transport = new WaitingTransport(holdWrite, holdConnect);
        SmbConfig config = SmbConfig.builder().withTransportLayerFactory((handlers, settings) -> transport).build();
        SMBClient client = new SMBClient(config);
        Connection primary = mock(Connection.class);
        when(primary.getRemoteHostname()).thenReturn("localhost");
        when(primary.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
        Session session = spy(new Session(primary, config, null, null, null, null, null));
        doNothing().when(session).logoff();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        Future<Connection> binding = worker.submit(() -> client.openChannel(session, "127.0.0.1", 445));
        try {
            assertTrue(transport.negotiating.await(3, TimeUnit.SECONDS));
            if (closeClient) client.close();
            else session.close();
            ExecutionException failure = assertThrows(ExecutionException.class, () -> binding.get(2, TimeUnit.SECONDS));
            assertInstanceOf(IOException.class, failure.getCause());
            assertFalse(transport.connected);
            assertTrue(session.getChannelCount() <= 1);
        } finally {
            transport.disconnect();
            worker.shutdownNow();
            assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS));
            client.close();
        }
    }

    @Test
    void closedSessionRejectsLatePublication() throws Exception {
        Connection primary = mock(Connection.class);
        Session session = spy(new Session(primary, SmbConfig.createDefaultConfig(), null, null, null, null, null));
        doNothing().when(session).logoff();
        session.close();
        Connection late = mock(Connection.class);
        assertThrows(IllegalStateException.class, () -> session.addChannel(late, new SecretKeySpec(new byte[16], "AesCmac")));
        assertEquals(0, session.getChannelCount());
    }

    @Test
    void cancelledCandidateCannotPublishEvenIfTransportReportsConnected() {
        Connection primary = mock(Connection.class);
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null, null, null, null, null);
        Connection cancelled = mock(Connection.class);
        when(cancelled.isClosed()).thenReturn(true);
        when(cancelled.isConnected()).thenReturn(true);
        assertThrows(IllegalStateException.class,
                () -> session.addChannel(cancelled, new SecretKeySpec(new byte[16], "AesCmac")));
        assertEquals(1, session.getChannelCount());
        verify(cancelled, never()).isConnected();
    }

    @Test
    void teardownBeforeConnectCannotOpenALateTransport() throws Exception {
        WaitingTransport transport = new WaitingTransport(false, false);
        SmbConfig config = SmbConfig.builder().withTransportLayerFactory((handlers, settings) -> transport).build();
        Connection connection = new Connection(config, null, new com.hierynomus.smbj.event.SMBEventBus(), null);
        connection.close(true);
        IOException failure = assertThrows(IOException.class, () -> connection.connect("localhost", 445));
        assertEquals("Connection closed", failure.getMessage());
        assertFalse(transport.connected);
    }

    // Java counterpart of go-smb2's invalid-session and typed-nil argument cases.
    @Test
    void invalidAndClosedSessionsCannotLeakNewTransports() throws Exception {
        java.util.concurrent.atomic.AtomicInteger created = new java.util.concurrent.atomic.AtomicInteger();
        WaitingTransport transport = new WaitingTransport(false, false);
        SmbConfig config = SmbConfig.builder().withTransportLayerFactory((handlers, settings) -> {
            created.incrementAndGet();
            return transport;
        }).build();
        try (SMBClient client = new SMBClient(config)) {
            assertThrows(NullPointerException.class, () -> client.openChannel(null, "localhost", 445));
            assertEquals(0, created.get());
            Connection primary = mock(Connection.class);
            Session session = spy(new Session(primary, config, null, null, null, null, null));
            doNothing().when(session).logoff();
            session.close();
            assertThrows(IOException.class, () -> client.openChannel(session, "localhost", 445));
            assertEquals(1, created.get());
            assertEquals(0, transport.disconnected.getCount(), "Rejected transport is owned and closed");
            assertFalse(transport.connected);
        }
    }

    private static class WaitingTransport implements TransportLayer<SMBPacket<?, ?>> {
        final CountDownLatch negotiating = new CountDownLatch(1);
        final CountDownLatch disconnected = new CountDownLatch(1);
        volatile boolean connected;
        private final boolean holdWrite;
        private final boolean holdConnect;

        WaitingTransport(boolean holdWrite, boolean holdConnect) {
            this.holdWrite = holdWrite;
            this.holdConnect = holdConnect;
        }

        @Override
        public void connect(InetSocketAddress address) throws IOException {
            connected = true;
            if (holdConnect) {
                negotiating.countDown();
                try {
                    if (!disconnected.await(5, TimeUnit.SECONDS)) throw new IOException("Test connect timed out");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException(interrupted);
                }
                throw new IOException("Test connect interrupted");
            }
        }

        @Override
        public void write(SMBPacket<?, ?> packet) throws TransportException {
            negotiating.countDown();
            if (!holdWrite) return;
            try {
                if (!disconnected.await(5, TimeUnit.SECONDS)) throw new TransportException("Test transport timed out");
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new TransportException(interrupted);
            }
            throw new TransportException("Test transport disconnected");
        }

        @Override
        public void disconnect() {
            connected = false;
            disconnected.countDown();
        }

        @Override
        public boolean isConnected() {
            return connected;
        }
    }
}
