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

import com.hierynomus.mssmb2.SMB3SigningAlgorithm;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedConstruction;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuxiliaryCleanupTest {
    @ParameterizedTest
    @CsvSource({"io,true", "io,false", "error,true"})
    void ownedCandidateClosesAndPreservesItsPrimaryFailure(String kind, boolean sameCleanup) throws Exception {
        Throwable primary = kind.equals("io") ? new IOException("Binding failed") : new AssertionError("Binding failed");
        Throwable cleanup = sameCleanup ? primary : new IOException("Close failed");
        Session target = mock(Session.class);
        Connection parent = mock(Connection.class);
        when(target.getConnection()).thenReturn(parent);
        when(parent.getRemoteHostname()).thenReturn("localhost");
        when(target.beginBinding(any(Connection.class))).thenReturn(true);
        AtomicBoolean connected = new AtomicBoolean();
        SMBClient client = new SMBClient();
        Field state = SMBClient.class.getDeclaredField("channelConnections"); state.setAccessible(true);
        Collection<?> tracked = (Collection<?>) state.get(client);
        try (MockedConstruction<Connection> channels = mockConstruction(Connection.class, (channel, construction) -> {
            doAnswer(invocation -> { connected.set(true); return null; }).when(channel).connect(anyString(), any(InetSocketAddress.class));
            when(channel.isConnected()).thenAnswer(invocation -> connected.get());
            doAnswer(invocation -> { throw primary; }).when(channel).bind(same(target), eq(true));
            doAnswer(invocation -> { connected.set(false); throw cleanup; }).when(channel).close(true);
        })) {
            try {
                assertSame(primary, assertThrows(primary.getClass(), () -> client.openChannel(target, "127.0.0.1", 445)));
                Connection channel = channels.constructed().get(0);
                verify(channel).close(true);
                verify(target).endBinding(channel);
                assertFalse(connected.get()); assertTrue(tracked.isEmpty());
                assertEquals(sameCleanup ? 0 : 1, primary.getSuppressed().length);
                if (!sameCleanup) assertSame(cleanup, primary.getSuppressed()[0]);
            } finally { connected.set(false); tracked.clear(); }
        } finally { client.close(); }
    }

    @ParameterizedTest
    @CsvSource({"io,true", "io,false", "runtime,true", "error,true"})
    void failedBindingPreservesItsPrimaryFailureAndBorrowedTransport(String kind, boolean sameCleanup) throws Exception {
        Throwable primary = kind.equals("io") ? new IOException("Binding failed")
                : kind.equals("runtime") ? new IllegalStateException("Binding failed") : new AssertionError("Binding failed");
        Throwable cleanup = sameCleanup ? primary : new IOException("Cleanup failed");
        Session target = mock(Session.class), auxiliary = mock(Session.class);
        AuthenticationContext authentication = mock(AuthenticationContext.class);
        when(target.getSessionId()).thenReturn(47L);
        when(target.getAuthenticationContext()).thenReturn(authentication);
        when(target.beginBinding(any(), eq(false))).thenReturn(true);
        doAnswer(invocation -> { throw cleanup; }).when(auxiliary).close();
        @SuppressWarnings("unchecked") TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
        SmbConfig config = SmbConfig.builder().withTransportLayerFactory((handlers, settings) -> transport).build();
        Connection channel = new Connection(config, null, new SMBEventBus(), new ServerList());
        ConnectionContext context = mock(ConnectionContext.class);
        when(context.getSigningAlgorithm()).thenReturn(SMB3SigningAlgorithm.AES_GMAC);
        when(context.getServer()).thenReturn(new Server("localhost", 445));
        Field state = Connection.class.getDeclaredField("connectionContext"); state.setAccessible(true); state.set(channel, context);
        try (MockedConstruction<SMBSessionBuilder> builders = mockConstruction(SMBSessionBuilder.class, (builder, construction) -> {
            when(builder.establish(same(authentication))).thenReturn(auxiliary);
            doAnswer(invocation -> { throw primary; }).when(builder).bind(same(target), any(), eq(false), same(auxiliary));
        })) {
            assertSame(primary, assertThrows(primary.getClass(), () -> channel.bind(target)));
            assertEquals(sameCleanup ? 0 : 1, primary.getSuppressed().length);
            if (!sameCleanup) assertSame(cleanup, primary.getSuppressed()[0]);
            verify(auxiliary).close();
            verify(target).endBinding(channel);
            verify(transport, never()).disconnect();
        } finally { channel.close(true); }
    }
}
