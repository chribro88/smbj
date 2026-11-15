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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuxiliaryCleanupTest {
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
