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

import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.lang.reflect.Field;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class NotificationAuthenticationTest {
    @ParameterizedTest
    @ValueSource(longs = {-1, 123})
    void validSignedNotificationCannotCompleteMatchingMidOrGrantCredits(long mid) throws Exception {
        try (Fixture f = new Fixture()) {
            Request outstanding = new Request(new SMB2Echo(SMB2Dialect.SMB_3_1_1), mid, UUID.randomUUID());
            f.connection.outstandingRequests.registerOutstanding(outstanding);
            f.connection.handle(new SMB2PacketData(notification(mid, true, 47)));
            verify(f.leases).dispatchBreak(any(), any());
            assertFalse(outstanding.getPromise().isFulfilled());
            assertEquals(1, f.connection.sequenceWindow.available());
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, 123})
    void forgedSignedNotificationNeverReachesLeaseDispatch(long mid) throws Exception {
        try (Fixture f = new Fixture()) {
            byte[] packet = notification(mid, true, 47);
            packet[80] ^= 1;
            f.connection.handle(new SMB2PacketData(packet));
            verify(f.leases, never()).dispatchBreak(any(), any());
            assertEquals(1, f.connection.sequenceWindow.available());
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, 123})
    void protocolPermitsUnsignedLeaseBreakWithoutSession(long mid) throws Exception {
        try (Fixture f = new Fixture()) {
            f.connection.handle(new SMB2PacketData(notification(mid, false, 0)));
            verify(f.leases).dispatchBreak(any(), any());
            assertEquals(1, f.connection.sequenceWindow.available());
        }
    }

    @ParameterizedTest
    @ValueSource(longs = {0, 999})
    void signedNotificationWithUnknownSessionIsRejected(long session) throws Exception {
        try (Fixture f = new Fixture()) {
            f.connection.handle(new SMB2PacketData(notification(123, true, session)));
            verify(f.leases, never()).dispatchBreak(any(), any());
        }
    }

    private byte[] notification(long mid, boolean signed, long session) throws Exception {
        byte[] wire = new byte[108];
        wire[0] = (byte) 0xfe; wire[1] = 'S'; wire[2] = 'M'; wire[3] = 'B';
        wire[4] = 64; wire[12] = 18; wire[14] = 100; wire[16] = (byte) (signed ? 9 : 1);
        for (int i = 0; i < 8; i++) {
            wire[24 + i] = (byte) (mid >>> (8 * i));
            wire[40 + i] = (byte) (session >>> (8 * i));
        }
        wire[64] = 44;
        if (signed) {
            byte[] nonce = new byte[12];
            System.arraycopy(wire, 24, nonce, 0, 8); nonce[8] = 1;
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(wire);
            System.arraycopy(cipher.doFinal(), 0, wire, 48, 16);
        }
        return wire;
    }

    private static class Fixture implements AutoCloseable {
        final LeaseManager leases = mock(LeaseManager.class);
        final Connection connection;

        @SuppressWarnings("unchecked")
        Fixture() throws Exception {
            TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
            SmbConfig config = SmbConfig.builder().withTransportLayerFactory((handlers, settings) -> transport).build();
            connection = new Connection(config, null, new SMBEventBus(), new ServerList());
            Field manager = Connection.class.getDeclaredField("leaseManager");
            manager.setAccessible(true);
            // Rebuild the actual Connection handler chain with an observable dispatch endpoint.
            manager.set(connection, leases);
            java.lang.reflect.Method init = Connection.class.getDeclaredMethod("init");
            init.setAccessible(true); init.invoke(connection);
            ConnectionContext context = mock(ConnectionContext.class);
            when(context.getServer()).thenReturn(new Server("localhost", 445));
            Field state = Connection.class.getDeclaredField("connectionContext");
            state.setAccessible(true); state.set(connection, context);
            Session session = mock(Session.class);
            when(session.getSessionId()).thenReturn(47L);
            when(session.getConnection()).thenReturn(connection);
            LeaseEntry entry = new LeaseEntry(LeaseKey.random(), null, 3, "held");
            entry.setOwner(session, 7, SMB2Dialect.SMB_3_1_1);
            when(leases.lookup(any())).thenReturn(entry);
            when(session.getSigningKey(any(), eq(false), same(connection)))
                    .thenReturn(new SecretKeySpec(new byte[16], "AES-GMAC"));
            when(session.isSigningRequired()).thenReturn(true);
            connection.getSessionTable().registerSession(47L, session);
        }

        @Override public void close() throws Exception { connection.close(true); }
    }
}
