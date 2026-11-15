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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static com.hierynomus.smbj.testing.Utils.*;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.ConnectionClosed;
import com.hierynomus.smbj.event.SMBEvent;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.SessionLoggedOff;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Share;
import com.hierynomus.smbj.testing.PacketProcessor.NoOpPacketProcessor;;

public class ConnectionTest {

    @Test
    public void shouldPreserveAnotherPeersSessionWhenItsNumericIdMatchesTheLoggedOffSession() throws Exception {
        SmbConfig config = distinctPeerConfig();
        SMBEventBus bus = new SMBEventBus();
        AuthenticationContext identity = new AuthenticationContext("user", new char[0], "domain");
        try (SMBClient client = new SMBClient(config, bus);
             Connection one = client.connect("one"); Connection two = client.connect("two");
             Session closing = one.authenticate(identity); Session other = two.authenticate(identity)) {
            assertEquals(closing.getSessionId(), other.getSessionId());
            assertNotSame(closing, other);
            closing.close();
            assertNull(one.getSessionTable().find(closing.getSessionId()));
            assertSame(other, two.getSessionTable().find(other.getSessionId()));
            try (Share share = other.connectShare("share")) { assertNotNull(share); }
        }
    }

    @Test
    public void shouldPreserveAnotherPeersCachedShareWhenSessionAndTreeIdsMatch() throws Exception {
        SMBEventBus bus = new SMBEventBus();
        AuthenticationContext identity = new AuthenticationContext("user", new char[0], "domain");
        try (SMBClient client = new SMBClient(distinctPeerConfig(), bus);
             Connection one = client.connect("one"); Connection two = client.connect("two");
             Session closing = one.authenticate(identity); Session other = two.authenticate(identity);
             Share closingShare = closing.connectShare("share"); Share otherShare = other.connectShare("share")) {
            assertEquals(closing.getSessionId(), other.getSessionId());
            assertEquals(closingShare.getTreeConnect().getTreeId(), otherShare.getTreeConnect().getTreeId());
            closing.close();
            assertSame(other, two.getSessionTable().find(other.getSessionId()));
            assertSame(otherShare, other.connectShare("share"));
        }
    }

    private static SmbConfig distinctPeerConfig() {
        AtomicInteger peers = new AtomicInteger();
        return configBuilder(request -> {
            if (request.getPacket() instanceof SMB2NegotiateRequest) {
                SMB2NegotiateResponse response = new SMB2NegotiateResponse();
                response.getHeader().setStatusCode(NtStatus.STATUS_SUCCESS.getValue());
                response.setDialect(SMB2Dialect.SMB_2_1);
                response.setSystemTime(FileTime.now());
                response.setServerGuid(new UUID(0, peers.incrementAndGet()));
                return response;
            }
            return null;
        }).withTimeout(1, java.util.concurrent.TimeUnit.SECONDS).build();
    }

    @Test
    public void shouldPreserveReplacementWhenAnOldSessionsDelayedLogoffEventArrives() throws Exception {
        AtomicReference<SessionLoggedOff> delayed = new AtomicReference<>();
        SMBEventBus bus = new SMBEventBus() {
            @Override public void publish(SMBEvent event) {
                if (event instanceof SessionLoggedOff && delayed.compareAndSet(null, (SessionLoggedOff) event)) return;
                super.publish(event);
            }
        };
        try (SMBClient client = new SMBClient(config(new NoOpPacketProcessor()), bus);
             Connection connection = client.connect("one")) {
            Session old = connection.authenticate(new AuthenticationContext("user", new char[0], "domain"));
            old.close(); assertNotNull(delayed.get());
            Session replacement = mock(Session.class);
            when(replacement.getSessionId()).thenReturn(old.getSessionId());
            connection.getSessionTable().registerSession(old.getSessionId(), replacement);
            bus.publish(delayed.get());
            assertSame(replacement, connection.getSessionTable().find(old.getSessionId()));
        }
    }

    @Test
    public void shouldRemoveTheSameLogicalSessionFromAllChannelTables() throws Exception {
        SMBEventBus bus = new SMBEventBus();
        try (SMBClient client = new SMBClient(config(new NoOpPacketProcessor()), bus);
             Connection primary = client.connect("one"); Connection channel = client.connect("one-channel");
             Session session = primary.authenticate(new AuthenticationContext("user", new char[0], "domain"))) {
            // Model the same logical session registered on two physical channel tables.
            channel.getSessionTable().registerSession(session.getSessionId(), session);
            session.close();
            assertNull(primary.getSessionTable().find(session.getSessionId()));
            assertNull(channel.getSessionTable().find(session.getSessionId()));
            assertFalse(channel.isClosed());
        }
    }

    @Test
    public void shouldPreserveReplacementInsertedBetweenLogoffLookupAndRemoval() throws Exception {
        AtomicReference<SessionLoggedOff> delayed = new AtomicReference<>();
        SMBEventBus bus = new SMBEventBus() {
            @Override public void publish(SMBEvent event) {
                if (event instanceof SessionLoggedOff && delayed.compareAndSet(null, (SessionLoggedOff) event)) return;
                super.publish(event);
            }
        };
        try (SMBClient client = new SMBClient(config(new NoOpPacketProcessor()), bus);
             Connection connection = client.connect("one")) {
            Session old = connection.authenticate(new AuthenticationContext("user", new char[0], "domain"));
            old.close();
            Session replacement = mock(Session.class);
            when(replacement.getSessionId()).thenReturn(old.getSessionId());
            AtomicBoolean replaced = new AtomicBoolean();
            SessionTable table = new SessionTable() {
                @Override public Session find(Long id) {
                    Session found = super.find(id);
                    if (replaced.compareAndSet(false, true)) registerSession(id, replacement);
                    return found;
                }
            };
            table.registerSession(old.getSessionId(), old);
            java.lang.reflect.Field field = Connection.class.getDeclaredField("sessionTable");
            field.setAccessible(true); field.set(connection, table);
            bus.publish(delayed.get());
            assertSame(replacement, table.find(old.getSessionId()));
        }
    }

    @Test
    public void shouldRetainReconnectedConnectionWhenOldCloseEventArrives() throws Exception {
        AtomicReference<ConnectionClosed> delayed = new AtomicReference<>();
        SMBEventBus bus = new SMBEventBus() {
            @Override
            public void publish(SMBEvent event) {
                if (event instanceof ConnectionClosed && delayed.compareAndSet(null, (ConnectionClosed) event)) {
                    return;
                }
                super.publish(event);
            }
        };
        String hostname = "127.0.0.1";
        try (SMBClient client = new SMBClient(config(new NoOpPacketProcessor()), bus)) {
            Connection first = client.connect(hostname);
            first.close(true);
            assertNotNull(delayed.get());
            assertSame(first, delayed.get().getConnection());

            Connection second = client.connect(hostname);
            assertNotSame(first, second);
            bus.publish(delayed.get());

            assertSame(second.getConnectionContext().getServer(), client.getServerList().lookup(hostname));
            assertSame(second, client.connect(hostname));
            client.close();
            assertFalse(second.isConnected());
            assertNull(client.getServerList().lookup(hostname));
        }
    }

    @Test
    public void shouldUnregisterConnectionForLegacyCloseEvent() throws Exception {
        SMBEventBus bus = new SMBEventBus();
        String hostname = "127.0.0.1";
        try (SMBClient client = new SMBClient(config(new NoOpPacketProcessor()), bus);
             Connection first = client.connect(hostname)) {
            first.transport.disconnect();
            ConnectionClosed event = new ConnectionClosed(hostname, SMBClient.DEFAULT_PORT);
            assertNull(event.getConnection());
            bus.publish(event);

            assertNull(client.getServerList().lookup(hostname));
            assertNotSame(first, client.connect(hostname));
        }
    }

    @Test
    public void shouldUnregisterServerWhenConnectionClosed() throws Exception {
        SmbConfig config = config(new NoOpPacketProcessor());
        SMBClient client = new SMBClient(config);

        Connection conn = client.connect("foo");
        assertNotNull(client.getServerList().lookup("foo"));

        conn.close();
        assertNull(client.getServerList().lookup("foo"));
    }

    @Test
    public void shouldNotUnregisterServerWhenNotAllConnectionsClosed() throws Exception {
        SmbConfig config = config(new NoOpPacketProcessor());
        SMBClient client = new SMBClient(config);

        Connection conn = client.connect("foo");
        Connection conn2 = client.connect("foo");
        conn.close();

        assertNotNull(client.getServerList().lookup("foo"));

        conn2.close();
        assertNull(client.getServerList().lookup("foo"));
    }

    @Test
    public void shouldConnectToServerWithChangedIdentificationWhenAllConnectionsClosed() throws Exception {
        UUID one = UUID.fromString("ffeeddcc-bbaa-9988-7766-554433221100");
        UUID two = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff");

        final AtomicBoolean sent = new AtomicBoolean(false);
        SmbConfig config = config((SMB2Packet req) -> {
            req = req.getPacket();
            if (!sent.get() && req instanceof SMB2NegotiateRequest) {
                sent.set(true);
                SMB2NegotiateResponse resp = new SMB2NegotiateResponse();
                resp.getHeader().setMessageType(SMB2MessageCommandCode.SMB2_NEGOTIATE);
                resp.getHeader().setStatusCode(NtStatus.STATUS_SUCCESS.getValue());
                resp.setDialect(SMB2Dialect.SMB_2_1);
                resp.setSystemTime(FileTime.now());
                resp.setServerGuid(one);
                return resp;
            }
            return null;
        });

        SMBClient client = new SMBClient(config);

        Connection conn = client.connect("foo");
        Connection conn2 = client.connect("foo");
        assertEquals(one, client.getServerList().lookup("foo").getServerGUID());
        assertEquals(one, conn.getConnectionContext().getServer().getServerGUID());
        assertEquals(one, conn2.getConnectionContext().getServer().getServerGUID());

        conn.close();

        assertNotNull(client.getServerList().lookup("foo"));

        conn2.close();
        assertNull(client.getServerList().lookup("foo"));

        conn = client.connect("foo");
        assertEquals(two, client.getServerList().lookup("foo").getServerGUID());
        assertEquals(two, conn.getConnectionContext().getServer().getServerGUID());
    }
}
