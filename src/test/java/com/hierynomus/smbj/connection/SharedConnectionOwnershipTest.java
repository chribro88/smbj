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
import com.hierynomus.protocol.commons.Factory;
import com.hierynomus.protocol.transport.*;
import com.hierynomus.smb.*;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.*;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.spnego.RawToken;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Actual Connection.authenticate/bind/Session.close with a controlled signing peer. */
@Timeout(15)
class SharedConnectionOwnershipTest {
    private static final class TestAuthenticator implements Authenticator {
        public void init(SmbConfig config) { }
        public boolean supports(AuthenticationContext context) { return true; }
        public AuthenticateResponse authenticate(AuthenticationContext context, byte[] token, ConnectionContext connection) {
            AuthenticateResponse response = new AuthenticateResponse(new RawToken(new byte[]{1}));
            response.setSessionKey(gssKey(context.getUsername().equals("A") ? 47 : 48));
            return response;
        }
    }

    private static final class PeerTransport implements TransportLayer<SMBPacket<?, ?>> {
        final PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> handlers;
        final long ownSession;
        volatile boolean connected = true;
        volatile boolean holdBinding;
        volatile SMBPacket<?, ?> pendingBinding;
        final CountDownLatch bindingReceived = new CountDownLatch(1);
        final AtomicInteger echoes = new AtomicInteger();
        final AtomicInteger logoffs = new AtomicInteger();
        PeerTransport(PacketHandlers<SMBPacketData<?>, SMBPacket<?, ?>> handlers, long ownSession) {
            this.handlers = handlers; this.ownSession = ownSession;
        }
        public void write(SMBPacket<?, ?> packet) throws TransportException {
            if (!connected) throw new TransportException("Controlled peer transport is closed");
            try {
                SMBBuffer wire = new SMBBuffer();
                packet.write(wire);
                SMB2PacketHeader h = (SMB2PacketHeader) packet.getHeader();
                int command = (int) h.getMessage().getValue();
                long sid = h.getSessionId() == 0 ? ownSession : h.getSessionId();
                if (holdBinding && command == 1 && (wire.getCompactData()[66] & 1) != 0) {
                    pendingBinding = packet;
                    bindingReceived.countDown();
                    return;
                }
                if (command == 13) echoes.incrementAndGet();
                if (command == 2) logoffs.incrementAndGet();
                byte[] response = new byte[command == 1 ? 73 : 68];
                ByteBuffer b = ByteBuffer.wrap(response).order(ByteOrder.LITTLE_ENDIAN);
                b.putInt(0x424d53fe).putShort((short) 64).putShort((short) 1).putInt(0)
                        .putShort((short) command).putShort((short) 64).putInt(9).putInt(0)
                        .putLong(h.getMessageId()).putLong(0).putLong(sid).put(new byte[16]);
                if (command == 1) b.putShort((short) 9).putShort((short) 0).putShort((short) 72).putShort((short) 1).put((byte) 1);
                else b.putShort((short) 4).putShort((short) 0);
                CMac cmac = new CMac(AESEngine.newInstance());
                cmac.init(new KeyParameter(signingKey(sid)));
                cmac.update(response, 0, response.length);
                byte[] signature = new byte[16];
                cmac.doFinal(signature, 0);
                System.arraycopy(signature, 0, response, 48, 16);
                handlers.getReceiver().handle(new SMB2PacketData(response));
            } catch (Exception e) {
                throw new TransportException(e);
            }
        }
        public void connect(InetSocketAddress address) { connected = true; }
        public void disconnect() { connected = false; }
        public boolean isConnected() { return connected; }
        void releaseBinding() throws TransportException {
            holdBinding = false;
            write(pendingBinding);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void closingOneSessionPreservesAnotherOnCallerOwnedConnection(boolean pendingBinding) throws Exception {
        List<PeerTransport> transports = new ArrayList<>();
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_0)
                .withSigningRequired(true).withTimeout(1, TimeUnit.SECONDS)
                .withAuthenticators(new Factory.Named<Authenticator>() {
                    public String getName() { return "review-test-authenticator"; }
                    public Authenticator create() { return new TestAuthenticator(); }
                }).withTransportLayerFactory((handlers, settings) -> {
                    PeerTransport transport = new PeerTransport(handlers, transports.size() == 0 ? 47 : 48);
                    transports.add(transport);
                    return transport;
                }).build();
        SMBEventBus bus = new SMBEventBus();
        Connection primary = new Connection(config, null, bus, new ServerList());
        Connection callerOwned = new Connection(config, null, bus, new ServerList());
        Connection owned = null;
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            for (Connection connection : Arrays.asList(primary, callerOwned)) {
                ConnectionContext context = new ConnectionContext(config.getClientGuid(), "review.invalid", 445, config);
                context.getServer().init(new UUID(1, 2), SMB2Dialect.SMB_3_0, 3,
                        EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL,
                                SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU));
                set(context, "negotiatedProtocol", new NegotiatedProtocol(SMB2Dialect.SMB_3_0, 65536, 65536, 65536, true));
                set(context, "preauthIntegrityHashValue", new byte[0]);
                set(connection, "connectionContext", context);
            }
            Session a = primary.authenticate(new AuthenticationContext("A", new char[0], "review"));
            Session b = callerOwned.authenticate(new AuthenticationContext("B", new char[0], "review"));
            Connection managed = new Connection(config, null, bus, new ServerList(), a);
            owned = managed;
            ConnectionContext managedContext = new ConnectionContext(config.getClientGuid(), "review.invalid", 445, config);
            managedContext.getServer().init(new UUID(1, 2), SMB2Dialect.SMB_3_0, 3,
                    EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL,
                            SMB2GlobalCapability.SMB2_GLOBAL_CAP_LARGE_MTU));
            set(managedContext, "negotiatedProtocol", new NegotiatedProtocol(SMB2Dialect.SMB_3_0, 65536, 65536, 65536, true));
            set(managedContext, "preauthIntegrityHashValue", new byte[0]);
            set(managed, "connectionContext", managedContext);
            assertSame(a, managed.bind(a));
            assertThrows(IllegalStateException.class,
                    () -> managed.authenticate(new AuthenticationContext("B", new char[0], "review")));
            assertThrows(java.io.IOException.class, () -> managed.bind(b));
            echo(b);
            transports.get(1).holdBinding = pendingBinding;
            Future<Session> binding;
            if (pendingBinding) {
                binding = worker.submit(() -> callerOwned.bind(a));
                assertTrue(transports.get(1).bindingReceived.await(2, TimeUnit.SECONDS));
            } else {
                assertSame(a, callerOwned.bind(a));
                binding = null;
            }
            assertSame(a, callerOwned.getSessionTable().find(a.getSessionId()));
            assertSame(b, callerOwned.getSessionTable().find(b.getSessionId()));
            echo(b);
            a.close();
            assertTrue(managed.isClosed());
            assertFalse(callerOwned.isClosed());
            assertTrue(callerOwned.isConnected());
            if (pendingBinding) {
                transports.get(1).releaseBinding();
                ExecutionException failure = assertThrows(ExecutionException.class, () -> binding.get(2, TimeUnit.SECONDS));
                assertInstanceOf(IllegalStateException.class, failure.getCause());
            }
            echo(b);
            assertNull(callerOwned.getSessionTable().find(a.getSessionId()));
            assertSame(b, callerOwned.getSessionTable().find(b.getSessionId()));
            assertEquals(1, transports.stream().mapToInt(transport -> transport.logoffs.get()).sum());
        } finally {
            try {
                if (owned != null) owned.close(true);
                primary.close(true);
            } finally {
                callerOwned.close(true);
                worker.shutdownNow();
                assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS));
            }
        }
    }

    private static void echo(Session session) throws Exception {
        SMB2Echo echo = new SMB2Echo(SMB2Dialect.SMB_3_0);
        echo.getHeader().setSessionId(session.getSessionId());
        SMB2Packet response = session.<SMB2Packet>send(echo).get(2, TimeUnit.SECONDS);
        check(response.getHeader().getStatusCode() == 0, "signed ECHO succeeded");
    }
    private static byte[] gssKey(long sid) {
        byte[] key = new byte[16]; Arrays.fill(key, (byte) sid); return key;
    }
    private static byte[] signingKey(long sid) throws Exception {
        ByteArrayOutputStream input = new ByteArrayOutputStream();
        input.write(new byte[]{0, 0, 0, 1});
        input.write("SMB2AESCMAC\0".getBytes(StandardCharsets.US_ASCII)); input.write(0);
        input.write("SmbSign\0".getBytes(StandardCharsets.US_ASCII));
        input.write(new byte[]{0, 0, 0, (byte) 128});
        Mac kdf = Mac.getInstance("HmacSHA256");
        kdf.init(new SecretKeySpec(gssKey(sid), "HmacSHA256"));
        return Arrays.copyOf(kdf.doFinal(input.toByteArray()), 16);
    }
    private static void set(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name); field.setAccessible(true); field.set(target, value);
    }
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
