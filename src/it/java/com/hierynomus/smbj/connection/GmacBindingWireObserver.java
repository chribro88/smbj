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

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;

import javax.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import java.io.*;
import java.lang.reflect.Field;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Independent wire/tag audit reused from the concurrent binding fixture. */
final class GmacBindingWireObserver extends SocketFactory {
    private final List<ObservedSocket> sockets = new ArrayList<>();
    private final Map<Connection, ObservedSocket> owners = new IdentityHashMap<>();
    private final Map<Thread, ObservedSocket> openedByThread = new IdentityHashMap<>();
    private final List<Event> events = new ArrayList<>();
    private final Map<Integer, Map<Long, byte[]>> auxiliaryKeys = new HashMap<>();
    private final Map<Integer, byte[]> channelKeys = new HashMap<>();
    private final Map<Long, byte[]> originalSessionKeys = new HashMap<>();
    private final Map<Long, byte[]> capturedKeys = new ConcurrentHashMap<>();
    private final Map<Long, byte[][]> encryptionKeys = new HashMap<>();
    private final Set<String> encryptionNonces = new HashSet<>();
    private int verifiedTransforms, encryptedLogoffs;
    private final byte[] fingerprintKey = new byte[32];
    private final String hostname;
    private final int port;
    private long mainSessionId;
    private int originalSocket;
    private byte[] originalKey;
    private int originalKeyBindingRequests, unsignedEchoRequests;
    private boolean originalApplicationTraffic;

    GmacBindingWireObserver() { this("127.0.0.1", Integer.parseInt(System.getenv("SMB_TEST_PORTS"))); }

    GmacBindingWireObserver(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
        new SecureRandom().nextBytes(fingerprintKey);
    }

    SmbConfig configuration(SmbConfig base) throws NoSuchFieldException {
        Field keyField = PacketSignatory.SignedPacketWrapper.class.getDeclaredField("secretKey");
        keyField.setAccessible(true);
        return SmbConfig.builder(base).withSocketFactory(this).withTransportLayerFactory((handlers, settings) -> {
            TransportLayer<SMBPacket<?, ?>> delegate = new DirectTcpTransport<>(
                    settings.getSocketFactory(), settings.getSoTimeout(), handlers);
            return new TransportLayer<SMBPacket<?, ?>>() {
                public void connect(InetSocketAddress address) throws IOException { delegate.connect(address); }
                public void disconnect() throws IOException { delegate.disconnect(); }
                public boolean isConnected() { return delegate.isConnected(); }
                public void write(SMBPacket<?, ?> packet) throws TransportException {
                    SMB2Packet smb = (SMB2Packet) packet;
                    if (packet instanceof PacketEncryptor.EncryptedPacketWrapper) {
                        Session owner = ((Connection) handlers.getReceiver()).getSessionTable().find(smb.getHeader().getSessionId());
                        encryption(owner);
                        capturedKeys.putIfAbsent(owner.getSessionId(), owner.getSessionContext().getSigningKey().getEncoded().clone());
                    }
                    if (packet instanceof PacketSignatory.SignedPacketWrapper) {
                        try {
                            SecretKey key = (SecretKey) keyField.get(packet);
                            capturedKeys.putIfAbsent(smb.getHeader().getSessionId(), key.getEncoded().clone());
                        } catch (IllegalAccessException failure) { throw new AssertionError(failure); }
                    }
                    delegate.write(packet);
                }
            };
        }).build();
    }

    synchronized void register(Connection connection) {
        ObservedSocket socket = openedByThread.get(Thread.currentThread());
        assertFalse(owners.containsValue(socket));
        owners.put(connection, socket);
    }

    synchronized void original(Session main, Connection connection) {
        mainSessionId = main.getSessionId();
        originalSocket = authenticationSocket(mainSessionId);
        originalKey = main.getSessionContext().getSigningKey().getEncoded().clone();
    }

    private int authenticationSocket(long sessionId) {
        return events.stream().filter(event -> event.sessionId == sessionId && event.command == 1
                && event.server && event.status == 0).findFirst().orElseThrow(AssertionError::new).connection;
    }

    synchronized void auxiliary(Session session, Connection connection) {
        byte[] original = session.getSessionContext().getSigningKey().getEncoded().clone();
        originalSessionKeys.put(session.getSessionId(), original);
        auxiliaryKeys.computeIfAbsent(authenticationSocket(session.getSessionId()), unused -> new HashMap<>())
                .put(session.getSessionId(), original);
        auxiliaryKeys.computeIfAbsent(owners.get(connection).id, unused -> new HashMap<>())
                .put(session.getSessionId(), session.getSigningKey(new SMB2Echo(SMB2Dialect.SMB_3_1_1).getHeader(), false, connection).getEncoded().clone());
    }

    synchronized void auxiliaryKeys(Map<Long, byte[]> keys) {
        for (ObservedSocket socket : sockets) {
            Map<Long, byte[]> actual = auxiliaryKeys.computeIfAbsent(socket.id, unused -> new HashMap<>());
            keys.forEach(actual::putIfAbsent);
        }
    }

    synchronized void bound(Session session, Connection connection) {
        byte[] key = session.getSigningKey(new SMB2Echo(SMB2Dialect.SMB_3_1_1).getHeader(), false, connection)
                .getEncoded().clone();
        assertFalse(Arrays.equals(originalKey, key), "Operational channel key must differ from original key");
        channelKeys.put(owners.get(connection).id, key);
    }

    synchronized void encryption(Session session) {
        assertNotNull(session);
        byte[][] keys = {session.getSessionContext().getEncryptionKey().getEncoded().clone(),
                session.getSessionContext().getDecryptionKey().getEncoded().clone()};
        byte[][] previous = encryptionKeys.putIfAbsent(session.getSessionId(), keys);
        if (previous != null) {
            assertArrayEquals(previous[0], keys[0]); assertArrayEquals(previous[1], keys[1]);
        }
    }

    synchronized byte[] decryptTransform(byte[] wire, boolean server) throws GeneralSecurityException {
        ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(wire.length - 52, header.getInt(36));
        assertEquals(0, header.getShort(40)); assertEquals(1, header.getShort(42));
        long sessionId = header.getLong(44);
        byte[][] keys = encryptionKeys.get(sessionId); assertNotNull(keys);
        byte[] ciphertextAndTag = Arrays.copyOfRange(wire, 52, wire.length + 16);
        System.arraycopy(wire, 4, ciphertextAndTag, wire.length - 52, 16);
        Cipher oracle = Cipher.getInstance("AES/GCM/NoPadding");
        oracle.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keys[server ? 1 : 0], "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(wire, 20, 32)));
        oracle.updateAAD(wire, 20, 32);
        byte[] plaintext = oracle.doFinal(ciphertextAndTag);
        assertEquals(sessionId, ByteBuffer.wrap(plaintext).order(ByteOrder.LITTLE_ENDIAN).getLong(40));
        return plaintext;
    }

    synchronized void failNextBinding(Connection connection) { owners.get(connection).failBinding = true; }
    synchronized boolean faultTriggered(Connection connection) { return owners.get(connection).injectedClose; }

    synchronized void gateBinding(Connection connection, CountDownLatch entered, CountDownLatch release, boolean partial) {
        ObservedSocket socket = owners.get(connection);
        socket.entered = entered;
        socket.release = release;
        socket.cutAfterBytes = partial ? 76 : -1;
    }

    synchronized int partialClientBytes(Connection connection) { return owners.get(connection).partialClientBytes; }

    synchronized int originalKeyBindingRequests() { return originalKeyBindingRequests; }
    synchronized int unsignedEchoRequests() { return unsignedEchoRequests; }
    synchronized boolean originalApplicationTraffic() { return originalApplicationTraffic; }

    synchronized void verifyAndReport(String run, int replacements) throws GeneralSecurityException {
        verifyAndReport(run, replacements, 501);
    }

    synchronized void verifyAndReport(String run, int replacements, int minimumOperational) throws GeneralSecurityException {
        verifyAndReport(run, replacements, minimumOperational, 32, 4);
    }

    synchronized void verifyAndReport(String run, int replacements, int minimumOperational,
                                      int minimumTransforms, int minimumLogoffs) throws GeneralSecurityException {
        auxiliaryKeys(capturedKeys);
        Map<String, String> authenticatedInputs = new HashMap<>();
        Set<String> actualKeys = new HashSet<>();
        Set<String> bindingRequests = new HashSet<>();
        for (Event event : events) {
            if (!event.server && event.command == 1 && event.wire.length > 66 && (event.wire[66] & 1) != 0) {
                bindingRequests.add(event.connection + ":" + event.mid);
            }
        }
        int verified = 0;
        int operational = 0;
        int encryptedOperational = 0;
        int preparedOnly = 0;
        MessageDigest transcript = MessageDigest.getInstance("SHA-256");
        for (Event event : events) {
            if (event.encrypted) {
                if (event.sessionId == mainSessionId && event.command != 1) encryptedOperational++;
                continue;
            }
            Map<Long, byte[]> auxiliary = auxiliaryKeys.get(event.connection);
            boolean isAuxiliary = auxiliary != null && auxiliary.containsKey(event.sessionId);
            if (!event.signed) {
                if (event.command != 0 && event.command != 1) {
                    System.out.printf("AUXWIRE_UNSIGNED run=%s event=%d connection=%d sender=%s command=%d status=%08x mid=%d%n",
                            run, event.id, event.connection, event.server ? "server" : "client", event.command, event.status, event.mid);
                }
                continue;
            }
            byte[] key;
            String role;
            if (event.sessionId == mainSessionId) {
                ObservedSocket socket = sockets.get(event.connection);
                if (event.connection == originalSocket || (event.command == 1 && bindingRequests.contains(event.connection + ":" + event.mid)
                        && (!event.server || event.status != 0))) {
                    key = originalKey;
                    role = "original";
                } else {
                    key = channelKeys.get(event.connection);
                    role = "operational";
                    operational++;
                }
            } else {
                assertTrue(isAuxiliary, "Every signed session must have an observed actual key");
                key = auxiliary.get(event.sessionId);
                if (event.command == 1 && bindingRequests.contains(event.connection + ":" + event.mid) && (!event.server || event.status != 0)) {
                    key = originalSessionKeys.getOrDefault(event.sessionId, key);
                }
                role = "auxiliary";
            }
            assertNotNull(key);
            byte[] nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putLong(event.mid).putInt(0).array();
            if (event.server) nonce[8] |= 1;
            if (event.command == 12) nonce[8] |= 2;
            byte[] normalized = event.wire.clone();
            Arrays.fill(normalized, 48, 64, (byte) 0);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(normalized);
            assertTrue(MessageDigest.isEqual(cipher.doFinal(), Arrays.copyOfRange(event.wire, 48, 64)),
                    "Independent tag verification failed for event=" + event.id + " connection=" + event.connection
                            + " sender=" + event.server + " command=" + event.command + " status=" + Long.toHexString(event.status) + " role=" + role);
            String keyId = fingerprint(key);
            String fingerprint = fingerprint(normalized);
            String domain = keyId + ":" + hex(nonce);
            String previous = authenticatedInputs.putIfAbsent(domain, fingerprint);
            assertTrue(previous == null || previous.equals(fingerprint), "Different authenticated bytes reused actual key/nonce");
            if (event.connection == originalSocket && event.sessionId == mainSessionId) {
                originalApplicationTraffic |= event.command != 1;
            }
            actualKeys.add(keyId);
            verified++;
            if (event.preparedOnly) preparedOnly++;
            transcript.update((domain + fingerprint).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            if (event.command == 1 || isAuxiliary) {
                System.out.printf("AUXWIRE run=%s event=%d connection=%d session=%s sender=%s command=%d status=%08x mid=%d keyRole=%s keyId=%s nonce=%s fingerprint=%s verified=true input=%s%n",
                        run, event.id, event.connection, isAuxiliary ? "aux-" + event.connection : "main",
                        event.server ? "server" : "client", event.command, event.status, event.mid, role, keyId, hex(nonce), fingerprint,
                        event.preparedOnly ? "write-attempt" : "complete-frame");
            }
        }
        assertTrue(operational + encryptedOperational >= minimumOperational, "Expected application traffic must be included in the independent verification");
        for (ObservedSocket socket : sockets) {
            assertTrue(socket.isClosed());
            long next = 0;
            for (Map.Entry<Long, Integer> range : socket.requestRanges.entrySet()) {
                assertEquals(next, range.getKey().longValue(), "Native allocation ranges must have no gaps or overlaps");
                next += range.getValue();
            }
            if (socket.injectedClose) {
                System.out.printf("AUXWIRE_FAULT run=%s connection=%d partialClientBytes=%d partialServerBytes=%d%n",
                        run, socket.id, socket.pending[0].size() + socket.partialClientBytes, socket.pending[1].size());
            } else {
                assertEquals(0, socket.pending[0].size());
                assertEquals(0, socket.pending[1].size());
            }
            assertTrue(socket.earlyGrants.isEmpty(), "No response may invent a credit grant without an observed request");
        }
        System.out.printf("AUXWIRE_COMPLETE run=%s replacements=%d observedEvents=%d independentlyVerified=%d preparedOnly=%d operationalSignedMessages=%d actualKeyDomains=%d distinctMessageNonceReuses=0 transcriptFingerprint=%s%n",
                run, replacements, events.size(), verified, preparedOnly, operational, actualKeys.size(), hex(transcript.digest()));
        if (!encryptionKeys.isEmpty()) {
            assertTrue(verifiedTransforms >= minimumTransforms); assertTrue(encryptedOperational >= minimumOperational);
            assertTrue(encryptedLogoffs >= minimumLogoffs, "Expected LOGOFF requests and replies must be encrypted");
            System.out.printf("AUXWIRE_GCM run=%s verifiedTransforms=%d encryptedOperationalMessages=%d encryptedLogoffFrames=%d distinctMessageNonceReuses=0%n",
                    run, verifiedTransforms, encryptedOperational, encryptedLogoffs);
        }
    }

    synchronized void verifyLeaseBreaks(Connection survivingChannel) {
        int survivor = owners.get(survivingChannel).id;
        int notifications = 0, acknowledgments = 0;
        int unsignedPlaintext = 0, zeroSession = 0, sentinelMid = 0;
        Set<String> survivingBreaks = new HashSet<>(), survivingAcks = new HashSet<>();
        for (Event event : events) {
            if (event.leaseNotification()) {
                notifications++;
                if (!event.signed && !event.encrypted) unsignedPlaintext++;
                if (event.sessionId == 0) zeroSession++;
                if (event.mid == -1) sentinelMid++;
                if (event.connection == survivor) survivingBreaks.add(hex(Arrays.copyOfRange(event.wire, 72, 88)));
            } else if (!event.server && event.command == 18) {
                assertTrue(event.encrypted || event.signed, "Every lease acknowledgment must be authenticated");
                acknowledgments++;
                if (event.connection == survivor) survivingAcks.add(hex(Arrays.copyOfRange(event.wire, 72, 88)));
            }
        }
        assertTrue(notifications >= 2); assertTrue(acknowledgments >= 2);
        assertFalse(survivingBreaks.isEmpty(), "Native break must arrive on the surviving transport");
        assertTrue(survivingAcks.containsAll(survivingBreaks), "Each surviving-channel break key must be acknowledged");
        System.out.printf("AUXWIRE_LEASE notifications=%d authenticatedAcknowledgments=%d survivingBreakKeys=%d unsignedPlaintextNotifications=%d zeroSessionNotifications=%d sentinelMidNotifications=%d%n",
                notifications, acknowledgments, survivingBreaks.size(), unsignedPlaintext, zeroSession, sentinelMid);
    }

    private String fingerprint(byte[] bytes) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(fingerprintKey, "HmacSHA256"));
        return hex(mac.doFinal(bytes));
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) text.append(String.format("%02x", value & 255));
        return text.toString();
    }

    @Override public Socket createSocket() { throw new UnsupportedOperationException("Explicit loopback endpoint required"); }
    @Override public Socket createSocket(String host, int port) throws IOException { return open(host, port, null, 0); }
    @Override public Socket createSocket(InetAddress host, int port) throws IOException { return open(host.getHostAddress(), port, null, 0); }
    @Override public Socket createSocket(String host, int port, InetAddress local, int localPort) throws IOException { return open(host, port, local, localPort); }
    @Override public Socket createSocket(InetAddress host, int port, InetAddress local, int localPort) throws IOException { return open(host.getHostAddress(), port, local, localPort); }

    private synchronized Socket open(String host, int port, InetAddress local, int localPort) throws IOException {
        if (!(hostname.equals(host) || "127.0.0.1".equals(host)) || port != this.port) throw new IOException("Only the owned loopback fixture is permitted");
        ObservedSocket socket = new ObservedSocket(sockets.size());
        sockets.add(socket);
        openedByThread.put(Thread.currentThread(), socket);
        try {
            if (local != null) socket.bind(new InetSocketAddress(local, localPort));
            socket.connect(new InetSocketAddress("127.0.0.1", port), 5000);
            return socket;
        } catch (IOException failure) {
            try { socket.close(); } catch (IOException close) { failure.addSuppressed(close); }
            throw failure;
        }
    }

    private final class ObservedSocket extends Socket {
        final int id;
        final ByteArrayOutputStream[] pending = {new ByteArrayOutputStream(), new ByteArrayOutputStream()};
        long grantedEnd = 1;
        long credits = 1;
        final Set<Long> requests = new HashSet<>();
        final java.util.SortedMap<Long, Integer> requestRanges = new java.util.TreeMap<>();
        final Map<Long, Integer> earlyGrants = new HashMap<>();
        boolean failBinding;
        volatile boolean injectedClose;
        CountDownLatch entered, release;
        int cutAfterBytes = -1, partialClientBytes;
        boolean gated;
        ObservedSocket(int id) { this.id = id; }

        @Override public InputStream getInputStream() throws IOException {
            return new FilterInputStream(super.getInputStream()) {
                @Override public int read() throws IOException {
                    int value = in.read();
                    if (value >= 0) observe(1, new byte[]{(byte) value}, 0, 1);
                    return value;
                }
                @Override public int read(byte[] bytes, int offset, int length) throws IOException {
                    int read = in.read(bytes, offset, length);
                    if (read > 0) observe(1, bytes, offset, read);
                    return read;
                }
            };
        }

        @Override public OutputStream getOutputStream() throws IOException {
            return new FilterOutputStream(super.getOutputStream()) {
                @Override public void write(int value) throws IOException {
                    out.write(value);
                    observe(0, new byte[]{(byte) value}, 0, 1);
                    if (injectedClose) ObservedSocket.this.close();
                }
                @Override public void write(byte[] bytes, int offset, int length) throws IOException {
                    boolean binding = gate(bytes, offset, length);
                    if (binding && cutAfterBytes >= 0) {
                        out.write(bytes, offset, cutAfterBytes);
                        // Observe the complete signed write input, while only its prefix reaches the peer.
                        synchronized (GmacBindingWireObserver.this) {
                            observe(0, bytes, offset, length);
                            events.get(events.size() - 1).preparedOnly = true;
                            partialClientBytes = cutAfterBytes;
                            injectedClose = true;
                        }
                        entered.countDown();
                        ObservedSocket.this.close();
                        throw new IOException("Injected partial binding write");
                    }
                    out.write(bytes, offset, length);
                    observe(0, bytes, offset, length);
                    if (binding) {
                        entered.countDown();
                        if (!injectedClose) {
                            assertFalse(Thread.holdsLock(GmacBindingWireObserver.this));
                            try {
                                if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("Research binding gate expired");
                            } catch (InterruptedException interrupted) {
                                Thread.currentThread().interrupt();
                                throw new IOException(interrupted);
                            }
                        }
                    }
                    if (injectedClose) ObservedSocket.this.close();
                }
            };
        }

        private boolean gate(byte[] bytes, int offset, int length) {
            synchronized (GmacBindingWireObserver.this) {
                if (entered == null || gated || length < 71) return false;
                ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
                if (header.getInt(offset + 4) != 0x424d53fe || header.getShort(offset + 16) != 1
                        || header.getLong(offset + 44) != mainSessionId || (bytes[offset + 70] & 1) == 0) return false;
                assertEquals(0, pending[0].size());
                assertEquals(length - 4, ByteBuffer.wrap(bytes, offset, 4).getInt(), "One complete binding write input required");
                assertTrue(length > cutAfterBytes);
                gated = true;
                return true;
            }
        }

        private void observe(int direction, byte[] bytes, int offset, int length) throws IOException {
            synchronized (GmacBindingWireObserver.this) {
                pending[direction].write(bytes, offset, length);
                byte[] buffered = pending[direction].toByteArray();
                int consumed = 0;
                while (buffered.length - consumed >= 4) {
                    int size = ByteBuffer.wrap(buffered, consumed, 4).getInt();
                    if (size < 64 || size > 1024 * 1024) throw new IOException("Invalid or oversized diagnostic frame");
                    if (buffered.length - consumed < size + 4) break;
                    byte[] wire = Arrays.copyOfRange(buffered, consumed + 4, consumed + 4 + size);
                    boolean encrypted = wire[0] == (byte) 0xfd;
                    byte[] plaintext = wire;
                    if (encrypted) {
                        try {
                            plaintext = decryptTransform(wire, direction == 1);
                            long sessionId = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN).getLong(44);
                            byte[] key = encryptionKeys.get(sessionId)[direction];
                            assertTrue(encryptionNonces.add(fingerprint(key) + ":" + hex(Arrays.copyOfRange(wire, 20, 32))),
                                    "Every transform must have a unique actual key/nonce across all sessions/channels");
                            if (verifiedTransforms == 0) {
                                byte[] tampered = wire.clone(); tampered[52] ^= 1;
                                assertThrows(AEADBadTagException.class, () -> decryptTransform(tampered, direction == 1));
                            }
                            assertTrue(++verifiedTransforms < 4096, "Bounded transform observation");
                        } catch (GeneralSecurityException failure) { throw new IOException("Independent GCM verification failed", failure); }
                    }
                    Event event = new Event(events.size() + 1, id, direction == 1, plaintext);
                    event.encrypted = encrypted;
                    if (encrypted && event.command == 2) encryptedLogoffs++;
                    if (!event.server && event.command == 1 && event.sessionId == mainSessionId
                            && (event.wire[66] & 1) != 0) originalKeyBindingRequests++;
                    if (!event.server && event.command == 13 && event.sessionId == 0) unsignedEchoRequests++;
                    if (!event.server && event.signed && event.connection == originalSocket && event.sessionId == mainSessionId
                            && event.command != 1) originalApplicationTraffic = true;
                    assertEquals(0, ByteBuffer.wrap(event.wire).order(ByteOrder.LITTLE_ENDIAN).getInt(20), "Compound traffic is outside this prototype");
                    if (event.server && !event.leaseNotification()) {
                        grantedEnd += event.creditGrant;
                        // A loopback response can be read before the writer records its completed write.
                        if (requests.contains(event.mid)) credits += event.creditGrant;
                        else earlyGrants.merge(event.mid, event.creditGrant, Integer::sum);
                    }
                    else if (!event.server && event.command != 12) {
                        int charge = Math.max(1, event.creditCharge);
                        assertTrue(event.mid >= 0 && event.mid <= grantedEnd - charge,
                                "A request's range must already have been granted by this connection");
                        assertTrue(credits >= charge, "Native per-connection credits must not be exceeded");
                        credits -= charge;
                        assertTrue(requests.add(event.mid));
                        requestRanges.put(event.mid, charge);
                        Integer grant = earlyGrants.remove(event.mid);
                        if (grant != null) credits += grant;
                    }
                    events.add(event);
                    if (direction == 0 && failBinding && event.command == 1 && event.sessionId == mainSessionId
                            && (event.wire[66] & 1) != 0) {
                        failBinding = false;
                        injectedClose = true;
                    }
                    consumed += size + 4;
                }
                pending[direction].reset();
                pending[direction].write(buffered, consumed, buffered.length - consumed);
            }
        }
    }

    private static final class Event {
        final int id, connection, command, creditCharge, creditGrant;
        final boolean server, signed;
        final long sessionId, mid, status;
        final byte[] wire;
        boolean preparedOnly;
        boolean encrypted;

        boolean leaseNotification() {
            return server && command == 18 && wire.length >= 108
                    && ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN).getShort(64) == 44;
        }

        Event(int id, int connection, boolean server, byte[] wire) {
            this.id = id; this.connection = connection; this.server = server; this.wire = wire;
            assertArrayEquals(new byte[]{(byte) 0xfe, 'S', 'M', 'B'}, Arrays.copyOf(wire, 4), "Plaintext SMB2 signing only");
            ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
            int flags = header.getInt(16);
            assertEquals(server, (flags & 1) != 0, "Socket sender role must match the wire header");
            signed = (flags & 8) != 0;
            command = header.getShort(12) & 65535;
            creditCharge = header.getShort(6) & 65535;
            creditGrant = header.getShort(14) & 65535;
            mid = header.getLong(24); sessionId = header.getLong(40); status = header.getInt(8) & 0xffffffffL;
        }
    }
}
