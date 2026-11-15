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
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.smbj.session.Session;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CountDownLatch;
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
    private final byte[] fingerprintKey = new byte[32];
    private long mainSessionId;
    private int originalSocket;
    private byte[] originalKey;
    private int originalKeyBindingRequests, unsignedEchoRequests;
    private boolean originalApplicationTraffic;

    GmacBindingWireObserver() { new SecureRandom().nextBytes(fingerprintKey); }

    synchronized void register(Connection connection) {
        ObservedSocket socket = openedByThread.get(Thread.currentThread());
        assertFalse(owners.containsValue(socket));
        owners.put(connection, socket);
    }

    synchronized void original(Session main, Connection connection) {
        mainSessionId = main.getSessionId();
        originalSocket = owners.get(connection).id;
        originalKey = main.getSessionContext().getSigningKey().getEncoded().clone();
    }

    synchronized void auxiliary(Session session, Connection connection) {
        auxiliaryKeys.computeIfAbsent(owners.get(connection).id, unused -> new HashMap<>())
                .put(session.getSessionId(), session.getSessionContext().getSigningKey().getEncoded().clone());
    }

    synchronized void auxiliaryKeys(Map<Long, byte[]> keys) {
        for (ObservedSocket socket : sockets) {
            auxiliaryKeys.computeIfAbsent(socket.id, unused -> new HashMap<>()).putAll(keys);
        }
    }

    synchronized void bound(Session session, Connection connection) {
        byte[] key = session.getSigningKey(new SMB2Echo(SMB2Dialect.SMB_3_1_1).getHeader(), false, connection)
                .getEncoded().clone();
        assertFalse(Arrays.equals(originalKey, key), "Operational channel key must differ from original key");
        channelKeys.put(owners.get(connection).id, key);
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
        Map<String, String> authenticatedInputs = new HashMap<>();
        Set<String> actualKeys = new HashSet<>();
        int verified = 0;
        int operational = 0;
        int preparedOnly = 0;
        MessageDigest transcript = MessageDigest.getInstance("SHA-256");
        for (Event event : events) {
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
                if (event.connection == originalSocket || (event.command == 1 && (!event.server || event.status != 0))) {
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
        assertTrue(operational >= minimumOperational, "Expected application traffic must be included in the independent verification");
        for (ObservedSocket socket : sockets) {
            assertTrue(socket.isClosed());
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
        if (!"127.0.0.1".equals(host) || port != Integer.parseInt(System.getenv("SMB_TEST_PORTS"))) throw new IOException("Only the owned loopback research fixture is permitted");
        ObservedSocket socket = new ObservedSocket(sockets.size());
        sockets.add(socket);
        openedByThread.put(Thread.currentThread(), socket);
        try {
            if (local != null) socket.bind(new InetSocketAddress(local, localPort));
            socket.connect(new InetSocketAddress(host, port), 5000);
            return socket;
        } catch (IOException failure) {
            try { socket.close(); } catch (IOException close) { failure.addSuppressed(close); }
            throw failure;
        }
    }

    private final class ObservedSocket extends Socket {
        final int id;
        final ByteArrayOutputStream[] pending = {new ByteArrayOutputStream(), new ByteArrayOutputStream()};
        long next;
        long credits = 1;
        final Set<Long> requests = new HashSet<>();
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
                    Event event = new Event(events.size() + 1, id, direction == 1,
                            Arrays.copyOfRange(buffered, consumed + 4, consumed + 4 + size));
                    if (!event.server && event.command == 1 && event.sessionId == mainSessionId
                            && (event.wire[66] & 1) != 0) originalKeyBindingRequests++;
                    if (!event.server && event.command == 13 && event.sessionId == 0) unsignedEchoRequests++;
                    if (!event.server && event.signed && event.connection == originalSocket && event.sessionId == mainSessionId
                            && event.command != 1) originalApplicationTraffic = true;
                    assertEquals(0, ByteBuffer.wrap(event.wire).order(ByteOrder.LITTLE_ENDIAN).getInt(20), "Compound traffic is outside this prototype");
                    if (event.server) {
                        // A loopback response can be read before the writer records its completed write.
                        if (requests.contains(event.mid)) credits += event.creditGrant;
                        else earlyGrants.merge(event.mid, event.creditGrant, Integer::sum);
                    }
                    else if (event.command != 12) {
                        assertEquals(next, event.mid, "Every request must consume the lowest native sequence range");
                        int charge = Math.max(1, event.creditCharge);
                        assertTrue(credits >= charge, "Native per-connection credits must not be exceeded");
                        next += charge;
                        credits -= charge;
                        assertTrue(requests.add(event.mid));
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
