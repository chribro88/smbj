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
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.Server;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class LeaseChannelOwnershipTest {
    @Test
    void secondaryDispatchesTheLogicalSessionsLeaseBreak() throws Exception {
        try (Fixture f = new Fixture()) {
            f.secondary.handle(notification(f.lease, 0));
            awaitBreak(f.lease);
            awaitHandled(f.primary.getLeaseManager(), 1);
            assertEquals(1, f.primary.getLeaseManager().getBreaksHandled());
            assertEquals(1, f.secondary.sequenceWindow.available());
        }
    }

    @Test
    void canonicalRetirementPreservesLeasesForSurvivingChannels() throws Exception {
        try (Fixture f = new Fixture()) {
            f.primary.close(true);
            assertEquals(1, f.session.getChannelCount());
            assertSame(f.lease, f.primary.getLeaseManager().lookup(f.lease.getLeaseKey()));
            f.secondary.handle(notification(f.lease, 0));
            awaitBreak(f.lease);
            assertTrue(f.secondary.isConnected());
        }
    }

    @Test
    void sessionQualifiedBreakCannotInvalidateAnotherSessionsLease() throws Exception {
        try (Fixture f = new Fixture()) {
            Session other = f.addSession(48);
            LeaseEntry barrier = f.lease(other, "barrier");
            f.primary.handle(notification(f.lease, 48));
            f.primary.handle(notification(barrier, 48));
            awaitBreak(barrier);
            awaitHandled(f.primary.getLeaseManager(), 1);
            assertFalse(f.lease.isBroken());
            assertEquals(1, f.primary.getLeaseManager().getBreaksHandled());
            assertEquals(1, f.primary.sequenceWindow.available());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void lastChannelClosureReleasesTheRetiredCanonicalsExecutor(boolean primaryFirst) throws Exception {
        try (Fixture f = new Fixture()) {
            Connection first = primaryFirst ? f.primary : f.secondary;
            Connection last = primaryFirst ? f.secondary : f.primary;
            first.close(true);
            assertFalse(executor(f.primary.getLeaseManager()).isShutdown());
            last.close(true);
            assertNull(f.primary.getLeaseManager().lookup(f.lease.getLeaseKey()));
            assertTrue(f.lease.isBroken());
            assertTrue(executor(f.primary.getLeaseManager()).isShutdown());
            assertNull(f.primary.getSessionTable().find(f.session.getSessionId()));
            Connection lateCandidate = f.connection();
            try {
                assertThrows(IllegalStateException.class, () -> f.session.addBorrowedChannel(lateCandidate,
                        new SecretKeySpec(new byte[16], "AES")), "A pending bind cannot resurrect released lease state");
            } finally { lateCandidate.close(true); }
        }
    }

    @Test
    void closingOneSessionAfterCanonicalRetirementPreservesOtherOwner() throws Exception {
        try (Fixture f = new Fixture()) {
            Session other = f.addSession(48);
            LeaseEntry otherLease = f.lease(other, "other");
            f.primary.close(true);
            assertThrows(java.io.IOException.class, f.session::close);
            assertFalse(executor(f.primary.getLeaseManager()).isShutdown());
            assertNull(f.primary.getLeaseManager().lookup(f.lease.getLeaseKey()));
            f.secondary.handle(notification(otherLease, 0));
            awaitBreak(otherLease);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void queuedBreakCannotBeAppliedToAReplacementLeaseOwner(boolean reusedEntry) throws Exception {
        try (Fixture f = new Fixture()) {
            LeaseManager manager = f.primary.getLeaseManager();
            CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
            executor(manager).submit(() -> {
                entered.countDown();
                try { assertTrue(release.await(5, TimeUnit.SECONDS)); }
                catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new AssertionError(failure); }
            });
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            try {
                Session other = f.addSession(48);
                LeaseEntry barrier = f.lease(other, "barrier");
                f.primary.handle(notification(f.lease, 47));
                if (!reusedEntry) assertThrows(java.io.IOException.class, f.session::close);
                LeaseEntry replacement = reusedEntry ? f.lease
                        : new LeaseEntry(f.lease.getLeaseKey(), null, 3, "replacement");
                replacement.setOwner(other, 7, SMB2Dialect.SMB_3_1_1);
                manager.register(replacement);
                f.primary.handle(notification(barrier, 48));
                release.countDown();
                awaitBreak(barrier);
                awaitHandled(manager, 1);
                assertFalse(replacement.isBroken());
            } finally { release.countDown(); }
        }
    }

    @Test
    void lateBreakAfterManagerShutdownIsIgnored() throws Exception {
        LeaseManager manager = new LeaseManager();
        manager.close();
        LeaseEntry lease = new LeaseEntry(LeaseKey.random(), null, 3, "late");
        com.hierynomus.mssmb2.messages.SMB2LeaseBreakNotification notification =
                new com.hierynomus.mssmb2.messages.SMB2LeaseBreakNotification().parse(notification(lease, 0));
        assertDoesNotThrow(() -> manager.dispatchBreak(notification));
    }

    private static ExecutorService executor(LeaseManager manager) throws Exception {
        Field field = LeaseManager.class.getDeclaredField("breakExecutor");
        field.setAccessible(true);
        return (ExecutorService) field.get(manager);
    }

    private static void awaitHandled(LeaseManager manager, int count) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (manager.getBreaksHandled() < count && System.nanoTime() < deadline) Thread.sleep(5);
        assertEquals(count, manager.getBreaksHandled());
    }

    @Test
    void failedSessionLogoffReleasesOnlyItsOwnLeaseState() throws Exception {
        try (Fixture f = new Fixture()) {
            Session other = f.addSession(48);
            LeaseEntry otherLease = f.lease(other, "other");
            assertThrows(java.io.IOException.class, f.session::close);
            assertNull(f.primary.getLeaseManager().lookup(f.lease.getLeaseKey()));
            assertSame(otherLease, f.primary.getLeaseManager().lookup(otherLease.getLeaseKey()));
            assertNull(f.primary.getSessionTable().find(f.session.getSessionId()));
            assertNull(f.secondary.getSessionTable().find(f.session.getSessionId()));
            assertSame(other, f.secondary.getSessionTable().find(other.getSessionId()));
            f.secondary.handle(notification(otherLease, 0));
            awaitBreak(otherLease);
        }
    }

    private static SMB2PacketData notification(LeaseEntry lease, long sessionId) throws Exception {
        byte[] wire = new byte[108];
        ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(0, 0x424d53fe); header.putShort(4, (short) 64); header.putShort(12, (short) 18);
        header.putShort(14, (short) 100); header.putInt(16, 1); header.putLong(24, -1); header.putLong(40, sessionId);
        header.putShort(64, (short) 44); header.putInt(88, 3);
        System.arraycopy(lease.getLeaseKey().getBytes(), 0, wire, 72, 16);
        return new SMB2PacketData(wire);
    }

    private static void awaitBreak(LeaseEntry lease) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (!lease.isBroken() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue(lease.isBroken(), "The session's lease must be reachable through its receiving channel");
    }

    private static class Fixture implements AutoCloseable {
        final SMBEventBus bus = new SMBEventBus();
        final SmbConfig config = SmbConfig.builder().withTransactTimeout(10, TimeUnit.MILLISECONDS).build();
        final List<Session> sessions = new ArrayList<>();
        final Connection primary = connection(), secondary = connection();
        final Session session = addSession(47);
        final LeaseEntry lease = lease(session, "held");

        Fixture() throws Exception { }

        @SuppressWarnings("unchecked")
        private Connection connection() {
            try {
                TransportLayer<SMBPacket<?, ?>> transport = mock(TransportLayer.class);
                when(transport.isConnected()).thenReturn(true);
                SmbConfig settings = SmbConfig.builder(config).withTransportLayerFactory((handlers, ignored) -> transport).build();
                Connection result = new Connection(settings, null, bus, new ServerList());
                ConnectionContext context = mock(ConnectionContext.class);
                when(context.getServer()).thenReturn(new Server("peer", 445));
                when(context.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
                Field field = Connection.class.getDeclaredField("connectionContext"); field.setAccessible(true); field.set(result, context);
                return result;
            } catch (Exception failure) { throw new AssertionError(failure); }
        }

        Session addSession(long id) {
            Signatory signer = mock(Signatory.class); when(signer.sign(any(), any())).thenAnswer(call -> call.getArgument(0));
            Session result = new Session(primary, config, null, bus, null, signer, null);
            result.setSessionId(id); result.getSessionContext().setSigningKey(new SecretKeySpec(new byte[16], "AES"));
            result.addBorrowedChannel(secondary, new SecretKeySpec(new byte[16], "AES"));
            primary.getSessionTable().registerSession(id, result); secondary.getSessionTable().registerSession(id, result);
            sessions.add(result); return result;
        }

        LeaseEntry lease(Session owner, String path) {
            LeaseEntry result = new LeaseEntry(LeaseKey.random(), null, 3, path);
            result.setGrantedState(3); result.setOwner(owner, 7, SMB2Dialect.SMB_3_1_1);
            primary.getLeaseManager().register(result); return result;
        }

        @Override public void close() throws Exception {
            primary.close(true); secondary.close(true);
            for (Session owner : sessions) {
                try { owner.close(); } catch (java.io.IOException expectedAfterTransportClosure) { }
            }
        }
    }
}
