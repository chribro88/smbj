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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.*;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.Arguments;

import java.util.EnumSet;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.stream.Stream;

import static com.hierynomus.smbj.testing.MultichannelTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Timeout(60)
class GmacLeaseBreakIT {
    static Stream<Arguments> profiles() {
        return Stream.of(Arguments.of(false, false), Arguments.of(true, false),
                Arguments.of(false, true), Arguments.of(true, true));
    }

    @ParameterizedTest
    @MethodSource("profiles")
    void leaseBreakSurvivesCanonicalConnectionRetirement(boolean encryption, boolean jce) throws Exception {
        String ports = System.getenv().getOrDefault("SMB_TEST_PORTS", System.getenv("SMB_TEST_PORT"));
        assumeTrue(ports != null, "Dedicated native Samba fixture required");
        int port = Integer.parseInt(ports.split(",")[0].trim());
        GmacBindingWireObserver observer = new GmacBindingWireObserver(hostname(), port);
        SmbConfig settings = observer.configuration(SmbConfig.builder(config(encryption))
                .withSecurityProvider(jce ? new JceSecurityProvider() : new BCSecurityProvider())
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withDirectoryLeasingEnabled(true).build());
        String parent = "gmac-lease-" + UUID.randomUUID();
        Connection survivor;
        try (SMBClient client = new SMBClient(settings);
             Connection primary = client.connect(hostname(), port)) {
            observer.register(primary);
            try (Session session = primary.authenticate(authentication());
             DiskShare share = (DiskShare) session.connectShare(shareName())) {
            observer.original(session, primary); observer.bound(session, primary);
            assertEquals(SMB3SigningAlgorithm.AES_GMAC, primary.getConnectionContext().getSigningAlgorithm());
            if (encryption) assertEquals(SMB3EncryptionCipher.AES_128_GCM, primary.getConnectionContext().getCipherId());
            assertTrue(primary.getConnectionContext().supportsDirectoryLeasing(), "The fixture must advertise directory leasing");
            Connection secondary = client.openChannel(session, hostname(), port);
            survivor = secondary;
            observer.register(secondary); observer.bound(session, secondary);
            assertEquals(2, session.getChannelCount());
            share.mkdir(parent);
            Throwable problem = null;
            try {
                for (int phase = 0; phase < 2; phase++) {
                    String path = parent + "/" + phase;
                    share.mkdir(path);
                    try (Directory directory = share.openDirectory(path, EnumSet.of(AccessMask.GENERIC_READ),
                            null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                        LeaseEntry lease = directory.getLeaseEntry();
                        assertNotNull(lease); assertTrue(SMB2LeaseState.isHandle(lease.getGrantedState()));
                        System.out.printf("GMAC_LEASE_PHASE encrypt=%s phase=%d granted=%d channels=%d%n",
                                encryption, phase, lease.getGrantedState(), session.getChannelCount());
                        int generation = lease.getCacheGeneration();
                        if (phase == 1) {
                            primary.close(true);
                            assertEquals(1, session.getChannelCount()); assertTrue(secondary.isConnected());
                        }
                        ExecutorService worker = Executors.newSingleThreadExecutor();
                        SmbConfig competingSettings = SmbConfig.builder(config(encryption))
                                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC)
                                .withDirectoryLeasingEnabled(true).withClientGuid(UUID.randomUUID()).build();
                        try (SMBClient competingClient = new SMBClient(competingSettings);
                             Connection competing = competingClient.connect(hostname(), port);
                             Session competingSession = competing.authenticate(authentication());
                             DiskShare competingShare = (DiskShare) competingSession.connectShare(shareName())) {
                            try {
                                Future<?> mutation = worker.submit(() -> {
                                    try (File file = competingShare.openFile(path + "/event.bin", EnumSet.of(AccessMask.GENERIC_WRITE),
                                            null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                                        assertEquals(1, file.write(new byte[]{1}, 0));
                                    }
                                });
                                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
                                while (!lease.isBroken() && System.nanoTime() < deadline) Thread.sleep(10);
                                assertTrue(lease.isBroken(), "A real peer mutation must invalidate the held lease, phase=" + phase);
                                assertTrue(lease.getCacheGeneration() > generation);
                                assertFalse(SMB2LeaseState.isHandle(lease.getGrantedState()));
                                mutation.get(8, TimeUnit.SECONDS);
                                assertTrue(directory.list().stream().anyMatch(item -> "event.bin".equals(item.getFileName())));
                            } catch (Exception | AssertionError failure) {
                                try { competing.close(true); }
                                catch (java.io.IOException cleanup) { if (cleanup != failure) failure.addSuppressed(cleanup); }
                                throw failure;
                            }
                        } finally {
                            worker.shutdownNow(); assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS));
                        }
                    }
                }
            } catch (Exception | AssertionError failure) {
                problem = failure;
                throw failure;
            } finally {
                try { if (session.getChannelCount() > 0) share.rmdir(parent, true); }
                catch (RuntimeException cleanup) {
                    if (problem == null) throw cleanup;
                    if (cleanup != problem) problem.addSuppressed(cleanup);
                }
            }
            assertTrue(secondary.isConnected());
            }
        }
        observer.verifyLeaseBreaks(survivor);
        observer.verifyAndReport("lease-" + jce + "-" + encryption, 0, 8, 16, 2);
        System.out.printf("GMAC_LEASE java=%s provider=%s signing=AES_GMAC encrypt=%s cipher=%s breaks=2 primaryRetired=true existingHandle=true%n",
                System.getProperty("java.version"), jce ? "JCE" : "BC", encryption, encryption ? "AES_128_GCM" : "none");
    }
}
