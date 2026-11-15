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
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.*;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static com.hierynomus.smbj.testing.MultichannelTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Timeout(90)
class GmacLeaseIsolationIT {
    static Stream<Arguments> profiles() {
        return Stream.of(Arguments.of(false, false), Arguments.of(true, false),
                Arguments.of(false, true), Arguments.of(true, true));
    }

    @ParameterizedTest
    @MethodSource("profiles")
    void isolatedCachesAndAnExistingSecondSessionHandleSurviveOwnerClosure(boolean encryption, boolean jce) throws Exception {
        assumeTrue("true".equals(System.getenv("SMB_TEST_LEASE_ISOLATION")), "Dedicated disposable two-share fixture required");
        int port = Integer.parseInt(System.getenv("SMB_TEST_PORTS"));
        GmacBindingWireObserver observer = new GmacBindingWireObserver(hostname(), port);
        SmbConfig settings = observer.configuration(SmbConfig.builder(config(encryption))
                .withSecurityProvider(jce ? new JceSecurityProvider() : new BCSecurityProvider())
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC).withDirectoryLeasingEnabled(true).build());
        String parent = "gmac-isolation-" + UUID.randomUUID();
        String path = parent + "/dir";
        String privatePath = "private/" + parent + "/dir";
        // The dedicated fixture removes its bounded tmpfs; unique paths isolate the four profiles.
        try (SMBClient client = new SMBClient(settings);
             SMBClient channelOwner = new SMBClient(settings);
             Connection primary = client.connect(hostname(), port)) {
            observer.register(primary);
            try (Session first = primary.authenticate(authentication())) {
                observer.original(first, primary); observer.bound(first, primary);
                assertEquals(SMB3SigningAlgorithm.AES_GMAC, primary.getConnectionContext().getSigningAlgorithm());
                if (encryption) assertEquals(SMB3EncryptionCipher.AES_128_GCM, primary.getConnectionContext().getCipherId());
                assertTrue(primary.getConnectionContext().supportsDirectoryLeasing());
                try (DiskShare left = (DiskShare) first.connectShare(shareName());
                     DiskShare right = (DiskShare) first.connectShare("other")) {
                    left.mkdir(parent); left.mkdir(path); right.mkdir(parent); right.mkdir(path);
                    write(left, path + "/left.txt"); write(right, path + "/right.txt");
                    left.mkdir("private/" + parent); left.mkdir(privatePath);
                    write(left, privatePath + "/secret.txt");
                    LeaseEntry leftEntry = cache(left, path, "left.txt", "right.txt");
                    LeaseEntry rightEntry = cache(right, path, "right.txt", "left.txt");
                    LeaseEntry privateEntry = cache(left, privatePath, "secret.txt", "left.txt");
                    assertNotEquals(leftEntry.getLeaseKey(), rightEntry.getLeaseKey());
                    AuthenticationContext secondUser = new AuthenticationContext(System.getenv("SMB_TEST_SECOND_USERNAME"),
                            System.getenv("SMB_TEST_PASSWORD").toCharArray(), System.getenv("SMB_TEST_DOMAIN"));
                    try (Session second = primary.authenticate(secondUser)) {
                        observer.auxiliary(second, primary);
                        try (DiskShare secondShare = (DiskShare) second.connectShare(shareName())) {
                            SMBApiException denied = assertThrows(SMBApiException.class, () -> secondShare.list(privatePath));
                            assertEquals(NtStatus.STATUS_ACCESS_DENIED.getValue(), denied.getStatusCode());
                            LeaseEntry secondEntry = cache(secondShare, path, "left.txt", "right.txt");
                            assertNotEquals(leftEntry.getLeaseKey(), secondEntry.getLeaseKey());
                            assertSame(second, secondEntry.getSession());
                            Connection secondary = channelOwner.connect(hostname(), port);
                            observer.register(secondary);
                            secondary.bind(first); observer.bound(first, secondary);
                            secondary.bind(second); observer.auxiliary(second, secondary);
                            assertEquals(2, first.getChannelCount()); assertEquals(2, second.getChannelCount());
                            try (Directory held = secondShare.openDirectory(path, EnumSet.of(AccessMask.GENERIC_READ),
                                    null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                                primary.close(true);
                                assertEquals(1, first.getChannelCount()); assertEquals(1, second.getChannelCount());
                                first.close();
                                assertTrue(secondary.isConnected()); assertEquals(1, second.getChannelCount());
                                LeaseManager manager = primary.getLeaseManager();
                                assertNull(manager.lookup(leftEntry.getLeaseKey()));
                                assertNull(manager.lookup(rightEntry.getLeaseKey()));
                                assertNull(manager.lookup(privateEntry.getLeaseKey()));
                                assertSame(secondEntry, manager.getByPath(secondShare.getTreeConnect(), path));
                                listing(held.list(), "left.txt", "right.txt");
                                listing(secondShare.list(path), "left.txt", "right.txt");
                            }
                        }
                    }
                }
            }
        }
        observer.verifyAndReport("lease-isolation-" + jce + "-" + encryption, 0, 8, 16, 2);
        System.out.printf("GMAC_LEASE_ISOLATION java=%s provider=%s signing=AES_GMAC encrypt=%s cipher=%s cacheScopes=4 secondUserDenied=true primaryRetired=true firstSessionClosed=true existingSecondHandle=true%n",
                System.getProperty("java.version"), jce ? "JCE" : "BC", encryption, encryption ? "AES_128_GCM" : "none");
    }

    private static LeaseEntry cache(DiskShare share, String path, String expected, String absent) {
        listing(share.list(path), expected, absent);
        LeaseEntry entry = share.getTreeConnect().getSession().getConnection().getLeaseManager()
                .getByPath(share.getTreeConnect(), path);
        assertNotNull(entry); assertTrue(entry.isGranted()); assertTrue(SMB2LeaseState.isReadHandle(entry.getGrantedState()));
        assertSame(share.getTreeConnect(), entry.getTreeConnect());
        long hits = entry.getCache().getServeHits();
        listing(share.list(path), expected, absent);
        assertEquals(hits + 1, entry.getCache().getServeHits());
        return entry;
    }

    private static void listing(List<FileIdBothDirectoryInformation> items, String expected, String absent) {
        assertTrue(items.stream().anyMatch(item -> expected.equals(item.getFileName())));
        assertFalse(items.stream().anyMatch(item -> absent.equals(item.getFileName())));
    }

    private static void write(DiskShare share, String path) {
        try (File file = share.openFile(path, EnumSet.of(AccessMask.GENERIC_WRITE), null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
            assertEquals(1, file.write(new byte[]{1}, 0));
        }
    }
}
