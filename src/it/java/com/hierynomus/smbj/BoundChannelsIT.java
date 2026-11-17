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
package com.hierynomus.smbj;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.mssmb2.*;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static com.hierynomus.smbj.testing.MultichannelTestSupport.*;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class BoundChannelsIT {
    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#configurations")
    void oneOpenUsesTwoBoundChannelsWithVerifiedContent(String port, boolean encryption, boolean writeThrough) throws Exception {
        verifyChannels(port, encryption, writeThrough, hostname(), port);
    }

    void verifyChannels(String port, boolean encryption, boolean writeThrough, String secondaryHost, String secondaryPort) throws Exception {
        assumeTrue(port != null, "SMB_TEST_PORT enables the dedicated Samba integration test");
        String hostname = hostname();
        SmbConfig config = config(encryption);
        String path = "bound-" + UUID.randomUUID() + ".bin";
        try (SMBClient client = new SMBClient(config);
             Connection primary = client.connect(hostname, Integer.parseInt(port));
             Session session = primary.authenticate(authentication())) {
            assertEquals(dialect(), primary.getNegotiatedProtocol().getDialect());
            SMB3SigningAlgorithm algorithm = primary.getConnectionContext().getSigningAlgorithm();
            if (algorithm == null) algorithm = SMB3SigningAlgorithm.AES_CMAC; // implicit SMB 3.x default
            assertEquals(SMB3SigningAlgorithm.AES_CMAC, algorithm);
            assertEquals(encryption, session.shouldEncryptData());
            byte[] signingKey = session.getSessionContext().getSigningKey().getEncoded().clone();
            javax.crypto.SecretKey encryptionKey = session.getSessionContext().getEncryptionKey();
            try (DiskShare share = (DiskShare) session.connectShare(shareName())) {
                try (File file = share.openFile(path, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                        EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_CREATE, writeThrough ? EnumSet.of(SMB2CreateOptions.FILE_WRITE_THROUGH) : EnumSet.noneOf(SMB2CreateOptions.class))) {
                    Connection secondary = client.openChannel(session, secondaryHost, Integer.parseInt(secondaryPort));
                    assertNotSame(primary, secondary);
                    assertEquals(hostname, secondary.getRemoteHostname());
                    assertEquals(primary.getConnectionContext().getServerGuid(), secondary.getConnectionContext().getServerGuid());
                    assertEquals(primary.getConnectionContext().getClientGuid(), secondary.getConnectionContext().getClientGuid());
                    assertEquals(primary.getConnectionContext().getSigningAlgorithm(), secondary.getConnectionContext().getSigningAlgorithm());
                    assertEquals(primary.getConnectionContext().getCipherId(), secondary.getConnectionContext().getCipherId());
                    assertEquals(dialect(), secondary.getNegotiatedProtocol().getDialect());
                    assertArrayEquals(signingKey, session.getSessionContext().getSigningKey().getEncoded());
                    assertSame(encryptionKey, session.getSessionContext().getEncryptionKey());
                    assertEquals(2, session.getChannelCount());
                    byte[] left = new byte[65536];
                    byte[] right = new byte[65536];
                    Arrays.fill(left, (byte) 0x35);
                    Arrays.fill(right, (byte) 0x6a);
                    ExecutorService workers = Executors.newFixedThreadPool(2);
                    try {
                        Future<?> a = workers.submit(() -> {
                            for (int i = 0; i < 16; i++) assertEquals(left.length, file.write(left, (long) i * left.length));
                        });
                        Future<?> c = workers.submit(() -> {
                            for (int i = 16; i < 32; i++) assertEquals(right.length, file.write(right, (long) i * right.length));
                        });
                        a.get(30, TimeUnit.SECONDS);
                        c.get(30, TimeUnit.SECONDS);
                    } finally {
                        workers.shutdownNow();
                        assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS));
                    }
                    file.flush();
                    byte[] actual = new byte[65536];
                    for (int i = 0; i < 32; i++) {
                        assertEquals(actual.length, file.read(actual, (long) i * actual.length));
                        assertArrayEquals(i < 16 ? left : right, actual);
                    }
                    assertTrue(primary.getWriteRequestCount() > 0);
                    assertTrue(secondary.getWriteRequestCount() > 0);
                    primary.close(true);
                    assertEquals(left.length, file.write(left, 0));
                    assertEquals(actual.length, file.read(actual, 0));
                    assertArrayEquals(left, actual);
                    assertEquals(1, session.getChannelCount());
                    System.out.printf("BOUND session=%d channels=2 primaryWrites=%d secondaryWrites=%d encryption=%s writeThrough=%s verifiedBytes=%d hostname=%s port=%s secondaryHost=%s secondaryPort=%s requestedDialect=%s negotiatedDialect=%s serverGuid=%s clientGuid=%s signing=%s cipher=%s primaryBytes=%d secondaryBytes=%d%n",
                            session.getSessionId(), primary.getWriteRequestCount(), secondary.getWriteRequestCount(), encryption, writeThrough, 32 * actual.length, hostname, port, secondaryHost, secondaryPort, dialect(), primary.getNegotiatedProtocol().getDialect(),
                            primary.getConnectionContext().getServerGuid(), config.getClientGuid(), algorithm,
                            primary.getConnectionContext().getCipherId(), primary.getWriteRequestCount() * actual.length, secondary.getWriteRequestCount() * actual.length);
                } finally {
                    share.rm(path);
                }
            }
        }
    }
}
