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
import com.hierynomus.protocol.transport.TransportLayer;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smb.SMBPacket;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.auth.NtlmAuthenticator;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import com.hierynomus.smbj.transport.tcp.async.AsyncDirectTcpTransportFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.Arguments;

import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

import static com.hierynomus.smbj.testing.MultichannelTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class SingleChannelSigningIT {
    static Stream<Arguments> signingConfigurations() {
        return configurations().flatMap(configuration -> {
            Object[] values = configuration.get();
            return Stream.of(false, true).flatMap(async -> Stream.of(false, true)
                    .map(jce -> Arguments.of(values[0], values[1], values[2], async, jce)));
        });
    }

    @ParameterizedTest
    @MethodSource("signingConfigurations")
    void existingFileWorksWithNegotiatedSigningAndAfterGmacBindingRejection(String port, boolean encryption,
            boolean writeThrough, boolean async, boolean jce) throws Exception {
        assumeTrue(port != null, "SMB_TEST_PORT enables dedicated server tests");
        List<TransportLayer<SMBPacket<?, ?>>> transports = new ArrayList<>();
        SmbConfig base = config(encryption);
        boolean gmac = base.getSigningAlgorithms().equals(Collections.singletonList(SMB3SigningAlgorithm.AES_GMAC));
        SmbConfig settings = SmbConfig.builder(base)
                .withSecurityProvider(jce ? (gmac ? new JceSecurityProvider() : new JceSecurityProvider(new BouncyCastleProvider()))
                        : new BCSecurityProvider())
                .withAuthenticators(new NtlmAuthenticator.Factory()).withTransportLayerFactory((handlers, configuration) -> {
            TransportLayer<SMBPacket<?, ?>> transport = async
                    ? new AsyncDirectTcpTransportFactory().createTransportLayer(handlers, configuration)
                    : new DirectTcpTransport<>(configuration.getSocketFactory(), configuration.getSoTimeout(), handlers);
            transports.add(transport);
            return transport;
        }).build();
        String name = "single-" + UUID.randomUUID() + ".bin";
        try (SMBClient client = new SMBClient(settings);
             Connection primary = client.connect(hostname(), Integer.parseInt(port));
             Session session = primary.authenticate(authentication());
             DiskShare share = (DiskShare) session.connectShare(shareName())) {
            System.out.printf("SIGNING_SINGLE provider=%s backend=%s transport=%s encrypt=%s writeThrough=%s dialect=%s signing=%s cipher=%s%n",
                    settings.getSecurityProvider().getClass().getSimpleName(), jce && gmac ? "default-JCE" : "BC",
                    async ? "AsyncDirectTcpTransport" : "DirectTcpTransport", encryption, writeThrough,
                    primary.getNegotiatedProtocol().getDialect(), primary.getConnectionContext().getSigningAlgorithm(),
                    primary.getConnectionContext().getCipherId());
            try (File file = share.openFile(name, EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE,
                    writeThrough ? EnumSet.of(SMB2CreateOptions.FILE_WRITE_THROUGH) : EnumSet.noneOf(SMB2CreateOptions.class))) {
                byte[] bytes = new byte[131072];
                new Random(47).nextBytes(bytes);
                assertEquals(bytes.length, file.write(bytes, 0));
                SMB3SigningAlgorithm algorithm = primary.getConnectionContext().getSigningAlgorithm();
                if (settings.getSigningAlgorithms().equals(Collections.singletonList(SMB3SigningAlgorithm.AES_GMAC))) {
                    assertEquals(SMB3SigningAlgorithm.AES_GMAC, algorithm);
                    IOException failure = assertThrows(IOException.class, () -> client.openChannel(session, hostname(), Integer.parseInt(port)));
                    assertTrue(failure.getMessage().contains("nonce uniqueness"));
                    assertEquals(2, transports.size());
                    assertFalse(transports.get(1).isConnected(), "openChannel closes its rejected owned transport");
                }
                assertEquals(1, session.getChannelCount());
                byte[] actual = new byte[bytes.length];
                assertEquals(bytes.length, file.read(actual, 0));
                assertArrayEquals(bytes, actual);
                bytes[0] ^= 1;
                assertEquals(bytes.length, file.write(bytes, 0));
                assertEquals(bytes.length, file.read(actual, 0));
                assertArrayEquals(bytes, actual);
            } finally {
                share.rm(name);
            }
        }
        for (TransportLayer<SMBPacket<?, ?>> transport : transports) assertFalse(transport.isConnected());
    }
}
