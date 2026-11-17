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

import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.transport.tcp.direct.DirectTcpTransport;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import static com.hierynomus.smbj.testing.MultichannelTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Explicit physical endpoints; enabled only when a separately routed address is supplied. */
class MultichannelMultiEndpointIT {
    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#configurations")
    void distinctPhysicalAddressesShareOneSessionAndOpen(String port, boolean encryption, boolean writeThrough) throws Exception {
        String secondary = System.getenv("SMB_TEST_SECONDARY_HOST");
        assumeTrue(port != null && secondary != null, "SMB_TEST_SECONDARY_HOST enables distinct-address tests");
        assertNotEquals(InetAddress.getByName(hostname()), InetAddress.getByName(secondary));
        new BoundChannelsIT().verifyChannels(port, encryption, writeThrough, secondary,
                System.getenv().getOrDefault("SMB_TEST_SECONDARY_PORT", port));
    }

    @ParameterizedTest(name = "{displayName}: port={0}, encryption={1}, writeThrough={2}")
    @MethodSource("com.hierynomus.smbj.testing.MultichannelTestSupport#configurations")
    void differentIdentityClosesOwnedCandidateAndPrimaryRemainsUsable(String port, boolean encryption, boolean writeThrough) throws Exception {
        String secondary = System.getenv("SMB_TEST_SECONDARY_HOST");
        String otherPort = System.getenv("SMB_TEST_DIFFERENT_SERVER_PORT");
        assumeTrue(port != null && secondary != null && otherPort != null, "A different server endpoint enables identity rejection");
        List<com.hierynomus.protocol.transport.TransportLayer<com.hierynomus.smb.SMBPacket<?, ?>>> transports = new ArrayList<>();
        SmbConfig settings = SmbConfig.builder(config(encryption)).withTransportLayerFactory((handlers, configuration) -> {
            com.hierynomus.protocol.transport.TransportLayer<com.hierynomus.smb.SMBPacket<?, ?>> transport = new DirectTcpTransport<>(configuration.getSocketFactory(), configuration.getSoTimeout(), handlers);
            transports.add(transport);
            return transport;
        }).build();
        try (SMBClient client = new SMBClient(settings);
             Connection primary = client.connect(hostname(), Integer.parseInt(port));
             Session session = primary.authenticate(authentication())) {
            java.io.IOException failure = assertThrows(java.io.IOException.class,
                    () -> client.openChannel(session, System.getenv().getOrDefault("SMB_TEST_DIFFERENT_SERVER_HOST", secondary), Integer.parseInt(otherPort)));
            assertTrue(failure.getMessage().contains("Different server found"));
            assertEquals(2, transports.size());
            assertFalse(transports.get(1).isConnected());
            assertEquals(1, session.getChannelCount());
            try (com.hierynomus.smbj.share.DiskShare share = (com.hierynomus.smbj.share.DiskShare) session.connectShare(shareName())) {
                assertNotNull(share.list(""));
            }
        }
    }
}
