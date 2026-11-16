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
import com.hierynomus.mssmb2.SMB2GlobalCapability;
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.ServerList;
import com.hierynomus.smbj.testing.PacketProcessor;
import com.hierynomus.smbj.testing.StubTransportLayerFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetSocketAddress;
import java.util.EnumSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class SMBServerIdentityTest {
    @ParameterizedTest
    @ValueSource(strings = {"GUID", "dialect", "securityMode", "capabilities"})
    void secondaryCannotChangeCachedServerPolicy(String mismatch) throws Exception {
        AtomicInteger requests = new AtomicInteger();
        PacketProcessor processor = request -> {
            SMB2NegotiateResponse response = spy((SMB2NegotiateResponse) new PacketProcessor.DefaultPacketProcessor().process(request));
            if (requests.incrementAndGet() == 2) {
                switch (mismatch) {
                    case "GUID": response.setServerGuid(new UUID(0, 99)); break;
                    case "dialect": response.setDialect(SMB2Dialect.SMB_3_0); break;
                    case "securityMode": when(response.getSecurityMode()).thenReturn(1); break;
                    case "capabilities": when(response.getCapabilities()).thenReturn(EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DFS)); break;
                    default: throw new AssertionError(mismatch);
                }
            }
            return response;
        };
        SmbConfig config = SmbConfig.builder().withTransportLayerFactory(new StubTransportLayerFactory<>(processor)).build();
        ServerList servers = new ServerList();
        SMBEventBus bus = new SMBEventBus();
        try (SMBClient client = new SMBClient(config)) {
            Connection primary = new Connection(config, client, bus, servers);
            Connection secondary = new Connection(config, client, bus, servers);
            try {
                primary.connect("IP1", new InetSocketAddress("127.0.0.1", 445));
                TransportException failure = assertThrows(TransportException.class,
                        () -> secondary.connect("IP1", new InetSocketAddress("127.0.0.2", 445)));
                assertTrue(failure.getMessage().contains("same hostname 'IP1': expected GUID="));
                assertTrue(failure.getMessage().contains("received GUID="));
                assertTrue(failure.getMessage().contains(mismatch + "="));
            } finally {
                secondary.close(true);
                primary.close(true);
            }
        }
    }
}
