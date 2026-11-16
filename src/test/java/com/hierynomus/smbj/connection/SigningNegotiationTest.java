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
import com.hierynomus.mssmb2.messages.SMB2NegotiateRequest;
import com.hierynomus.mssmb2.messages.negotiate.*;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SmbConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SigningNegotiationTest {
    @Test
    void serializesAndParsesTheSigningCapabilitiesWireFormat() throws Exception {
        SMBBuffer wire = new SMBBuffer();
        new SMB2SigningCapabilities(Arrays.asList(SMB3SigningAlgorithm.AES_GMAC, SMB3SigningAlgorithm.AES_CMAC)).write(wire);
        assertArrayEquals(new byte[]{8,0,6,0,0,0,0,0,2,0,2,0,1,0}, wire.getCompactData());
        SMB2SigningCapabilities parsed = (SMB2SigningCapabilities) SMB2NegotiateContext.factory(new SMBBuffer(wire.getCompactData()));
        assertEquals(Arrays.asList(SMB3SigningAlgorithm.AES_GMAC, SMB3SigningAlgorithm.AES_CMAC), parsed.getAlgorithms());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3})
    void rejectsInvalidCountsAndUnknownAlgorithms(int count) {
        byte[] wire = {8,0,4,0,0,0,0,0,(byte) count,0,127,0};
        assertThrows(IllegalArgumentException.class, () -> SMB2NegotiateContext.factory(new SMBBuffer(wire)));
    }

    @Test
    void gmacIsAnExplicitImmutableConfiguration() {
        SMB3SigningAlgorithm[] algorithms = {SMB3SigningAlgorithm.AES_GMAC};
        SmbConfig config = SmbConfig.builder().withSigningAlgorithms(algorithms).build();
        algorithms[0] = SMB3SigningAlgorithm.AES_CMAC;
        assertEquals(Collections.singletonList(SMB3SigningAlgorithm.AES_GMAC), config.getSigningAlgorithms());
        assertEquals(config.getSigningAlgorithms(), SmbConfig.builder(config).build().getSigningAlgorithms());
        assertThrows(UnsupportedOperationException.class, () -> config.getSigningAlgorithms().clear());
        assertThrows(IllegalArgumentException.class, () -> SmbConfig.builder().withSigningAlgorithms());
        assertThrows(IllegalArgumentException.class, () -> SmbConfig.builder().withSigningAlgorithms((SMB3SigningAlgorithm[]) null));
        assertEquals(Collections.singletonList(SMB3SigningAlgorithm.AES_CMAC), SmbConfig.createDefaultConfig().getSigningAlgorithms());
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"omitted", "unoffered", "duplicate"})
    void rejectedServerSelectionClosesTheTransport(String selection) throws Exception {
        List<SMB2NegotiateContext> contexts = new ArrayList<>();
        if (!selection.equals("omitted")) contexts.add(new SMB2SigningCapabilities(Collections.singletonList(
                selection.equals("unoffered") ? SMB3SigningAlgorithm.AES_CMAC : SMB3SigningAlgorithm.AES_GMAC)));
        if (selection.equals("duplicate")) contexts.add(contexts.get(0));
        com.hierynomus.mssmb2.messages.SMB2NegotiateResponse response = new com.hierynomus.mssmb2.messages.SMB2NegotiateResponse() {
            @Override public List<SMB2NegotiateContext> getNegotiateContextList() { return contexts; }
        };
        response.setDialect(SMB2Dialect.SMB_3_1_1);
        response.getHeader().setMessageType(SMB2MessageCommandCode.SMB2_NEGOTIATE);
        com.hierynomus.smbj.testing.StubTransportLayerFactory factory = new com.hierynomus.smbj.testing.StubTransportLayerFactory(packet -> response);
        java.util.concurrent.atomic.AtomicReference<com.hierynomus.protocol.transport.TransportLayer> created = new java.util.concurrent.atomic.AtomicReference<>();
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1)
                .withSigningAlgorithms(SMB3SigningAlgorithm.AES_GMAC)
                .withTransportLayerFactory((handlers, settings) -> {
                    com.hierynomus.protocol.transport.TransportLayer transport = factory.createTransportLayer(handlers, settings);
                    created.set(transport);
                    return transport;
                }).build();
        try (com.hierynomus.smbj.SMBClient client = new com.hierynomus.smbj.SMBClient(config)) {
            assertThrows(IllegalStateException.class, () -> client.connect("localhost"));
            assertFalse(created.get().isConnected(), "Negotiation rejection must release the owned transport");
        } finally {
            if (created.get() != null) created.get().disconnect();
        }
    }

    @Test
    void advertisesGmacOnlyWithSmb311() {
        for (SMB2Dialect dialect : new SMB2Dialect[]{SMB2Dialect.SMB_3_0_2, SMB2Dialect.SMB_3_1_1}) {
            SMB2NegotiateRequest request = new SMB2NegotiateRequest(EnumSet.of(dialect), new UUID(0, 1), true,
                    EnumSet.noneOf(SMB2GlobalCapability.class), new byte[32], Collections.singletonList(SMB3SigningAlgorithm.AES_GMAC));
            long signingContexts = request.getNegotiateContextList().stream().filter(SMB2SigningCapabilities.class::isInstance).count();
            assertEquals(dialect == SMB2Dialect.SMB_3_1_1 ? 1 : 0, signingContexts);
        }
    }
}
