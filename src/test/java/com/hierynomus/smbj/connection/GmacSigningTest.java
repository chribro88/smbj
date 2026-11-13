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
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.mssmb2.messages.SMB2Cancel;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.security.jce.JceSecurityProvider;
import com.hierynomus.smb.SMBBuffer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.*;
import java.util.ArrayList;
import java.util.List;
import com.hierynomus.security.AEADBlockCipher;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import org.junit.jupiter.params.provider.CsvSource;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class GmacSigningTest {
    @Test
    void duplicateBindingInputsAlreadyExistAtTheProviderBoundary() throws Exception {
        List<byte[]> keys = new ArrayList<>();
        List<byte[]> nonces = new ArrayList<>();
        BCSecurityProvider provider = new BCSecurityProvider() {
            @Override public AEADBlockCipher getAEADBlockCipher(String algorithm) {
                AEADBlockCipher cipher = spy(super.getAEADBlockCipher(algorithm));
                try {
                    doAnswer(call -> {
                        keys.add(((byte[]) call.getArgument(1)).clone());
                        nonces.add(((GCMParameterSpec) call.getArgument(2)).getIV());
                        return call.callRealMethod();
                    }).when(cipher).init(any(), any(), any());
                } catch (com.hierynomus.security.SecurityException failure) {
                    throw new AssertionError(failure);
                }
                return cipher;
            }
        };
        PacketSignatory signatory = new PacketSignatory(provider);
        SecretKeySpec syntheticKey = new SecretKeySpec(new byte[16], "AES-GMAC");
        for (int channel = 0; channel < 2; channel++) {
            SMB2SessionSetup binding = new SMB2SessionSetup(SMB2Dialect.SMB_3_1_1,
                    java.util.EnumSet.noneOf(SMB2SessionSetup.SMB2SecurityMode.class),
                    java.util.EnumSet.noneOf(SMB2GlobalCapability.class));
            binding.setBinding(true);
            binding.setSecurityBuffer(new byte[]{(byte) channel});
            binding.getHeader().setMessageId(1);
            signatory.sign(binding, syntheticKey).write(new SMBBuffer());
        }
        assertEquals(2, keys.size());
        assertArrayEquals(keys.get(0), keys.get(1));
        assertArrayEquals(nonces.get(0), nonces.get(1));
        assertEquals(1, nonces.get(0)[0]);
        // The binding admission guard must reject this case before signing; the provider cannot repair its inputs.
    }

    @ParameterizedTest
    @CsvSource({"false,false,0", "false,false,72623859790382856", "false,true,72623859790382856",
            "true,false,72623859790382856", "true,true,72623859790382856"})
    void matchesIndependentGmacOracleAndSeparatesCancelAndResponseNonces(boolean response, boolean cancel, long messageId) throws Exception {
        for (SecurityProvider provider : new SecurityProvider[]{new BCSecurityProvider(), new JceSecurityProvider()}) {
            SMB2Packet packet = cancel ? new SMB2Cancel(SMB2Dialect.SMB_3_1_1, 47, messageId, 0) : new SMB2Echo(SMB2Dialect.SMB_3_1_1);
            packet.getHeader().setMessageId(messageId);
            if (response) packet.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
            SecretKeySpec key = new SecretKeySpec(new byte[16], "AES-GMAC");
            PacketSignatory signatory = new PacketSignatory(provider);
            SMBBuffer buffer = new SMBBuffer();
            signatory.sign(packet, key).write(buffer);
            byte[] wire = buffer.getCompactData();
            byte[] received = Arrays.copyOfRange(wire, 48, 64);
            Arrays.fill(wire, 48, 64, (byte) 0);
            byte[] nonce = new byte[12];
            for (int i = 0; i < 8; i++) nonce[i] = (byte) (messageId >>> (8 * i));
            nonce[8] = (byte) ((response ? 1 : 0) | (cancel ? 2 : 0));
            Cipher oracle = Cipher.getInstance("AES/GCM/NoPadding");
            oracle.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"), new GCMParameterSpec(128, nonce));
            oracle.updateAAD(wire);
            assertArrayEquals(oracle.doFinal(), received);
            System.arraycopy(received, 0, wire, 48, 16);
            assertTrue(signatory.verify(new SMB2PacketData(wire), key));
            wire[wire.length - 1] ^= 1;
            assertFalse(signatory.verify(new SMB2PacketData(wire), key));
        }
    }
}
