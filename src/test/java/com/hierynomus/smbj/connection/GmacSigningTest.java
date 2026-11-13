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
import org.junit.jupiter.params.provider.ValueSource;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.mssmb2.messages.SMB2Logoff;
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
            SecretKeySpec key = new SecretKeySpec(new byte[16], "AES-GMAC");
            PacketSignatory signatory = new PacketSignatory(provider);
            SMBBuffer buffer = new SMBBuffer();
            signatory.sign(packet, key).write(buffer);
            byte[] wire = buffer.getCompactData();
            if (response) wire[16] |= 1;
            byte[] received = Arrays.copyOfRange(wire, 48, 64);
            Arrays.fill(wire, 48, 64, (byte) 0);
            byte[] nonce = new byte[12];
            for (int i = 0; i < 8; i++) nonce[i] = (byte) (messageId >>> (8 * i));
            nonce[8] = (byte) ((response ? 1 : 0) | (cancel ? 2 : 0));
            Cipher oracle = Cipher.getInstance("AES/GCM/NoPadding");
            oracle.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "AES"), new GCMParameterSpec(128, nonce));
            oracle.updateAAD(wire);
            byte[] expected = oracle.doFinal();
            if (response) received = expected;
            else assertArrayEquals(expected, received);
            System.arraycopy(received, 0, wire, 48, 16);
            assertEquals(response, signatory.verify(new SMB2PacketData(wire), key));
            wire[wire.length - 1] ^= 1;
            assertFalse(signatory.verify(new SMB2PacketData(wire), key));
        }
    }
    @ParameterizedTest
    @ValueSource(ints = {0, 15, 17})
    void invalidProviderTagLengthCannotProduceOrVerifyAPacket(int length) throws Exception {
        AEADBlockCipher cipher = mock(AEADBlockCipher.class);
        when(cipher.doFinal(any(), anyInt(), anyInt())).thenReturn(new byte[length]);
        SecurityProvider provider = mock(SecurityProvider.class);
        when(provider.getAEADBlockCipher(anyString())).thenReturn(cipher);
        PacketSignatory signatory = new PacketSignatory(provider);
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES-GMAC");
        assertThrows(IllegalStateException.class,
                () -> signatory.sign(new SMB2Echo(SMB2Dialect.SMB_3_1_1), key).write(new SMBBuffer()));
        assertThrows(IllegalStateException.class, () -> signatory.verify(new SMB2PacketData(response(7, 68)), key));
    }

    private static SecurityProvider provider(boolean jce) {
        return jce ? new JceSecurityProvider() : new BCSecurityProvider();
    }

    // smb-rs f4524d032c8951cc288e1c8231ad68588583abda, signer.rs.
    // The vector's MIT notice is retained in docs/gmac-test-vector-notices.md.
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void fixedLogoffVectorAtNonzeroOffset(boolean jce) {
        SMB2Logoff packet = new SMB2Logoff(SMB2Dialect.SMB_3_1_1, 0x210c2053L);
        packet.getHeader().setMessageId(9);
        packet.getHeader().setFlags(0x18);
        SMBBuffer buffer = new SMBBuffer();
        buffer.putReserved(11);
        new PacketSignatory(provider(jce)).sign(packet,
                new SecretKeySpec(ByteArrayUtils.parseHex("ac36e9543cd888f0a84123e46bb2a0d7"), "AES-GMAC")).write(buffer);
        assertEquals(11, packet.getHeader().getHeaderStartPosition());
        assertArrayEquals(ByteArrayUtils.parseHex("76234b3c812f51ab8a5cf9fa43d4eb28"),
                Arrays.copyOfRange(buffer.array(), 59, 75));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void compoundsAuthenticateOnlyTheirOwnExtentIncludingPadding(boolean jce) throws Exception {
        byte[] first = response(1, 72), second = response(2, 68);
        first[20] = 72;
        authenticate(first);
        authenticate(second);
        byte[] frame = new byte[140];
        System.arraycopy(first, 0, frame, 0, 72);
        System.arraycopy(second, 0, frame, 72, 68);
        PacketSignatory signatory = new PacketSignatory(provider(jce));
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES-GMAC");
        SMB2PacketData head = new SMB2PacketData(frame);
        head.getDataBuffer().rpos(72);
        SMB2PacketData tail = head.next();
        byte[] before = frame.clone();
        assertTrue(signatory.verify(head, key));
        assertTrue(signatory.verify(tail, key));
        assertTrue(signatory.verify(head, key));
        assertArrayEquals(before, frame);
        frame[71] ^= 1;
        assertFalse(signatory.verify(head, key));
        assertTrue(signatory.verify(tail, key));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rejectsMalformedExtentUnsignedWrongKeyAndWrongSender(boolean jce) throws Exception {
        PacketSignatory signatory = new PacketSignatory(provider(jce));
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES-GMAC");
        byte[] wire = response(3, 68);
        authenticate(wire);
        assertTrue(signatory.verify(new SMB2PacketData(wire), key));
        for (int position : new int[]{4, 12, 16, 24, 48, 67}) {
            byte[] corrupt = wire.clone();
            corrupt[position] ^= 1;
            assertFalse(signatory.verify(new SMB2PacketData(corrupt), key));
        }
        for (int next : new int[]{8, 65, 72}) {
            byte[] corrupt = wire.clone();
            corrupt[20] = (byte) next;
            assertFalse(signatory.verify(new SMB2PacketData(corrupt), key));
        }
        byte[] wrongKey = new byte[16]; wrongKey[0] = 1;
        assertFalse(signatory.verify(new SMB2PacketData(wire), new SecretKeySpec(wrongKey, "AES-GMAC")));
        wire[16] &= ~8;
        assertFalse(signatory.verify(new SMB2PacketData(wire), key));
        wire[16] = 8;
        authenticate(wire); // Cryptographically valid client-role message received by a client.
        assertFalse(signatory.verify(new SMB2PacketData(wire), key));
        SMB2Echo outbound = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        outbound.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
        assertThrows(IllegalArgumentException.class, () -> signatory.sign(outbound, key).write(new SMBBuffer()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void concurrentMessagesUseIndependentProviderState(boolean jce) throws Exception {
        PacketSignatory signatory = new PacketSignatory(provider(jce));
        java.util.concurrent.ExecutorService workers = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            java.util.List<java.util.concurrent.Callable<Void>> calls = new java.util.ArrayList<>();
            for (int i = 0; i < 20; i++) {
                final int mid = i;
                calls.add(() -> {
                    SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
                    packet.getHeader().setMessageId(mid);
                    SMBBuffer buffer = new SMBBuffer();
                    signatory.sign(packet, new SecretKeySpec(new byte[16], "AES-GMAC")).write(buffer);
                    byte[] wire = buffer.getCompactData();
                    byte[] expected = wire.clone();
                    authenticate(expected);
                    assertArrayEquals(expected, wire);
                    byte[] reply = response(mid, 68);
                    authenticate(reply);
                    assertTrue(signatory.verify(new SMB2PacketData(reply), new SecretKeySpec(new byte[16], "AES-GMAC")));
                    return null;
                });
            }
            for (java.util.concurrent.Future<Void> task : workers.invokeAll(calls, 10, java.util.concurrent.TimeUnit.SECONDS)) {
                task.get(1, java.util.concurrent.TimeUnit.SECONDS);
            }
        } finally {
            workers.shutdownNow();
        }
    }

    private static byte[] response(long mid, int size) {
        byte[] wire = new byte[size];
        wire[0] = (byte) 0xfe; wire[1] = 'S'; wire[2] = 'M'; wire[3] = 'B';
        wire[4] = 64; wire[12] = 13; wire[16] = 9; wire[64] = 4;
        for (int i = 0; i < 8; i++) wire[24 + i] = (byte) (mid >>> (8 * i));
        return wire;
    }

    private static void authenticate(byte[] wire) throws Exception {
        byte[] nonce = new byte[12];
        System.arraycopy(wire, 24, nonce, 0, 8);
        nonce[8] = (byte) ((wire[16] & 1) | (wire[12] == 12 ? 2 : 0));
        Cipher oracle = Cipher.getInstance("AES/GCM/NoPadding");
        oracle.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new GCMParameterSpec(128, nonce));
        oracle.updateAAD(wire, 0, 48);
        oracle.updateAAD(new byte[16]);
        oracle.updateAAD(wire, 64, wire.length - 64);
        System.arraycopy(oracle.doFinal(), 0, wire, 48, 16);
    }

}
