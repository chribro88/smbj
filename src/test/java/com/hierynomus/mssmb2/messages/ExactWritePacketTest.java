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
package com.hierynomus.mssmb2.messages;
import com.hierynomus.mssmb2.*;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import java.nio.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class ExactWritePacketTest {
    @ParameterizedTest
    @ValueSource(ints={1,1000,65535,65536,65537,70000})
    void declaredLengthEqualsConsumedBytes(int length) {
        byte[] source = new byte[80000];
        for (int i=0;i<source.length;i++) source[i]=(byte)i;
        ArrayByteChunkProvider provider = new ArrayByteChunkProvider(source, 0x100000001L);
        SMB2WriteRequest request = new SMB2WriteRequest(SMB2Dialect.SMB_3_1_1,
                new SMB2FileId(new byte[8], new byte[8]), 4, 5, provider, length);
        request.setCreditsAssigned((length+65535)/65536);
        SMBBuffer buffer = new SMBBuffer();
        request.write(buffer);
        byte[] wire = buffer.getCompactData();
        ByteBuffer header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(length, header.getInt(68));
        assertEquals(0x100000001L, header.getLong(72));
        assertEquals(0, header.getInt(100));
        assertEquals(112+length, wire.length);
        assertArrayEquals(Arrays.copyOf(source,length), Arrays.copyOfRange(wire,112,wire.length));
        assertEquals(source.length-length,provider.bytesLeft());
        assertEquals(0x100000001L+length,provider.getOffset());
    }

    @Test
    void bindingFlagIsIndependentOfPreviousSessionId() {
        SMB2SessionSetup request = new SMB2SessionSetup(SMB2Dialect.SMB_3_1_1,
                EnumSet.of(SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED), EnumSet.noneOf(SMB2GlobalCapability.class));
        request.setPreviousSessionId(7);
        SMBBuffer previous = new SMBBuffer();request.write(previous);
        assertEquals(0,previous.array()[66]);
        request.setPreviousSessionId(0);request.setBinding(true);
        SMBBuffer binding = new SMBBuffer();request.write(binding);
        assertEquals(1,binding.array()[66]);
        assertEquals(0,ByteBuffer.wrap(binding.array()).order(ByteOrder.LITTLE_ENDIAN).getLong(80));
    }
}
