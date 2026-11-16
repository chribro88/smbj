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

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.smb.SMBBuffer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import static org.junit.jupiter.api.Assertions.*;

class ChannelSequenceTest {
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 0x7fff, 0x8000, 0xffff})
    void serializesTheUnsignedSequenceAtTheSmb3HeaderOffset(int sequence) {
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        packet.getHeader().setChannelSequence(sequence);
        SMBBuffer buffer = new SMBBuffer();
        packet.write(buffer);
        ByteBuffer wire = ByteBuffer.wrap(buffer.getCompactData()).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(sequence, Short.toUnsignedInt(wire.getShort(8)));
        assertEquals(0, wire.getShort(10));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0x10000})
    void refusesSequencesThatWouldBeTruncatedOnTheWire(int sequence) {
        SMB2Echo packet = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
        assertThrows(IllegalArgumentException.class, () -> packet.getHeader().setChannelSequence(sequence));
    }
}
