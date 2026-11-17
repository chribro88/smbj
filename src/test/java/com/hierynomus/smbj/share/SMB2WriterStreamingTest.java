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
package com.hierynomus.smbj.share;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2WriteResponse;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.io.ByteChunkProvider;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

class SMB2WriterStreamingTest {
    private final SMB2FileId id = new SMB2FileId(new byte[8], new byte[8]);

    private static SMB2WriteResponse acknowledgement(final int count) {
        return new SMB2WriteResponse() {
            @Override
            public int getBytesWritten() {
                return count;
            }
        };
    }

    @Test
    void positiveShortWriteReplaysOnlyTheUnacknowledgedSuffix() {
        Share share = mock(Share.class);
        when(share.getWriteBufferSize()).thenReturn(65536);
        List<Long> offsets = new ArrayList<>();
        List<byte[]> payloads = new ArrayList<>();
        when(share.write(any(), any())).thenAnswer(call -> {
            ByteChunkProvider provider = call.getArgument(1);
            offsets.add(provider.getOffset());
            SMBBuffer wire = new SMBBuffer();
            provider.writeBytes(wire, provider.bytesLeft());
            payloads.add(wire.getCompactData());
            return acknowledgement(payloads.size() == 1 ? 2 : 1);
        });
        assertEquals(3, new SMB2Writer(share, id, "test").write(new byte[]{1, 2, 3}, 7));
        assertEquals(Arrays.asList(7L, 9L), offsets);
        assertArrayEquals(new byte[]{1, 2, 3}, payloads.get(0));
        assertArrayEquals(new byte[]{3}, payloads.get(1));
    }

    @Test
    void zeroAcknowledgementFailsRatherThanSilentlyDroppingData() {
        Share share = mock(Share.class);
        when(share.getWriteBufferSize()).thenReturn(65536);
        when(share.write(any(), any())).thenReturn(acknowledgement(0));
        assertThrows(SMBRuntimeException.class, () -> new SMB2Writer(share, id, "test").write(new byte[]{1}, 0));
    }

    @Test
    void oversizedAcknowledgementFailsRatherThanClaimingUnsentBytes() {
        Share share = mock(Share.class);
        when(share.getWriteBufferSize()).thenReturn(65536);
        when(share.write(any(), any())).thenReturn(acknowledgement(2));
        assertThrows(SMBRuntimeException.class, () -> new SMB2Writer(share, id, "test").write(new byte[]{1}, 0));
    }

    @Test
    void moreThanTwoGiBUsesLongTotalsWithOnlyRequestSizedBuffers() {
        // stubOnly prevents Mockito retaining one payload per request during this streaming size check.
        Share share = mock(Share.class, withSettings().stubOnly());
        when(share.getWriteBufferSize()).thenReturn(65536);
        when(share.write(any(), any())).thenAnswer(call -> {
            ByteChunkProvider provider = call.getArgument(1);
            int count = Math.min(65536, provider.bytesLeft());
            provider.writeBytes(new SMBBuffer(), count);
            return acknowledgement(count);
        });
        final long length = (1L << 31) + 65537;
        ByteChunkProvider generated = new ByteChunkProvider() {
            private long remaining = length;
            @Override public void prepareWrite(int size) { }
            @Override public boolean isAvailable() { return remaining > 0; }
            @Override public int bytesLeft() { return (int) Math.min(Integer.MAX_VALUE, remaining); }
            @Override protected int getChunk(byte[] bytes) {
                int count = (int) Math.min(bytes.length, remaining);
                remaining -= count;
                return count;
            }
        };
        assertEquals(length, new SMB2Writer(share, id, "generated").write(generated));
        assertEquals(length, generated.getOffset());
    }
}
