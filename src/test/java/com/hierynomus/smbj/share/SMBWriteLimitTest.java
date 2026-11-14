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

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.params.ParameterizedTest;
import org.mockito.ArgumentCaptor;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

class SMBWriteLimitTest {
    @ParameterizedTest
    @CsvSource({"1048576,1048576,1048576", "32768,1048576,32768", "1048576,32768,32768"})
    void boundsEveryWritePathToTheChannelAdmissionLimit(int configured, int negotiated, int expected) throws Exception {
        TreeConnect tree = mock(TreeConnect.class);
        Session session = mock(Session.class);
        when(tree.getSession()).thenReturn(session);
        when(tree.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1,
                1048576, 1048576, negotiated, true));
        when(tree.getConfig()).thenReturn(SmbConfig.builder().withWriteBufferSize(configured).build());
        Share share = new DiskShare(new SmbPath("server", "share"), tree, null);
        ArrayByteChunkProvider provider = new ArrayByteChunkProvider(new byte[1048576], 0);
        share.writeAsync(new SMB2FileId(new byte[8], new byte[8]), provider);
        ArgumentCaptor<SMB2WriteRequest> request = ArgumentCaptor.forClass(SMB2WriteRequest.class);
        verify(session).send(request.capture());
        // Even a generous credit grant must not enlarge writes beyond channel admission.
        request.getValue().setCreditsAssigned(16);
        SMBBuffer wire = new SMBBuffer();
        request.getValue().write(wire);
        assertEquals(expected, ByteBuffer.wrap(wire.getCompactData()).order(ByteOrder.LITTLE_ENDIAN).getInt(68));
        assertEquals(expected, provider.getOffset());
    }
}
