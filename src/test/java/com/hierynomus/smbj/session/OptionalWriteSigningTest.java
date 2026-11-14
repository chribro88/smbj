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
package com.hierynomus.smbj.session;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.mssmb2.messages.SMB2WriteRequest;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.ConnectionContext;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import com.hierynomus.smbj.connection.Signatory;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import javax.crypto.spec.SecretKeySpec;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OptionalWriteSigningTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void onlyOptionalWritesMayBeUnsignedAndControlsAlwaysSign(boolean required) throws Exception {
        Connection connection = mock(Connection.class);
        ConnectionContext context = mock(ConnectionContext.class);
        when(connection.getConnectionContext()).thenReturn(context);
        when(connection.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
        Signatory signatory = mock(Signatory.class);
        when(signatory.sign(any(), any())).thenAnswer(call -> call.getArgument(0));
        Session session = new Session(connection, SmbConfig.builder().withOptionalWriteSigning(false).build(), null, null, null, signatory, null);
        session.getSessionContext().setSigningKey(new SecretKeySpec(new byte[16], "AesCmac"));
        session.getSessionContext().setSigningRequired(required);
        session.send(new SMB2WriteRequest(SMB2Dialect.SMB_3_1_1, new SMB2FileId(new byte[8], new byte[8]), 1, 2,
                new ArrayByteChunkProvider(new byte[1], 0), 1));
        if (required) {
            verify(signatory).sign(any(), any());
        } else {
            verify(signatory, never()).sign(any(), any());
        }
        clearInvocations(signatory);
        session.send(new SMB2Echo(SMB2Dialect.SMB_3_1_1));
        verify(signatory).sign(any(), any());
    }
}
