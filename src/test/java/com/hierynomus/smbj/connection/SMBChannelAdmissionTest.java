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
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.session.SessionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SMBChannelAdmissionTest {
    @ParameterizedTest
    @CsvSource({"1048576,1048576,1048576,true", "1048576,65536,1048576,false", "1048576,65535,1048576,false",
            "65536,65536,1048576,true", "65536,0,1048576,false", "1048576,32768,32768,true", "1048576,32767,32768,false"})
    void checksActualWriteLimitInsteadOfPrimaryAdvertisement(int primaryLimit, int secondaryLimit, int configuredLimit, boolean admitted) {
        Connection primary = mock(Connection.class);
        Connection secondary = mock(Connection.class);
        ConnectionContext original = context(primaryLimit);
        ConnectionContext additional = context(secondaryLimit);
        when(primary.getConnectionContext()).thenReturn(original);
        when(secondary.getConnectionContext()).thenReturn(additional);
        when(secondary.getSessionTable()).thenReturn(new SessionTable());
        Session session = mock(Session.class);
        when(session.getConnection()).thenReturn(primary);
        SessionContext keys = new SessionContext();
        keys.setSigningKey(new SecretKeySpec(new byte[16], "AES"));
        when(session.getSessionContext()).thenReturn(keys);
        // Stop after admission: authentication and wire binding are covered by BoundChannelsIT.
        SmbConfig config = SmbConfig.builder().withWriteBufferSize(configuredLimit).withAuthenticators(Collections.emptyList()).build();
        SMBSessionBuilder builder = new SMBSessionBuilder(secondary, config, null);
        if (admitted) {
            SMBRuntimeException failure = assertThrows(SMBRuntimeException.class, () -> builder.bind(session, null));
            assertTrue(failure.getMessage().startsWith("Could not find a configured authenticator"));
        } else {
            IOException failure = assertThrows(IOException.class, () -> builder.bind(session, null));
            assertTrue(failure.getMessage().contains("write"));
        }
    }

    private ConnectionContext context(int maxWrite) {
        ConnectionContext context = mock(ConnectionContext.class);
        when(context.getNegotiatedProtocol()).thenReturn(new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1,
                1048576, 1048576, maxWrite, true));
        when(context.getServerGuid()).thenReturn(new UUID(0, 1));
        when(context.getClientGuid()).thenReturn(new UUID(0, 2));
        when(context.getServerCapabilities()).thenReturn(EnumSet.of(SMB2GlobalCapability.SMB2_GLOBAL_CAP_MULTI_CHANNEL));
        when(context.getGssNegotiateToken()).thenReturn(new byte[0]);
        return context;
    }
}
