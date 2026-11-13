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

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2GlobalCapability;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.connection.NegotiatedProtocol;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionSetupChannelKeyTest {
    private static Connection connection() {
        Connection connection = mock(Connection.class);
        when(connection.isConnected()).thenReturn(true);
        when(connection.getNegotiatedProtocol()).thenReturn(
                new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
        return connection;
    }

    private static SMB2SessionSetup setup(long status) {
        SMB2SessionSetup packet = new SMB2SessionSetup(SMB2Dialect.SMB_3_1_1,
                EnumSet.of(SMB2SessionSetup.SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED),
                EnumSet.noneOf(SMB2GlobalCapability.class));
        packet.getHeader().setStatusCode(status);
        return packet;
    }

    @Test
    void bindingUsesOriginalKeyButBoundChannelReauthenticationUsesChannelKey() {
        Connection primary = connection();
        Connection candidate = connection();
        Connection bound = connection();
        SecretKey originalKey = new SecretKeySpec(new byte[16], "AES-GMAC");
        byte[] bytes = new byte[16];
        bytes[0] = 7;
        SecretKey boundKey = new SecretKeySpec(bytes, "AES-GMAC");
        Session session = new Session(primary, SmbConfig.createDefaultConfig(), null, null, null, null, null);
        session.getSessionContext().setSigningKey(originalKey);
        session.addChannel(bound, boundKey);

        for (long status : new long[]{NtStatus.STATUS_SUCCESS.getValue(),
                NtStatus.STATUS_MORE_PROCESSING_REQUIRED.getValue(), NtStatus.STATUS_ACCESS_DENIED.getValue()}) {
            SMB2SessionSetup packet = setup(status);
            for (boolean outgoing : new boolean[]{false, true}) {
                assertSame(originalKey, session.getSigningKey(packet.getHeader(), outgoing, primary));
                assertSame(originalKey, session.getSigningKey(packet.getHeader(), outgoing, candidate),
                        "Pending bind must not acquire a channel key before publication");
                assertSame(boundKey, session.getSigningKey(packet.getHeader(), outgoing, bound),
                        "Existing bound channel must use its channel signing key for reauthentication");
            }
        }
    }
}
