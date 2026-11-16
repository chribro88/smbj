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
import com.hierynomus.mssmb2.SMB2PacketData;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.testing.PacketProcessor.NoOpPacketProcessor;
import com.hierynomus.smbj.testing.Utils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static com.hierynomus.smbj.connection.ResponseTestPackets.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MultichannelResponseValidationTest {
    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 1})
    void validatesEveryCompoundMemberUsingTheReceivingChannelsKey(int wrongKeyMember) throws Exception {
        SmbConfig config = Utils.config(new NoOpPacketProcessor());
        try (SMBClient client = new SMBClient(config)) {
            Connection receiving = client.connect("127.0.0.1");
            Connection primary = mock(Connection.class);
            when(primary.getNegotiatedProtocol()).thenReturn(
                new NegotiatedProtocol(SMB2Dialect.SMB_3_1_1, 65536, 65536, 65536, true));
            Session session = new Session(primary, config, null, null, null, null, null);
            session.setSessionId(SESSION_ID);
            session.getSessionContext().setSigningKey(KEY);
            session.getSessionContext().setSigningRequired(true);
            SecretKeySpec channelKey = new SecretKeySpec(new byte[16], "HmacSHA256");
            session.addChannel(receiving, channelKey);
            receiving.getSessionTable().registerSession(SESSION_ID, session);
            Request[] requests = new Request[2];
            for (int i = 0; i < requests.length; i++) {
                SMB2Echo echo = new SMB2Echo(SMB2Dialect.SMB_3_1_1);
                echo.getHeader().setSessionId(SESSION_ID);
                requests[i] = new Request(echo, i + 1, UUID.randomUUID(), true);
                receiving.outstandingRequests.registerOutstanding(requests[i]);
            }
            byte[] data = frame(response(1), response(2));
            for (int member = 0; member < 2; member++) {
                int start = member * MEMBER_SIZE;
                int signature = start + SMB2PacketHeader.SIGNATURE_OFFSET;
                Arrays.fill(data, signature, signature + SMB2PacketHeader.SIGNATURE_SIZE, (byte) 0);
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(member == wrongKeyMember ? KEY : channelKey);
                mac.update(data, start, MEMBER_SIZE);
                System.arraycopy(mac.doFinal(), 0, data, signature, SMB2PacketHeader.SIGNATURE_SIZE);
            }
            int credits = receiving.sequenceWindow.available();

            receiving.handle(new SMB2PacketData(data));

            for (Request request : requests) {
                if (wrongKeyMember < 0) {
                    assertEquals(request.getMessageId(), request.getPromise().future()
                        .get(1, TimeUnit.SECONDS).getHeader().getMessageId());
                } else {
                    assertFalse(request.getPromise().future().isDone());
                    assertSame(request, receiving.outstandingRequests.getRequestByMessageId(request.getMessageId()));
                }
            }
            assertEquals(credits + (wrongKeyMember < 0 ? 6 : 0), receiving.sequenceWindow.available());
        }
    }
}
