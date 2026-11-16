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
import com.hierynomus.mssmb2.SMB2GlobalCapability;
import com.hierynomus.mssmb2.messages.SMB2SessionSetup.SMB2SecurityMode;
import com.hierynomus.smb.SMBBuffer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.EnumSet;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SessionSetupCapabilitiesTest {
    // go-smb2 7f69f658, sessionSetupBinding: SESSION_SETUP carries DFS, not NEGOTIATE-only capabilities.
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void onlyDfsIsAdvertisedInSessionSetup(boolean dfs) {
        EnumSet<SMB2GlobalCapability> capabilities = EnumSet.allOf(SMB2GlobalCapability.class);
        if (!dfs) capabilities.remove(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DFS);
        SMB2SessionSetup request = new SMB2SessionSetup(SMB2Dialect.SMB_3_1_1,
                EnumSet.of(SMB2SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED), capabilities);
        request.setBinding(true);
        SMBBuffer buffer = new SMBBuffer();
        request.write(buffer);
        assertEquals(dfs ? 1 : 0, ByteBuffer.wrap(buffer.getCompactData()).order(ByteOrder.LITTLE_ENDIAN).getInt(68));
    }
}
