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
package com.hierynomus.mssmb2.messages.negotiate;

import com.hierynomus.mssmb2.SMB3SigningAlgorithm;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** [MS-SMB2] 2.2.3.1.7 / 2.2.4.1.7 SMB2_SIGNING_CAPABILITIES. */
public class SMB2SigningCapabilities extends SMB2NegotiateContext {
    private final List<SMB3SigningAlgorithm> algorithms = new ArrayList<>();

    public SMB2SigningCapabilities() {
        super(SMB2NegotiateContextType.SMB2_SIGNING_CAPABILITIES);
    }

    public SMB2SigningCapabilities(List<SMB3SigningAlgorithm> algorithms) {
        this();
        this.algorithms.addAll(algorithms);
    }

    @Override
    protected int writeContext(SMBBuffer buffer) {
        if (algorithms.isEmpty()) throw new IllegalStateException("Signing algorithms cannot be empty");
        buffer.putUInt16(algorithms.size());
        for (SMB3SigningAlgorithm algorithm : algorithms) buffer.putUInt16((int) algorithm.getValue());
        return 2 + 2 * algorithms.size();
    }

    @Override
    protected void readContext(SMBBuffer buffer, int dataSize) throws Buffer.BufferException {
        int count = buffer.readUInt16();
        if (count == 0 || dataSize != 2 + 2 * count) throw new IllegalArgumentException("Invalid signing capabilities length");
        for (int i = 0; i < count; i++) {
            SMB3SigningAlgorithm algorithm = EnumWithValue.EnumUtils.valueOf(buffer.readUInt16(), SMB3SigningAlgorithm.class, null);
            if (algorithm == null) throw new IllegalArgumentException("Unknown signing algorithm");
            algorithms.add(algorithm);
        }
    }

    public List<SMB3SigningAlgorithm> getAlgorithms() { return Collections.unmodifiableList(algorithms); }
}
