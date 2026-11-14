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
import com.hierynomus.mssmb2.SMB3EncryptionCipher;
import com.hierynomus.security.bc.BCSecurityProvider;
import org.junit.jupiter.api.Test;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class ChannelNonceTest {
    @Test
    void concurrentChannelsNeverRepeatANonceAndExhaustionFailsClosed() throws Exception {
        PacketEncryptor encryptor = new PacketEncryptor(new BCSecurityProvider());
        encryptor.setCipher(SMB3EncryptionCipher.AES_128_GCM);
        Set<String> nonces = ConcurrentHashMap.newKeySet();
        ExecutorService workers = Executors.newFixedThreadPool(4);
        try {
            List<Future<?>> results = new ArrayList<>();
            for (int c=0;c<4;c++) results.add(workers.submit(() -> {
                for(int i=0;i<2000;i++) assertTrue(nonces.add(Base64.getEncoder().encodeToString(encryptor.getNewNonce())));
            }));
            for(Future<?> result:results) result.get(10,TimeUnit.SECONDS);
            assertEquals(8000,nonces.size());
        } finally { workers.shutdownNow();assertTrue(workers.awaitTermination(5,TimeUnit.SECONDS)); }
        java.lang.reflect.Field field = PacketEncryptor.class.getDeclaredField("nonceCounter");
        field.setAccessible(true);((AtomicLong)field.get(encryptor)).set(Long.MAX_VALUE);
        encryptor.getNewNonce();
        assertThrows(IllegalStateException.class,encryptor::getNewNonce);
        assertThrows(IllegalStateException.class,encryptor::getNewNonce);
    }
}
