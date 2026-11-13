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
package com.hierynomus.smbj.testing;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import org.junit.jupiter.params.provider.Arguments;
import java.util.Arrays;
import java.util.stream.Stream;

public final class MultichannelTestSupport {
    private MultichannelTestSupport() { }

    public static Stream<Arguments> configurations() {
        String ports = System.getenv().getOrDefault("SMB_TEST_PORTS", System.getenv("SMB_TEST_PORT"));
        if (ports == null) return Stream.of(Arguments.of(null, false, false));
        boolean required = Boolean.parseBoolean(System.getenv("SMB_TEST_ENCRYPTION_REQUIRED"));
        return Arrays.stream(ports.split(",")).flatMap(port -> Stream.of(false, true)
                .filter(encryption -> !required || encryption)
                .flatMap(encryption -> Stream.of(false, true).map(writeThrough -> Arguments.of(port.trim(), encryption, writeThrough))));
    }

    public static Stream<Arguments> rejectedBindingConfigurations() {
        String ports = System.getenv("SMB_TEST_REJECT_BINDING_PORTS");
        if (ports == null) return Stream.of(Arguments.of(null, true, false));
        return Arrays.stream(ports.split(",")).flatMap(port -> Stream.of(false, true)
                .map(writeThrough -> Arguments.of(port.trim(), true, writeThrough)));
    }

    public static String hostname() {
        return System.getenv().getOrDefault("SMB_TEST_HOST", "localhost");
    }

    public static String shareName() {
        return System.getenv().getOrDefault("SMB_TEST_SHARE", "share");
    }

    public static AuthenticationContext authentication() {
        return new AuthenticationContext(System.getenv().getOrDefault("SMB_TEST_USERNAME", "username"),
                System.getenv().getOrDefault("SMB_TEST_PASSWORD", "password").toCharArray(),
                System.getenv().getOrDefault("SMB_TEST_DOMAIN", "domain"));
    }

    public static SMB2Dialect dialect() {
        return SMB2Dialect.valueOf(System.getenv().getOrDefault("SMB_TEST_DIALECT", "SMB_3_1_1"));
    }

    public static SmbConfig config(boolean encryption) {
        return SmbConfig.builder().withDialects(dialect())
                .withSigningAlgorithms(com.hierynomus.mssmb2.SMB3SigningAlgorithm.valueOf(
                        System.getenv().getOrDefault("SMB_TEST_SIGNING_ALGORITHM", "AES_CMAC")))
                .withSigningRequired(true).withEncryptData(encryption)
                .withTimeout(5, java.util.concurrent.TimeUnit.SECONDS).build();
    }
}
