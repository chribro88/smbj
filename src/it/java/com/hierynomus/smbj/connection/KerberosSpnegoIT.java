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

import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticateResponse;
import com.hierynomus.smbj.auth.GSSAuthenticationContext;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;
import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/** Real KDC and JDK GSS exchange; the fixture supplies private keytabs and JVM Kerberos configuration. */
@EnabledIfEnvironmentVariable(named = "SMBJ_KRB5_TEST_DIR", matches = ".+")
@Timeout(30)
class KerberosSpnegoIT {
    private static final String REALM = "SMBJ.TEST";
    private static final String HOST = "server.smbj.test";
    private static final SmbConfig CONFIG = SmbConfig.builder().build();

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void freshContextsExportMatchingDistinctKeysAndSelectCifsSpn(boolean explicitCredentials) throws Exception {
        LoginContext client = login("client@" + REALM, "client.keytab", true);
        try {
            LoginContext server = login("cifs/" + HOST + "@" + REALM, "server.keytab", false);
            try {
                GSSCredential credential = explicitCredentials ? Subject.doAs(client.getSubject(),
                        (PrivilegedExceptionAction<GSSCredential>) () -> GSSManager.getInstance().createCredential(
                                null, GSSCredential.DEFAULT_LIFETIME, new Oid("1.3.6.1.5.5.2"), GSSCredential.INITIATE_ONLY)) : null;
                try {
                    GSSAuthenticationContext auth = new GSSAuthenticationContext("client", REALM, client.getSubject(), credential);
                    byte[] first = exchange(auth, server.getSubject());
                    byte[] second = exchange(auth, server.getSubject());
                    assertFalse(MessageDigest.isEqual(first, second), "Fresh GSS contexts must not retain the previous exported key");
                } finally {
                    if (credential != null) credential.dispose();
                }
            } finally {
                server.logout();
            }
        } finally {
            client.logout();
        }
    }

    @Test
    void unknownCifsPrincipalFailsWithoutExportingAKey() throws Exception {
        LoginContext client = login("client@" + REALM, "client.keytab", true);
        SpnegoAuthenticator authenticator = new SpnegoAuthenticator();
        authenticator.init(CONFIG);
        try {
            GSSAuthenticationContext auth = new GSSAuthenticationContext("client", REALM, client.getSubject(), null);
            IOException failure = assertThrows(IOException.class,
                    () -> authenticator.authenticate(auth, new byte[0], context("missing.smbj.test")));
            boolean unknownPrincipal = false;
            for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                unknownPrincipal |= cause.getMessage() != null
                        && cause.getMessage().contains("Server not found in Kerberos database");
            }
            assertTrue(unknownPrincipal, "Failure must identify the missing service principal rather than a transport/login error");
        } finally {
            try {
                dispose(authenticator);
            } finally {
                client.logout();
            }
        }
    }

    private byte[] exchange(GSSAuthenticationContext auth, Subject server) throws Exception {
        SpnegoAuthenticator authenticator = new SpnegoAuthenticator.Factory().create();
        authenticator.init(CONFIG);
        GSSContext acceptor = Subject.doAs(server,
                (PrivilegedExceptionAction<GSSContext>) () -> GSSManager.getInstance().createContext((GSSCredential) null));
        try {
            AuthenticateResponse initial = authenticator.authenticate(auth, new byte[0], context(HOST));
            assertNull(initial.getSessionKey(), "Mutual authentication must finish before key export");
            SMBBuffer token = new SMBBuffer();
            initial.getNegToken().write(token);
            byte[] request = token.getCompactData();
            assertTrue(request.length > 0);
            byte[] peer = Subject.doAs(server,
                    (PrivilegedExceptionAction<byte[]>) () -> acceptor.acceptSecContext(request, 0, request.length));
            assertTrue(acceptor.isEstablished());
            assertTrue(acceptor.getMutualAuthState());
            assertFalse(acceptor.getCredDelegState());
            assertEquals("client@" + REALM, acceptor.getSrcName().toString());
            assertEquals("cifs/" + HOST + "@" + REALM, acceptor.getTargName().toString());
            assertNotNull(peer);
            assertTrue(peer.length > 0);
            AuthenticateResponse complete = authenticator.authenticate(auth, peer, context(HOST));
            Key exported = Subject.doAs(server, (PrivilegedExceptionAction<Key>) () ->
                    (Key) ((ExtendedGSSContext) acceptor).inquireSecContext(InquireType.KRB5_GET_SESSION_KEY));
            assertNotNull(exported);
            int expectedLength = Integer.parseInt(System.getenv("SMBJ_KRB5_KEY_BYTES"));
            assertEquals(expectedLength, exported.getEncoded().length);
            assertNotNull(complete.getSessionKey());
            assertEquals(16, complete.getSessionKey().length);
            assertTrue(MessageDigest.isEqual(Arrays.copyOf(exported.getEncoded(), 16), complete.getSessionKey()),
                    "SMBJ must export this GSS context's key, normalized to sixteen bytes");
            SMBBuffer finalToken = new SMBBuffer();
            complete.getNegToken().write(finalToken);
            assertEquals(0, finalToken.wpos(), "The final mutual-authentication token needs no extra client leg");
            return complete.getSessionKey();
        } finally {
            try {
                acceptor.dispose();
            } finally {
                dispose(authenticator);
            }
        }
    }

    private ConnectionContext context(String hostname) {
        return new ConnectionContext(new UUID(0, 1), hostname, 445, CONFIG);
    }

    private static LoginContext login(String principal, String keytab, boolean initiator) throws Exception {
        Path directory = Paths.get(System.getenv("SMBJ_KRB5_TEST_DIR"));
        Map<String, String> options = new HashMap<>();
        options.put("principal", principal);
        options.put("useKeyTab", "true");
        options.put("keyTab", directory.resolve(keytab).toString());
        options.put("storeKey", "true");
        options.put("doNotPrompt", "true");
        options.put("useTicketCache", "false");
        options.put("isInitiator", Boolean.toString(initiator));
        LoginContext login = new LoginContext("smbj-test", null, null, new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[]{new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)};
            }
        });
        login.login();
        return login;
    }

    private static void dispose(SpnegoAuthenticator authenticator) throws Exception {
        // Authenticator has no close API; release the real GSS context after each fixture exchange.
        Field field = SpnegoAuthenticator.class.getDeclaredField("gssContext");
        field.setAccessible(true);
        GSSContext context = (GSSContext) field.get(authenticator);
        if (context != null) context.dispose();
    }
}
