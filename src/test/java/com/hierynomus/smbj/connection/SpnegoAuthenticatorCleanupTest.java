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

import com.hierynomus.smbj.auth.SpnegoAuthenticator;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.io.IOException;
import java.lang.reflect.Field;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SpnegoAuthenticatorCleanupTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void disposesAndClearsTheContextOnceEvenWhenDisposalFails(boolean fail) throws Exception {
        GSSContext context = mock(GSSContext.class);
        if (fail) doThrow(new GSSException(GSSException.FAILURE)).when(context).dispose();
        SpnegoAuthenticator authenticator = new SpnegoAuthenticator();
        Field field = SpnegoAuthenticator.class.getDeclaredField("gssContext"); field.setAccessible(true); field.set(authenticator, context);
        if (fail) assertInstanceOf(GSSException.class, assertThrows(IOException.class, authenticator::close).getCause());
        else authenticator.close();
        assertNull(field.get(authenticator)); authenticator.close(); verify(context).dispose();
    }
}
