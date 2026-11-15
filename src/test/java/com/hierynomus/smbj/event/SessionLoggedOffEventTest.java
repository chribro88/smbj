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
package com.hierynomus.smbj.event;

import com.hierynomus.smbj.session.Session;
import org.junit.jupiter.api.Test;

import java.lang.ref.WeakReference;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class SessionLoggedOffEventTest {
    @Test
    void scopedEventMatchesOnlyItsOriginatingSessionEvenWhenSessionsCompareEqual() {
        Session owner = valueSession(47), replacement = valueSession(47);
        assertEquals(owner, replacement);
        SessionLoggedOff event = new SessionLoggedOff(owner);
        assertTrue(event.matchesSession(owner));
        assertFalse(event.matchesSession(replacement));
        assertFalse(event.matchesSession(session(48)));
        assertFalse(event.matchesSession(null));
    }

    @Test
    void legacyConstructorRetainsNumericMatchingAndValueEquality() {
        Session owner = session(47);
        SessionLoggedOff legacy = new SessionLoggedOff(47), scoped = new SessionLoggedOff(owner);
        assertEquals(legacy, scoped); assertEquals(scoped, legacy);
        assertEquals(legacy.hashCode(), scoped.hashCode());
        assertTrue(legacy.matchesSession(owner));
        assertTrue(legacy.matchesSession(session(47)));
        assertFalse(legacy.matchesSession(session(48)));
        assertFalse(legacy.matchesSession(null));
    }

    @Test
    void retainedEventDoesNotRetainItsSessionOrMatchAReplacement() throws Exception {
        AtomicReference<WeakReference<Session>> probe = new AtomicReference<>();
        SessionLoggedOff event = ephemeralEvent(probe);
        for (int attempt = 0; attempt < 3 && probe.get().get() != null; attempt++) {
            System.gc(); Thread.sleep(10);
        }
        assertNull(probe.get().get(), "A stored notification must not retain session keys and credentials");
        assertFalse(event.matchesSession(session(47)), "An expired scoped event must not become a numeric broadcast");
        assertEquals(new SessionLoggedOff(47), event);
    }

    private static SessionLoggedOff ephemeralEvent(AtomicReference<WeakReference<Session>> probe) {
        Session owner = session(47);
        probe.set(new WeakReference<>(owner));
        return new SessionLoggedOff(owner);
    }

    private static Session session(long id) {
        Session session = new Session(null, null, null, null, null, null, null);
        session.setSessionId(id);
        return session;
    }

    private static Session valueSession(long id) {
        Session session = new Session(null, null, null, null, null, null, null) {
            @Override public boolean equals(Object other) {
                return other instanceof Session && ((Session) other).getSessionId() == getSessionId();
            }
            @Override public int hashCode() { return (int) getSessionId(); }
        };
        session.setSessionId(id);
        return session;
    }
}
