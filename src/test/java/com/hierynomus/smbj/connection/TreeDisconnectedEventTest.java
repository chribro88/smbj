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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2ShareCapabilities;
import com.hierynomus.mssmb2.SMB2ShareFlags;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.event.TreeDisconnected;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.TreeConnect;
import org.junit.jupiter.api.Test;

import java.lang.ref.WeakReference;
import java.util.EnumSet;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class TreeDisconnectedEventTest {
    @Test
    void scopedEventMatchesOnlyItsSessionAndTreeGenerationEvenWhenTreesCompareEqual() {
        Session session = session(47), other = session(47);
        TreeConnect owner = tree(session, 7), replacement = tree(session, 7), foreign = tree(other, 7);
        assertEquals(owner, replacement); assertEquals(owner, foreign);
        TreeDisconnected event = new TreeDisconnected(owner);
        assertTrue(event.matchesSession(session)); assertFalse(event.matchesSession(other));
        assertTrue(event.matchesTree(owner)); assertFalse(event.matchesTree(replacement));
        assertFalse(event.matchesTree(foreign)); assertFalse(event.matchesTree(tree(session, 8)));
        assertFalse(event.matchesSession(null)); assertFalse(event.matchesTree(null));
    }

    @Test
    void legacyConstructorRetainsNumericMatchingAndValueEquality() {
        Session session = session(47); TreeConnect owner = tree(session, 7);
        TreeDisconnected legacy = new TreeDisconnected(47, 7), scoped = new TreeDisconnected(owner);
        assertEquals(legacy, scoped); assertEquals(scoped, legacy);
        assertEquals(legacy.hashCode(), scoped.hashCode());
        assertTrue(legacy.matchesTree(owner)); assertTrue(legacy.matchesTree(tree(session(47), 7)));
        assertFalse(legacy.matchesTree(tree(session(48), 7)));
        assertFalse(legacy.matchesTree(tree(session, 8))); assertFalse(legacy.matchesTree(null));
    }

    @Test
    void retainedEventDoesNotRetainItsTreeOrSessionOrMatchAReplacement() throws Exception {
        AtomicReference<WeakReference<TreeConnect>> treeProbe = new AtomicReference<>();
        AtomicReference<WeakReference<Session>> sessionProbe = new AtomicReference<>();
        TreeDisconnected event = ephemeralEvent(treeProbe, sessionProbe);
        for (int attempt = 0; attempt < 3 && (treeProbe.get().get() != null || sessionProbe.get().get() != null); attempt++) {
            System.gc(); Thread.sleep(10);
        }
        assertNull(treeProbe.get().get()); assertNull(sessionProbe.get().get());
        assertFalse(event.matchesTree(tree(session(47), 7)));
        assertFalse(event.matchesSession(session(47)), "An expired scoped event must not become a numeric broadcast");
        assertEquals(new TreeDisconnected(47, 7), event);
    }

    private static TreeDisconnected ephemeralEvent(AtomicReference<WeakReference<TreeConnect>> treeProbe,
            AtomicReference<WeakReference<Session>> sessionProbe) {
        Session session = session(47); TreeConnect tree = tree(session, 7);
        treeProbe.set(new WeakReference<>(tree)); sessionProbe.set(new WeakReference<>(session));
        return new TreeDisconnected(tree);
    }

    private static Session session(long id) {
        Session session = new Session(null, null, null, null, null, null, null);
        session.setSessionId(id); return session;
    }

    private static TreeConnect tree(Session session, long id) {
        SmbConfig config = SmbConfig.createDefaultConfig();
        ConnectionContext context = new ConnectionContext(new UUID(0, 1), "peer", 445, config);
        return new TreeConnect(id, new SmbPath("peer", "share"), session, EnumSet.noneOf(SMB2ShareCapabilities.class),
                config, context, null, EnumSet.noneOf(AccessMask.class), EnumSet.noneOf(SMB2ShareFlags.class)) {
            @Override public boolean equals(Object other) {
                return other instanceof TreeConnect && ((TreeConnect) other).getTreeId() == getTreeId()
                        && ((TreeConnect) other).getSession().getSessionId() == getSession().getSessionId();
            }
            @Override public int hashCode() { return (int) getTreeId(); }
        };
    }
}
