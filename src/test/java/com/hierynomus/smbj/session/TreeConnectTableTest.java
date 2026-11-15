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

import com.hierynomus.smbj.share.Share;
import com.hierynomus.smbj.share.TreeConnect;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TreeConnectTableTest {
    private final TreeConnectTable table = new TreeConnectTable();

    @Test
    void closesTheCurrentShareOnceFromBothIndexes() {
        Share share = share(7, "share"); table.register(share);
        table.closed(7, share); table.closed(7, share);
        assertNull(table.getTreeConnect(7)); assertNull(table.getTreeConnect("share"));
        assertTrue(table.getOpenTreeConnects().isEmpty());
    }

    @Test
    void oldCloseDoesNotRemoveAReplacementWithTheSameTreeId() {
        Share old = share(7, "share"), replacement = share(7, "share");
        table.register(old); table.register(replacement); table.closed(7, old);
        assertSame(replacement, table.getTreeConnect(7));
        assertSame(replacement, table.getTreeConnect("share"));
    }

    @Test
    void closingAnOlderTreePreservesTheNewerShareNameMapping() {
        Share old = share(7, "share"), replacement = share(8, "share");
        table.register(old); table.register(replacement);
        assertSame(old, table.getTreeConnect(7), "Both live trees remain tracked by ID");
        table.closed(7, old);
        assertNull(table.getTreeConnect(7));
        assertSame(replacement, table.getTreeConnect(8));
        assertSame(replacement, table.getTreeConnect("share"));
    }

    @Test
    void reusingATreeIdRemovesOnlyItsObsoleteNameAlias() {
        Share old = share(7, "old"), replacement = share(7, "new");
        table.register(old); table.register(replacement); table.closed(7, old);
        assertNull(table.getTreeConnect("old"));
        assertSame(replacement, table.getTreeConnect(7));
        assertSame(replacement, table.getTreeConnect("new"));
        table.closed(7, replacement);
        assertNull(table.getTreeConnect(7)); assertNull(table.getTreeConnect("new"));
    }

    private static Share share(long id, String name) {
        TreeConnect tree = mock(TreeConnect.class);
        when(tree.getTreeId()).thenReturn(id); when(tree.getShareName()).thenReturn(name);
        Share share = mock(Share.class); when(share.getTreeConnect()).thenReturn(tree);
        return share;
    }
}
