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

import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.SMBEventBus;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import javax.crypto.spec.SecretKeySpec;
import java.lang.management.ManagementFactory;
import java.net.URLClassLoader;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ChannelSelectionTest {
    // Behavioral regression: go-smb2 7f69f658, TestSessionChannelsSelectionAllocations.
    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void selectionNeedsNoAllocation(int count) throws Exception {
        assumeTrue(ManagementFactory.getThreadMXBean() instanceof com.sun.management.ThreadMXBean);
        assumeTrue(((com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean()).isThreadAllocatedMemorySupported());
        // Other tests mock Session and Connection. Their inline instrumentation allocates even on real
        // instances, so load the production classes independently for this allocation measurement.
        Class<?>[] dependencies = {ChannelSelectionTest.class, Session.class, org.slf4j.Logger.class,
                net.engio.mbassy.bus.MBassador.class, org.bouncycastle.crypto.macs.CMac.class,
                com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier.class};
        java.net.URL[] classpath = new java.net.URL[dependencies.length];
        for (int i = 0; i < dependencies.length; i++) classpath[i] = dependencies[i].getProtectionDomain().getCodeSource().getLocation();
        try (URLClassLoader isolated = new URLClassLoader(classpath, ClassLoader.getPlatformClassLoader())) {
            Class<?> probe = Class.forName(AllocationProbe.class.getName(), true, isolated);
            assertEquals(0L, probe.getMethod("measure", int.class).invoke(null, count));
        }
    }

    public static class AllocationProbe {
        public static long measure(int count) throws Exception {
            com.sun.management.ThreadMXBean bean = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
            bean.setThreadAllocatedMemoryEnabled(true);
            SmbConfig config = SmbConfig.createDefaultConfig();
            Connection primary = new ConnectedConnection(config);
            Connection secondary = new ConnectedConnection(config);
            try {
                Session session = new Session(primary, config, null, null, null, null, null);
                if (count == 2) session.addChannel(secondary, new SecretKeySpec(new byte[16], "AesCmac"));
                for (int i = 0; i < 100000; i++) session.selectChannel();
                long thread = Thread.currentThread().getId();
                long before = bean.getThreadAllocatedBytes(thread);
                Connection selected = null;
                for (int i = 0; i < 10000; i++) selected = session.selectChannel();
                long allocated = bean.getThreadAllocatedBytes(thread) - before;
                if (selected != (count == 2 ? secondary : primary)) throw new AssertionError("Unexpected selected channel");
                return allocated;
            } finally {
                primary.close(true);
                secondary.close(true);
            }
        }
    }

    private static class ConnectedConnection extends Connection {
        ConnectedConnection(SmbConfig config) { super(config, null, new SMBEventBus(), null); }
        @Override public boolean isConnected() { return true; }
    }
}
