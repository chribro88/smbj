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
package com.hierynomus.smbj;

import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.ConnectionClosed;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.server.ServerList;
import net.engio.mbassy.listener.Handler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.hierynomus.protocol.commons.IOUtils.closeSilently;

/**
 * Server Message Block Client API.
 */
public class SMBClient implements Closeable {
    /**
     * The default TCP port for SMB
     */
    public static final int DEFAULT_PORT = 445;

    private Map<String, Connection> connectionTable = new ConcurrentHashMap<>();
    private ServerList serverList = new ServerList();
    private final java.util.Set<Connection> channelConnections = java.util.Collections.newSetFromMap(new ConcurrentHashMap<Connection, Boolean>());
    private final Object connectionLock = new Object();
    private boolean closed;

    private SmbConfig config;

    private SMBEventBus bus;

    public SMBClient() {
        this(SmbConfig.createDefaultConfig());
    }

    public SMBClient(SmbConfig config) {
        this(config, new SMBEventBus());
    }

    public SMBClient(SmbConfig config, SMBEventBus bus) {
        this.config = config;
        this.bus = bus;
        bus.subscribe(this);
    }

    /**
     * Connect to the host at <pre>hostname</pre> on the default port (445)
     *
     * @param hostname The hostname to connect to.
     * @return An established connection.
     * @throws IOException If the connection could not be established.
     */
    public Connection connect(String hostname) throws IOException {
        return getEstablishedOrConnect(hostname, DEFAULT_PORT);
    }

    /**
     * Connect to the host at <pre>hostname</pre> on the given port
     *
     * @param hostname The hostname to connect to.
     * @param port     The port to connect to
     * @return An established connection.
     * @throws IOException If the connection could not be established.
     */
    public Connection connect(String hostname, int port) throws IOException {
        return getEstablishedOrConnect(hostname, port);
    }

    // CUSTOM ADDED: pooled connect() cannot create a second TCP channel to the same endpoint.
    public Connection openChannel(com.hierynomus.smbj.session.Session session, String hostname, int port) throws IOException {
        java.util.Objects.requireNonNull(session, "session");
        Connection channel = new Connection(config, this, bus, serverList, session);
        boolean registered = false;
        try {
            synchronized (this) {
                if (closed) {
                    throw new IOException("SMB client is closed");
                }
                registered = session.beginBinding(channel);
                channelConnections.add(channel);
            }
            channel.connect(session.getConnection().getRemoteHostname(), new java.net.InetSocketAddress(hostname, port));
            channel.bind(session, true);
            return channel;
        } catch (IOException | RuntimeException e) {
            try {
                channel.close(true);
            } catch (Exception closeFailure) {
                e.addSuppressed(closeFailure);
            }
            throw e;
        } finally {
            if (registered) {
                session.endBinding(channel);
            }
            if (!channel.isConnected()) {
                channelConnections.remove(channel);
            }
        }
    }

    public synchronized void registerBootstrapConnection(Connection bootstrap) throws IOException {
        if (closed) throw new IOException("SMB client is closed");
        if (bootstrap.getClient() != this) throw new IOException("Connection belongs to another SMB client");
        channelConnections.add(bootstrap);
    }

    public void releaseBootstrapConnection(Connection bootstrap) {
        channelConnections.remove(bootstrap);
    }

    public synchronized void publishBootstrapChannel(com.hierynomus.smbj.session.Session session,
            Connection bootstrap, Connection caller) throws IOException {
        if (closed) throw new IOException("SMB client is closed");
        if (bootstrap.getClient() != this || caller.getClient() != this) {
            throw new IOException("Bootstrap channel belongs to another SMB client");
        }
        session.adoptBootstrapChannel(bootstrap, caller);
    }

    private Connection getEstablishedOrConnect(String hostname, int port) throws IOException {
        synchronized (this) {
            if (closed) {
                throw new IOException("SMB client is closed");
            }
        }
        synchronized (connectionLock) {
            synchronized (this) {
                if (closed) {
                    throw new IOException("SMB client is closed");
                }
            }
            String hostPort = hostname + ":" + port;
            Connection cachedConnection = connectionTable.get(hostPort);
            if (cachedConnection != null) {
                if (cachedConnection.isConnected()) {
                    Connection leased = cachedConnection.lease();
                    if (leased != null) {
                        return leased;
                    }
                }
                connectionTable.remove(hostPort, cachedConnection);
                closeQuietly(cachedConnection);
                cachedConnection = null;
            }
            if (cachedConnection == null || !cachedConnection.isConnected()) {
                Connection connection = new Connection(config, this, bus, serverList);
                try {
                    synchronized (this) {
                        if (closed) {
                            throw new IOException("SMB client is closed");
                        }
                        channelConnections.add(connection);
                    }
                    connection.connect(hostname, port);
                    synchronized (this) {
                        if (closed || connection.isClosed()) {
                            throw new IOException("SMB client closed before connection publication");
                        }
                        connectionTable.put(hostPort, connection);
                    }
                } catch (IOException | RuntimeException e) {
                    closeSilently(connection); // Quietly close broken connection.
                    throw e;
                } finally {
                    channelConnections.remove(connection);
                }
                return connection;
            }

            synchronized (this) {
                if (closed) {
                    throw new IOException("SMB client is closed");
                }
            }
            return cachedConnection;
        }
    }

    private void closeQuietly(Connection connection) {
        try {
            connection.close(true);
        } catch (Exception e) {
            logger.debug("Error closing connection to host {}", connection.getRemoteHostname());
            logger.debug("Exception was: ", e);
        }
    }

    @Handler
    @SuppressWarnings("unused")
    private void connectionClosed(ConnectionClosed event) {
        synchronized (this) {
            String hostPort = event.getHostname() + ":" + event.getPort();
            Connection connection = event.getConnection();
            if (connection != null) {
                channelConnections.remove(connection);
            }
            Connection cached = connectionTable.get(hostPort);
            if (connection == null && cached != null && cached.isConnected()) {
                return;
            }
            boolean removed = connection == null ? connectionTable.remove(hostPort) != null
                : connectionTable.remove(hostPort, connection);
            if (removed) {
                serverList.unregister(event.getHostname());
                logger.debug("Connection to << {} >> closed", hostPort);
            }
        }
    }

    private static final Logger logger = LoggerFactory.getLogger(SMBClient.class);

    @Override
    public void close() {
        synchronized (this) {
            closed = true;
        }
        logger.info("Going to close all remaining connections");
        for (Connection channel : channelConnections) {
            try {
                channel.close(true);
            } catch (IOException e) {
                logger.debug("Could not close bound channel", e);
            }
        }
        channelConnections.clear();
        for (Connection connection : connectionTable.values()) {
            try {
                connection.close(true);
            } catch (Exception e) {
                logger.debug("Error closing connection to host {}", connection.getRemoteHostname());
                logger.debug("Exception was: ", e);
            }
        }
    }

    public ServerList getServerList() {
        return serverList;
    }
}
