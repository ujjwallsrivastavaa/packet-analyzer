package com.packetanalyzer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

final class ConnectionTracker {
    private final int fpId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections = new HashMap<>();

    private long totalSeen;
    private long classifiedCount;
    private long blockedCount;

    ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    Connection getOrCreateConnection(FiveTuple tuple) {
        Connection existing = getConnection(tuple);
        if (existing != null) {
            return existing;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        Connection connection = new Connection(tuple);
        connections.put(tuple, connection);
        totalSeen++;
        return connection;
    }

    Connection getConnection(FiveTuple tuple) {
        Connection connection = connections.get(tuple);
        if (connection != null) {
            return connection;
        }
        return connections.get(tuple.reverse());
    }

    void updateConnection(Connection connection, int packetSize, boolean outbound) {
        if (connection == null) {
            return;
        }

        connection.lastSeenMillis = System.currentTimeMillis();
        if (outbound) {
            connection.packetsOut++;
            connection.bytesOut += packetSize;
        } else {
            connection.packetsIn++;
            connection.bytesIn += packetSize;
        }
    }

    void classifyConnection(Connection connection, AppType app, String sni) {
        if (connection == null || connection.state == ConnectionState.CLASSIFIED) {
            return;
        }

        connection.appType = app;
        connection.sni = sni == null ? "" : sni;
        connection.state = ConnectionState.CLASSIFIED;
        classifiedCount++;
    }

    void blockConnection(Connection connection) {
        if (connection == null || connection.state == ConnectionState.BLOCKED) {
            return;
        }

        connection.state = ConnectionState.BLOCKED;
        connection.action = PacketAction.DROP;
        blockedCount++;
    }

    void closeConnection(FiveTuple tuple) {
        Connection connection = connections.get(tuple);
        if (connection != null) {
            connection.state = ConnectionState.CLOSED;
        }
    }

    int cleanupStale(Duration timeout) {
        long threshold = System.currentTimeMillis() - timeout.toMillis();
        int removed = 0;

        List<FiveTuple> stale = new ArrayList<>();
        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().state == ConnectionState.CLOSED || entry.getValue().lastSeenMillis < threshold) {
                stale.add(entry.getKey());
            }
        }

        for (FiveTuple tuple : stale) {
            connections.remove(tuple);
            removed++;
        }

        return removed;
    }

    List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    int getActiveCount() {
        return connections.size();
    }

    TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    void clear() {
        connections.clear();
    }

    void forEach(Consumer<Connection> callback) {
        for (Connection connection : connections.values()) {
            callback.accept(connection);
        }
    }

    private void evictOldest() {
        FiveTuple oldestKey = null;
        long oldestSeen = Long.MAX_VALUE;

        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().lastSeenMillis < oldestSeen) {
                oldestSeen = entry.getValue().lastSeenMillis;
                oldestKey = entry.getKey();
            }
        }

        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }

    record TrackerStats(int activeConnections,
                        long totalConnectionsSeen,
                        long classifiedConnections,
                        long blockedConnections) {
    }
}