package com.packetanalyzer;

final class Connection {
    final FiveTuple tuple;
    volatile ConnectionState state = ConnectionState.NEW;
    volatile AppType appType = AppType.UNKNOWN;
    volatile String sni = "";

    long packetsIn;
    long packetsOut;
    long bytesIn;
    long bytesOut;

    final long firstSeenMillis = System.currentTimeMillis();
    volatile long lastSeenMillis = firstSeenMillis;

    volatile PacketAction action = PacketAction.FORWARD;
    volatile boolean synSeen;
    volatile boolean synAckSeen;
    volatile boolean finSeen;

    Connection(FiveTuple tuple) {
        this.tuple = tuple;
    }
}