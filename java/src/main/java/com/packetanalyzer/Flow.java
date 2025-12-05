package com.packetanalyzer;

final class Flow {
    final FiveTuple tuple;
    AppType appType = AppType.UNKNOWN;
    String sni = "";
    long packets;
    long bytes;
    boolean blocked;

    Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }
}