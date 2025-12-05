package com.packetanalyzer;

record FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
    FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public String toString() {
        String proto = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?";
        return BinaryUtil.formatIp(srcIp) + ":" + srcPort + " -> "
                + BinaryUtil.formatIp(dstIp) + ":" + dstPort + " (" + proto + ")";
    }
}