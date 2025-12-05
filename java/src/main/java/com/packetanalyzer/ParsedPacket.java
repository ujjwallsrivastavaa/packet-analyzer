package com.packetanalyzer;

final class ParsedPacket {
    long timestampSec;
    long timestampUsec;

    String srcMac = "";
    String destMac = "";
    int etherType;

    boolean hasIp;
    int ipVersion;
    long srcIpRaw;
    long destIpRaw;
    String srcIp = "";
    String destIp = "";
    int protocol;
    int ttl;

    boolean hasTcp;
    boolean hasUdp;
    int srcPort;
    int destPort;

    int tcpFlags;
    long seqNumber;
    long ackNumber;

    int payloadOffset;
    int payloadLength;

    void reset() {
        timestampSec = 0;
        timestampUsec = 0;
        srcMac = "";
        destMac = "";
        etherType = 0;
        hasIp = false;
        ipVersion = 0;
        srcIpRaw = 0;
        destIpRaw = 0;
        srcIp = "";
        destIp = "";
        protocol = 0;
        ttl = 0;
        hasTcp = false;
        hasUdp = false;
        srcPort = 0;
        destPort = 0;
        tcpFlags = 0;
        seqNumber = 0;
        ackNumber = 0;
        payloadOffset = 0;
        payloadLength = 0;
    }
}