package com.packetanalyzer;

final class PacketJob {
    final long packetId;
    final FiveTuple tuple;
    final byte[] data;
    final int ethOffset;
    final int ipOffset;
    final int transportOffset;
    final int payloadOffset;
    final int payloadLength;
    final int tcpFlags;
    final long tsSec;
    final long tsUsec;

    PacketJob(long packetId,
              FiveTuple tuple,
              byte[] data,
              int ethOffset,
              int ipOffset,
              int transportOffset,
              int payloadOffset,
              int payloadLength,
              int tcpFlags,
              long tsSec,
              long tsUsec) {
        this.packetId = packetId;
        this.tuple = tuple;
        this.data = data;
        this.ethOffset = ethOffset;
        this.ipOffset = ipOffset;
        this.transportOffset = transportOffset;
        this.payloadOffset = payloadOffset;
        this.payloadLength = payloadLength;
        this.tcpFlags = tcpFlags;
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
    }
}