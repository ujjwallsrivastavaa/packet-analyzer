package com.packetanalyzer;

record RawPacket(PcapPacketHeader header, byte[] data) {
}