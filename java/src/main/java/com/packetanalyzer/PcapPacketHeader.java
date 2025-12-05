package com.packetanalyzer;

record PcapPacketHeader(long tsSec, long tsUsec, long inclLen, long origLen) {
}