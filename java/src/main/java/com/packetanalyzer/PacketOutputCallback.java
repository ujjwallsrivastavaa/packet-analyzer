package com.packetanalyzer;

@FunctionalInterface
interface PacketOutputCallback {
    void handle(PacketJob job, PacketAction action);
}