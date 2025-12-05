package com.packetanalyzer;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

final class BinaryUtil {
    private BinaryUtil() {
    }

    static int readUInt16LE(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    static int readUInt16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    static long readUInt32LE(byte[] data, int offset) {
        return (data[offset] & 0xFFL)
                | ((data[offset + 1] & 0xFFL) << 8)
                | ((data[offset + 2] & 0xFFL) << 16)
                | ((data[offset + 3] & 0xFFL) << 24);
    }

    static long readUInt32BE(byte[] data, int offset) {
        return ((data[offset] & 0xFFL) << 24)
                | ((data[offset + 1] & 0xFFL) << 16)
                | ((data[offset + 2] & 0xFFL) << 8)
                | (data[offset + 3] & 0xFFL);
    }

    static long readUInt24BE(byte[] data, int offset) {
        return ((data[offset] & 0xFFL) << 16)
                | ((data[offset + 1] & 0xFFL) << 8)
                | (data[offset + 2] & 0xFFL);
    }

    static void writeUInt16LE(byte[] buffer, int offset, int value) {
        buffer[offset] = (byte) (value & 0xFF);
        buffer[offset + 1] = (byte) ((value >>> 8) & 0xFF);
    }

    static void writeUInt16BE(byte[] buffer, int offset, int value) {
        buffer[offset] = (byte) ((value >>> 8) & 0xFF);
        buffer[offset + 1] = (byte) (value & 0xFF);
    }

    static void writeUInt32LE(byte[] buffer, int offset, long value) {
        buffer[offset] = (byte) (value & 0xFF);
        buffer[offset + 1] = (byte) ((value >>> 8) & 0xFF);
        buffer[offset + 2] = (byte) ((value >>> 16) & 0xFF);
        buffer[offset + 3] = (byte) ((value >>> 24) & 0xFF);
    }

    static void writeUInt32BE(byte[] buffer, int offset, long value) {
        buffer[offset] = (byte) ((value >>> 24) & 0xFF);
        buffer[offset + 1] = (byte) ((value >>> 16) & 0xFF);
        buffer[offset + 2] = (byte) ((value >>> 8) & 0xFF);
        buffer[offset + 3] = (byte) (value & 0xFF);
    }

    static String formatIp(long ip) {
        return ((ip >>> 24) & 0xFF) + "."
                + ((ip >>> 16) & 0xFF) + "."
                + ((ip >>> 8) & 0xFF) + "."
                + (ip & 0xFF);
    }

    static long parseIp(String ip) {
        long result = 0;
        int octet = 0;
        int shift = 24;
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c == '.') {
                result |= ((long) octet & 0xFFL) << shift;
                shift -= 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= ((long) octet & 0xFFL) << shift;
        return result & 0xFFFFFFFFL;
    }

    static String lowercaseAscii(String value) {
        return value.toLowerCase(Locale.ROOT);
    }

    static String ascii(byte[] data, int offset, int length) {
        return new String(data, offset, length, StandardCharsets.US_ASCII);
    }
}