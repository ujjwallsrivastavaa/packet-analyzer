package com.packetanalyzer;

final class PacketParser {
    private static final int ETHER_HEADER_LEN = 14;
    private static final int MIN_IPV4_HEADER_LEN = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN = 8;

    private PacketParser() {
    }

    static boolean parse(RawPacket raw, ParsedPacket parsed) {
        parsed.reset();
        parsed.timestampSec = raw.header().tsSec();
        parsed.timestampUsec = raw.header().tsUsec();

        byte[] data = raw.data();
        int length = data.length;
        int offset = 0;

        if (!parseEthernet(data, length, parsed)) {
            return false;
        }
        offset += ETHER_HEADER_LEN;

        if (parsed.etherType == 0x0800) {
            if (!parseIpv4(data, length, parsed, offset)) {
                return false;
            }
            offset = parsed.payloadOffset;

            if (parsed.protocol == 6) {
                if (!parseTcp(data, length, parsed, offset)) {
                    return false;
                }
                offset = parsed.payloadOffset;
            } else if (parsed.protocol == 17) {
                if (!parseUdp(data, length, parsed, offset)) {
                    return false;
                }
                offset = parsed.payloadOffset;
            }
        }

        if (offset < length) {
            parsed.payloadOffset = offset;
            parsed.payloadLength = length - offset;
        } else {
            parsed.payloadOffset = length;
            parsed.payloadLength = 0;
        }

        return true;
    }

    static String protocolToString(int protocol) {
        return switch (protocol) {
            case 1 -> "ICMP";
            case 6 -> "TCP";
            case 17 -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    static String tcpFlagsToString(int flags) {
        StringBuilder builder = new StringBuilder();
        if ((flags & 0x02) != 0) builder.append("SYN ");
        if ((flags & 0x10) != 0) builder.append("ACK ");
        if ((flags & 0x01) != 0) builder.append("FIN ");
        if ((flags & 0x04) != 0) builder.append("RST ");
        if ((flags & 0x08) != 0) builder.append("PSH ");
        if ((flags & 0x20) != 0) builder.append("URG ");
        if (builder.length() == 0) {
            return "none";
        }
        builder.setLength(builder.length() - 1);
        return builder.toString();
    }

    private static boolean parseEthernet(byte[] data, int length, ParsedPacket parsed) {
        if (length < ETHER_HEADER_LEN) {
            return false;
        }

        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        parsed.etherType = BinaryUtil.readUInt16BE(data, 12);
        return true;
    }

    private static boolean parseIpv4(byte[] data, int length, ParsedPacket parsed, int offset) {
        if (length < offset + MIN_IPV4_HEADER_LEN) {
            return false;
        }

        int versionIhl = data[offset] & 0xFF;
        parsed.ipVersion = (versionIhl >>> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;
        if (parsed.ipVersion != 4) {
            return false;
        }

        int headerLength = ihl * 4;
        if (headerLength < MIN_IPV4_HEADER_LEN || length < offset + headerLength) {
            return false;
        }

        parsed.ttl = data[offset + 8] & 0xFF;
        parsed.protocol = data[offset + 9] & 0xFF;
        parsed.srcIpRaw = BinaryUtil.readUInt32BE(data, offset + 12);
        parsed.destIpRaw = BinaryUtil.readUInt32BE(data, offset + 16);
        parsed.srcIp = BinaryUtil.formatIp(parsed.srcIpRaw);
        parsed.destIp = BinaryUtil.formatIp(parsed.destIpRaw);
        parsed.hasIp = true;
        parsed.payloadOffset = offset + headerLength;
        return true;
    }

    private static boolean parseTcp(byte[] data, int length, ParsedPacket parsed, int offset) {
        if (length < offset + MIN_TCP_HEADER_LEN) {
            return false;
        }

        parsed.srcPort = BinaryUtil.readUInt16BE(data, offset);
        parsed.destPort = BinaryUtil.readUInt16BE(data, offset + 2);
        parsed.seqNumber = BinaryUtil.readUInt32BE(data, offset + 4);
        parsed.ackNumber = BinaryUtil.readUInt32BE(data, offset + 8);
        int dataOffset = (data[offset + 12] >>> 4) & 0x0F;
        int headerLength = dataOffset * 4;
        parsed.tcpFlags = data[offset + 13] & 0xFF;

        if (headerLength < MIN_TCP_HEADER_LEN || length < offset + headerLength) {
            return false;
        }

        parsed.hasTcp = true;
        parsed.payloadOffset = offset + headerLength;
        return true;
    }

    private static boolean parseUdp(byte[] data, int length, ParsedPacket parsed, int offset) {
        if (length < offset + UDP_HEADER_LEN) {
            return false;
        }

        parsed.srcPort = BinaryUtil.readUInt16BE(data, offset);
        parsed.destPort = BinaryUtil.readUInt16BE(data, offset + 2);
        parsed.hasUdp = true;
        parsed.payloadOffset = offset + UDP_HEADER_LEN;
        return true;
    }

    private static String macToString(byte[] data, int offset) {
        StringBuilder builder = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                builder.append(':');
            }
            int value = data[offset + i] & 0xFF;
            if (value < 0x10) {
                builder.append('0');
            }
            builder.append(Integer.toHexString(value));
        }
        return builder.toString();
    }
}