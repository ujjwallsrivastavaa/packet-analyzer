package com.packetanalyzer;

final class DnsExtractor {
    private DnsExtractor() {
    }

    static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (length < 12) {
            return false;
        }

        if ((payload[offset + 2] & 0x80) != 0) {
            return false;
        }

        int qdCount = BinaryUtil.readUInt16BE(payload, offset + 4);
        return qdCount > 0;
    }

    static String extractQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length)) {
            return null;
        }

        int cursor = offset + 12;
        StringBuilder builder = new StringBuilder();

        while (cursor < offset + length) {
            int labelLength = payload[cursor] & 0xFF;
            if (labelLength == 0) {
                break;
            }
            if (labelLength > 63) {
                break;
            }

            cursor++;
            if (cursor + labelLength > offset + length) {
                break;
            }

            if (builder.length() > 0) {
                builder.append('.');
            }

            builder.append(new String(payload, cursor, labelLength, java.nio.charset.StandardCharsets.US_ASCII));
            cursor += labelLength;
        }

        return builder.length() == 0 ? null : builder.toString();
    }
}