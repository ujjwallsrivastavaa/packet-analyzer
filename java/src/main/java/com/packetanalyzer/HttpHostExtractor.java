package com.packetanalyzer;

final class HttpHostExtractor {
    private HttpHostExtractor() {
    }

    static String extract(byte[] payload, int offset, int length) {
        if (!isHttpRequest(payload, offset, length)) {
            return null;
        }

        for (int index = offset; index + 5 < offset + length; index++) {
            if (matchesHostHeader(payload, index, offset + length)) {
                int cursor = index + 5;
                while (cursor < offset + length && (payload[cursor] == ' ' || payload[cursor] == '\t')) {
                    cursor++;
                }

                int end = cursor;
                while (end < offset + length && payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }

                if (end <= cursor) {
                    return null;
                }

                String host = new String(payload, cursor, end - cursor, java.nio.charset.StandardCharsets.US_ASCII).trim();
                int colon = host.indexOf(':');
                if (colon >= 0) {
                    host = host.substring(0, colon);
                }
                return host;
            }
        }

        return null;
    }

    static boolean isHttpRequest(byte[] payload, int offset, int length) {
        if (length < 4) {
            return false;
        }

        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
        for (String method : methods) {
            if (matchesAscii(payload, offset, length, method)) {
                return true;
            }
        }

        return false;
    }

    private static boolean matchesHostHeader(byte[] payload, int offset, int limit) {
        if (offset + 5 > limit) {
            return false;
        }

        return (payload[offset] == 'H' || payload[offset] == 'h')
                && (payload[offset + 1] == 'o' || payload[offset + 1] == 'O')
                && (payload[offset + 2] == 's' || payload[offset + 2] == 'S')
                && (payload[offset + 3] == 't' || payload[offset + 3] == 'T')
                && payload[offset + 4] == ':';
    }

    private static boolean matchesAscii(byte[] payload, int offset, int length, String value) {
        if (value.length() > length || offset + value.length() > payload.length) {
            return false;
        }

        for (int i = 0; i < value.length(); i++) {
            if ((byte) value.charAt(i) != payload[offset + i]) {
                return false;
            }
        }
        return true;
    }
}