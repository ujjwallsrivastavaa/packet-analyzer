package com.packetanalyzer;

final class SniExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SniExtractor() {
    }

    static String extract(byte[] payload, int offset, int length) {
        if (!isTlsClientHello(payload, offset, length)) {
            return null;
        }

        int cursor = offset + 5;
        cursor += 4;
        cursor += 2;
        cursor += 32;

        if (cursor >= offset + length) {
            return null;
        }

        int sessionIdLength = payload[cursor] & 0xFF;
        cursor += 1 + sessionIdLength;

        if (cursor + 2 > offset + length) {
            return null;
        }

        int cipherSuitesLength = BinaryUtil.readUInt16BE(payload, cursor);
        cursor += 2 + cipherSuitesLength;

        if (cursor >= offset + length) {
            return null;
        }

        int compressionMethodsLength = payload[cursor] & 0xFF;
        cursor += 1 + compressionMethodsLength;

        if (cursor + 2 > offset + length) {
            return null;
        }

        int extensionsLength = BinaryUtil.readUInt16BE(payload, cursor);
        cursor += 2;
        int extensionsEnd = Math.min(offset + length, cursor + extensionsLength);

        while (cursor + 4 <= extensionsEnd) {
            int extensionType = BinaryUtil.readUInt16BE(payload, cursor);
            int extensionLength = BinaryUtil.readUInt16BE(payload, cursor + 2);
            cursor += 4;

            if (cursor + extensionLength > extensionsEnd) {
                break;
            }

            if (extensionType == EXTENSION_SNI) {
                if (extensionLength < 5) {
                    break;
                }

                int sniListLength = BinaryUtil.readUInt16BE(payload, cursor);
                if (sniListLength < 3) {
                    break;
                }

                int sniType = payload[cursor + 2] & 0xFF;
                int sniLength = BinaryUtil.readUInt16BE(payload, cursor + 3);

                if (sniType != SNI_TYPE_HOSTNAME) {
                    break;
                }
                if (sniLength > extensionLength - 5 || cursor + 5 + sniLength > extensionsEnd) {
                    break;
                }

                return new String(payload, cursor + 5, sniLength, java.nio.charset.StandardCharsets.UTF_8);
            }

            cursor += extensionLength;
        }

        return null;
    }

    static boolean isTlsClientHello(byte[] payload, int offset, int length) {
        if (length < 9) {
            return false;
        }

        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) {
            return false;
        }

        int version = BinaryUtil.readUInt16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) {
            return false;
        }

        int recordLength = BinaryUtil.readUInt16BE(payload, offset + 3);
        if (recordLength > length - 5) {
            return false;
        }

        return (payload[offset + 5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }
}