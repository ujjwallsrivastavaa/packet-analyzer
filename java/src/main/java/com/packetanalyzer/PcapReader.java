package com.packetanalyzer;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

final class PcapReader implements Closeable {
    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;
    private static final long MAGIC_NATIVE = 0xA1B2C3D4L;
    private static final long MAGIC_SWAPPED = 0xD4C3B2A1L;

    private InputStream inputStream;
    private PcapGlobalHeader globalHeader;
    private boolean littleEndianFile;

    boolean open(Path path) throws IOException {
        close();

        inputStream = new BufferedInputStream(Files.newInputStream(path));
        byte[] headerBytes = readExact(GLOBAL_HEADER_SIZE);
        long magicLe = BinaryUtil.readUInt32LE(headerBytes, 0);

        if (magicLe == MAGIC_NATIVE) {
            littleEndianFile = true;
        } else if (magicLe == MAGIC_SWAPPED) {
            littleEndianFile = false;
        } else {
            throw new IOException(String.format("Invalid PCAP magic number: 0x%08X", magicLe));
        }

        globalHeader = new PcapGlobalHeader(
                littleEndianFile ? BinaryUtil.readUInt32LE(headerBytes, 0) : BinaryUtil.readUInt32BE(headerBytes, 0),
                readUInt16(headerBytes, 4),
                readUInt16(headerBytes, 6),
                readUInt32(headerBytes, 8),
                readUInt32(headerBytes, 12),
                readUInt32(headerBytes, 16),
                readUInt32(headerBytes, 20));

        System.out.println("Opened PCAP file: " + path);
        System.out.println("  Version: " + globalHeader.versionMajor() + "." + globalHeader.versionMinor());
        System.out.println("  Snaplen: " + globalHeader.snaplen() + " bytes");
        System.out.println("  Link type: " + globalHeader.network() + (globalHeader.network() == 1 ? " (Ethernet)" : ""));

        return true;
    }

    PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    boolean isLittleEndianFile() {
        return littleEndianFile;
    }

    RawPacket readNextPacket() throws IOException {
        if (inputStream == null) {
            return null;
        }

        byte[] headerBytes;
        try {
            headerBytes = readExact(PACKET_HEADER_SIZE);
        } catch (IOException ex) {
            if (ex.getMessage() != null && ex.getMessage().contains("EOF")) {
                return null;
            }
            throw ex;
        }

        long tsSec = readUInt32(headerBytes, 0);
        long tsUsec = readUInt32(headerBytes, 4);
        long inclLen = readUInt32(headerBytes, 8);
        long origLen = readUInt32(headerBytes, 12);

        if (inclLen > globalHeader.snaplen() || inclLen > 65535L) {
            throw new IOException("Invalid packet length: " + inclLen);
        }

        if (inclLen > Integer.MAX_VALUE) {
            throw new IOException("Packet too large: " + inclLen);
        }

        byte[] data = readExact((int) inclLen);
        return new RawPacket(new PcapPacketHeader(tsSec, tsUsec, inclLen, origLen), data);
    }

    @Override
    public void close() throws IOException {
        if (inputStream != null) {
            inputStream.close();
            inputStream = null;
        }
        globalHeader = null;
        littleEndianFile = true;
    }

    private long readUInt32(byte[] data, int offset) {
        return littleEndianFile ? BinaryUtil.readUInt32LE(data, offset) : BinaryUtil.readUInt32BE(data, offset);
    }

    private int readUInt16(byte[] data, int offset) {
        return littleEndianFile ? BinaryUtil.readUInt16LE(data, offset) : BinaryUtil.readUInt16BE(data, offset);
    }

    private byte[] readExact(int length) throws IOException {
        byte[] buffer = new byte[length];
        int read = 0;

        while (read < length) {
            int count = inputStream.read(buffer, read, length - read);
            if (count < 0) {
                throw new IOException("EOF");
            }
            read += count;
        }

        return buffer;
    }
}