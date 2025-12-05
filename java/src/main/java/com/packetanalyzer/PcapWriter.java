package com.packetanalyzer;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

final class PcapWriter implements Closeable {
    private OutputStream outputStream;
    private boolean littleEndianFile = true;

    void open(Path path) throws IOException {
        close();
        outputStream = new BufferedOutputStream(Files.newOutputStream(path));
    }

    void writeGlobalHeader(PcapGlobalHeader header, boolean littleEndianFile) throws IOException {
        this.littleEndianFile = littleEndianFile;

        byte[] buffer = new byte[24];
        writeUInt32(buffer, 0, header.magicNumber());
        writeUInt16(buffer, 4, header.versionMajor());
        writeUInt16(buffer, 6, header.versionMinor());
        writeUInt32(buffer, 8, header.thiszone());
        writeUInt32(buffer, 12, header.sigfigs());
        writeUInt32(buffer, 16, header.snaplen());
        writeUInt32(buffer, 20, header.network());
        outputStream.write(buffer);
    }

    void writePacket(RawPacket packet) throws IOException {
        byte[] header = new byte[16];
        PcapPacketHeader packetHeader = packet.header();
        writeUInt32(header, 0, packetHeader.tsSec());
        writeUInt32(header, 4, packetHeader.tsUsec());
        writeUInt32(header, 8, packetHeader.inclLen());
        writeUInt32(header, 12, packetHeader.origLen());
        outputStream.write(header);
        outputStream.write(packet.data());
    }

    void writePacket(PacketJob job) throws IOException {
        byte[] header = new byte[16];
        writeUInt32(header, 0, job.tsSec);
        writeUInt32(header, 4, job.tsUsec);
        writeUInt32(header, 8, job.data.length);
        writeUInt32(header, 12, job.data.length);
        outputStream.write(header);
        outputStream.write(job.data);
    }

    @Override
    public void close() throws IOException {
        if (outputStream != null) {
            outputStream.flush();
            outputStream.close();
            outputStream = null;
        }
    }

    private void writeUInt16(byte[] buffer, int offset, long value) {
        if (littleEndianFile) {
            BinaryUtil.writeUInt16LE(buffer, offset, (int) value);
        } else {
            BinaryUtil.writeUInt16BE(buffer, offset, (int) value);
        }
    }

    private void writeUInt32(byte[] buffer, int offset, long value) {
        if (littleEndianFile) {
            BinaryUtil.writeUInt32LE(buffer, offset, value);
        } else {
            BinaryUtil.writeUInt32BE(buffer, offset, value);
        }
    }
}