package com.packetanalyzer;

record PcapGlobalHeader(long magicNumber,
                        int versionMajor,
                        int versionMinor,
                        long thiszone,
                        long sigfigs,
                        long snaplen,
                        long network) {
}