package com.packetanalyzer;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

final class ThreadedDpiEngine {
    private static final Duration OUTPUT_POLL_TIMEOUT = Duration.ofMillis(100);

    static final class Config {
        int numLoadBalancers = 2;
        int fpsPerLb = 2;
        int queueSize = 10000;
    }

    private final Config config;
    private final BlockingRules rules;
    private final ThreadSafeQueue<PacketJob> outputQueue;
    private final FPManager fpManager;
    private final LBManager lbManager;
    private final GlobalConnectionTable globalConnectionTable;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private final AtomicLong totalPackets = new AtomicLong();
    private final AtomicLong totalBytes = new AtomicLong();
    private final AtomicLong forwardedPackets = new AtomicLong();
    private final AtomicLong droppedPackets = new AtomicLong();
    private final AtomicLong tcpPackets = new AtomicLong();
    private final AtomicLong udpPackets = new AtomicLong();

    private Thread readerThread;
    private Thread outputThread;
    private PcapWriter outputWriter;

    ThreadedDpiEngine(Config config, BlockingRules rules) {
        this.config = config;
        this.rules = rules;
        this.outputQueue = new ThreadSafeQueue<>(config.queueSize);

        PacketOutputCallback outputCallback = (job, action) -> {
            if (action == PacketAction.DROP) {
                droppedPackets.incrementAndGet();
                return;
            }

            forwardedPackets.incrementAndGet();
            outputQueue.push(job);
        };

        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        this.fpManager = new FPManager(totalFps, config.queueSize, rules, outputCallback);
        this.lbManager = new LBManager(config.numLoadBalancers, config.fpsPerLb, fpManager.getQueuePtrs(), config.queueSize);
        this.globalConnectionTable = new GlobalConnectionTable(totalFps);

        for (int index = 0; index < totalFps; index++) {
            globalConnectionTable.registerTracker(index, fpManager.getFP(index).getConnectionTracker());
        }

        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v2.0 (Java)                    ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf(Locale.ROOT, "║ Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d     ║%n",
                config.numLoadBalancers, config.fpsPerLb, totalFps);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    boolean process(Path inputFile, Path outputFile) throws IOException {
        PcapReader reader = new PcapReader();
        outputWriter = new PcapWriter();

        if (!reader.open(inputFile)) {
            return false;
        }

        outputWriter.open(outputFile);
        outputWriter.writeGlobalHeader(reader.getGlobalHeader(), reader.isLittleEndianFile());

        running.set(true);
        startOutputThread();
        fpManager.startAll();
        lbManager.startAll();

        readerThread = new Thread(() -> readerLoop(reader), "Reader");
        readerThread.start();

        try {
            readerThread.join();
            waitForDrain();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } finally {
            running.set(false);
            lbManager.stopAll();
            fpManager.stopAll();
            outputQueue.shutdown();
            try {
                if (outputThread != null) {
                    outputThread.join();
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }

            try {
                outputWriter.close();
            } catch (IOException ex) {
                System.err.println("[Error] Failed to close output file: " + ex.getMessage());
            }

            try {
                reader.close();
            } catch (IOException ex) {
                System.err.println("[Error] Failed to close input file: " + ex.getMessage());
            }
        }

        printReports();
        return true;
    }

    private void startOutputThread() {
        outputThread = new Thread(() -> {
            while (running.get() || !outputQueue.empty()) {
                Optional<PacketJob> jobOpt = outputQueue.popWithTimeout(OUTPUT_POLL_TIMEOUT);
                if (jobOpt.isEmpty()) {
                    continue;
                }

                try {
                    outputWriter.writePacket(jobOpt.get());
                } catch (IOException ex) {
                    System.err.println("[Error] Failed to write packet: " + ex.getMessage());
                }
            }
        }, "OutputWriter");
        outputThread.start();
    }

    private void readerLoop(PcapReader reader) {
        ObjectPool<ParsedPacket> parsedPool = new ObjectPool<>(256, ParsedPacket::new);
        ParsedPacket parsed = parsedPool.acquire();
        long packetId = 0;

        try {
            System.out.println("[Reader] Starting packet processing...");
            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                totalPackets.incrementAndGet();
                totalBytes.addAndGet(raw.data().length);

                if (!PacketParser.parse(raw, parsed)) {
                    continue;
                }

                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }

                if (parsed.hasTcp) {
                    tcpPackets.incrementAndGet();
                } else if (parsed.hasUdp) {
                    udpPackets.incrementAndGet();
                }

                PacketJob job = createPacketJob(raw, parsed, packetId++);
                LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
                lb.getInputQueue().push(job);

                parsed.reset();
                parsed = parsedPool.acquire();
            }

            parsedPool.release(parsed);
            System.out.println("[Reader] Finished reading " + packetId + " packets");
        } catch (IOException ex) {
            System.err.println("[Reader] Error: " + ex.getMessage());
        }
    }

    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, long packetId) {
        FiveTuple tuple = new FiveTuple(parsed.srcIpRaw, parsed.destIpRaw, parsed.srcPort, parsed.destPort, parsed.protocol);
        int transportOffset = parsed.hasTcp || parsed.hasUdp ? parsed.payloadOffset : 0;
        int payloadOffset = parsed.payloadOffset;
        int payloadLength = parsed.payloadLength;

        return new PacketJob(
                packetId,
                tuple,
                raw.data(),
                0,
                14,
                transportOffset,
                payloadOffset,
                payloadLength,
                parsed.tcpFlags,
                raw.header().tsSec(),
                raw.header().tsUsec());
    }

    private void waitForDrain() {
        while (true) {
            boolean queuesEmpty = lbManager.allInputQueuesEmpty() && fpManager.allQueuesEmpty() && outputQueue.empty();
            boolean idle = fpManager.getTotalActiveProcessing() == 0;
            if (queuesEmpty && idle) {
                return;
            }

            try {
                Thread.sleep(50);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void printReports() {
        System.out.println();
        System.out.println("====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets: " + totalPackets.get());
        System.out.println("  Total bytes:   " + totalBytes.get());
        System.out.println("  Forwarded:     " + forwardedPackets.get());
        System.out.println("  Dropped:       " + droppedPackets.get());
        System.out.println("  TCP packets:   " + tcpPackets.get());
        System.out.println("  UDP packets:   " + udpPackets.get());
        System.out.println("====================================");
        System.out.print(globalConnectionTable.generateReport());
        System.out.print(fpManager.generateClassificationReport());
    }
}