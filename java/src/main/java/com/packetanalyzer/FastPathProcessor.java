package com.packetanalyzer;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

final class FastPathProcessor {
    private static final Duration POLL_TIMEOUT = Duration.ofMillis(100);
    private static final Duration STALE_TIMEOUT = Duration.ofSeconds(300);

    private final int fpId;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final ConnectionTracker connectionTracker;
    private final BlockingRules rules;
    private final PacketOutputCallback outputCallback;

    private final AtomicLong packetsProcessed = new AtomicLong();
    private final AtomicLong packetsForwarded = new AtomicLong();
    private final AtomicLong packetsDropped = new AtomicLong();
    private final AtomicLong sniExtractions = new AtomicLong();
    private final AtomicLong classificationHits = new AtomicLong();
    private final AtomicLong activeProcessing = new AtomicLong();
    private final AtomicBoolean running = new AtomicBoolean(false);

    private Thread thread;

    FastPathProcessor(int fpId, int queueSize, BlockingRules rules, PacketOutputCallback outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new ThreadSafeQueue<>(queueSize);
        this.connectionTracker = new ConnectionTracker(fpId, 100000);
        this.rules = rules;
        this.outputCallback = outputCallback;
    }

    void start() {
        if (running.getAndSet(true)) {
            return;
        }

        thread = new Thread(this::run, "FP-" + fpId);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    void stop() {
        if (!running.getAndSet(false)) {
            return;
        }

        inputQueue.shutdown();
        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    ConnectionTracker getConnectionTracker() {
        return connectionTracker;
    }

    long getActiveProcessingCount() {
        return activeProcessing.get();
    }

    boolean isRunning() {
        return running.get();
    }

    FPStats getStats() {
        return new FPStats(
                packetsProcessed.get(),
                packetsForwarded.get(),
                packetsDropped.get(),
                connectionTracker.getActiveCount(),
                sniExtractions.get(),
                classificationHits.get());
    }

    private void run() {
        while (running.get() || !inputQueue.empty()) {
                PacketJob job = inputQueue.popWithTimeout(POLL_TIMEOUT).orElse(null);
            if (job == null) {
                connectionTracker.cleanupStale(STALE_TIMEOUT);
                continue;
            }

            activeProcessing.incrementAndGet();
            try {
                packetsProcessed.incrementAndGet();

                PacketAction action = processPacket(job);
                if (action == PacketAction.DROP) {
                    packetsDropped.incrementAndGet();
                } else {
                    packetsForwarded.incrementAndGet();
                }

                if (outputCallback != null) {
                    outputCallback.handle(job, action);
                }
            } finally {
                activeProcessing.decrementAndGet();
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection connection = connectionTracker.getOrCreateConnection(job.tuple);
        if (connection == null) {
            return PacketAction.FORWARD;
        }

        connectionTracker.updateConnection(connection, job.data.length, true);

        if (job.tuple.protocol() == 6) {
            updateTCPState(connection, job.tcpFlags);
        }

        if (connection.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        if (connection.state != ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, connection);
        }

        return checkRules(job, connection);
    }

    private void inspectPayload(PacketJob job, Connection connection) {
        if (job.payloadLength <= 0 || job.payloadOffset >= job.data.length) {
            return;
        }

        if (tryExtractSni(job, connection)) {
            return;
        }

        if (tryExtractHttpHost(job, connection)) {
            return;
        }

        if (job.tuple.dstPort() == 53 || job.tuple.srcPort() == 53) {
            String domain = DnsExtractor.extractQuery(job.data, job.payloadOffset, job.payloadLength);
            if (domain != null) {
                connectionTracker.classifyConnection(connection, AppType.DNS, domain);
                return;
            }
        }

        if (job.tuple.dstPort() == 80) {
            connectionTracker.classifyConnection(connection, AppType.HTTP, "");
        } else if (job.tuple.dstPort() == 443) {
            connectionTracker.classifyConnection(connection, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSni(PacketJob job, Connection connection) {
        if (job.tuple.dstPort() != 443 && job.payloadLength < 50) {
            return false;
        }

        String sni = SniExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (sni == null) {
            return false;
        }

        sniExtractions.incrementAndGet();
        AppType app = AppType.fromSni(sni);
        connectionTracker.classifyConnection(connection, app, sni);
        if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
            classificationHits.incrementAndGet();
        }
        return true;
    }

    private boolean tryExtractHttpHost(PacketJob job, Connection connection) {
        if (job.tuple.dstPort() != 80) {
            return false;
        }

        String host = HttpHostExtractor.extract(job.data, job.payloadOffset, job.payloadLength);
        if (host == null) {
            return false;
        }

        AppType app = AppType.fromSni(host);
        connectionTracker.classifyConnection(connection, app, host);
        if (app != AppType.UNKNOWN && app != AppType.HTTP) {
            classificationHits.incrementAndGet();
        }
        return true;
    }

    private PacketAction checkRules(PacketJob job, Connection connection) {
        if (rules == null) {
            return PacketAction.FORWARD;
        }

        boolean blocked = rules.isBlocked(job.tuple.srcIp(), connection.appType, connection.sni);
        if (blocked) {
            System.out.println("[FP" + fpId + "] BLOCKED packet: " + job.tuple);
            connectionTracker.blockConnection(connection);
            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection connection, int tcpFlags) {
        final int syn = 0x02;
        final int ack = 0x10;
        final int fin = 0x01;
        final int rst = 0x04;

        if ((tcpFlags & syn) != 0) {
            if ((tcpFlags & ack) != 0) {
                connection.synAckSeen = true;
            } else {
                connection.synSeen = true;
            }
        }

        if (connection.synSeen && connection.synAckSeen && (tcpFlags & ack) != 0 && connection.state == ConnectionState.NEW) {
            connection.state = ConnectionState.ESTABLISHED;
        }

        if ((tcpFlags & fin) != 0) {
            connection.finSeen = true;
        }

        if ((tcpFlags & rst) != 0) {
            connection.state = ConnectionState.CLOSED;
        }

        if (connection.finSeen && (tcpFlags & ack) != 0) {
            connection.state = ConnectionState.CLOSED;
        }
    }

    record FPStats(long packetsProcessed,
                   long packetsForwarded,
                   long packetsDropped,
                   long connectionsTracked,
                   long sniExtractions,
                   long classificationHits) {
    }
}