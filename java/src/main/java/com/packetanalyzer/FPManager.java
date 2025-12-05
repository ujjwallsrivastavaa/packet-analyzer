package com.packetanalyzer;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class FPManager {
    private final List<FastPathProcessor> fps = new ArrayList<>();

    FPManager(int numFps, int queueSize, BlockingRules rules, PacketOutputCallback outputCallback) {
        for (int index = 0; index < numFps; index++) {
            fps.add(new FastPathProcessor(index, queueSize, rules, outputCallback));
        }
        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    void startAll() {
        for (FastPathProcessor fp : fps) {
            fp.start();
        }
    }

    void stopAll() {
        for (FastPathProcessor fp : fps) {
            fp.stop();
        }
    }

    FastPathProcessor getFP(int id) {
        return fps.get(id);
    }

    ThreadSafeQueue<PacketJob> getFPQueue(int id) {
        return fps.get(id).getInputQueue();
    }

    List<ThreadSafeQueue<PacketJob>> getQueuePtrs() {
        List<ThreadSafeQueue<PacketJob>> queues = new ArrayList<>(fps.size());
        for (FastPathProcessor fp : fps) {
            queues.add(fp.getInputQueue());
        }
        return queues;
    }

    int getNumFPs() {
        return fps.size();
    }

    boolean allQueuesEmpty() {
        for (FastPathProcessor fp : fps) {
            if (!fp.getInputQueue().empty()) {
                return false;
            }
        }
        return true;
    }

    long getTotalActiveProcessing() {
        long total = 0;
        for (FastPathProcessor fp : fps) {
            total += fp.getActiveProcessingCount();
        }
        return total;
    }

    AggregatedStats getAggregatedStats() {
        long totalProcessed = 0;
        long totalForwarded = 0;
        long totalDropped = 0;
        long totalConnections = 0;

        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats stats = fp.getStats();
            totalProcessed += stats.packetsProcessed();
            totalForwarded += stats.packetsForwarded();
            totalDropped += stats.packetsDropped();
            totalConnections += stats.connectionsTracked();
        }

        return new AggregatedStats(totalProcessed, totalForwarded, totalDropped, totalConnections);
    }

    String generateClassificationReport() {
        Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
        Map<String, Long> domainCounts = new HashMap<>();
        long totalClassified = 0;
        long totalUnknown = 0;

        for (FastPathProcessor fp : fps) {
            fp.getConnectionTracker().forEach(connection -> {
                appCounts.merge(connection.appType, 1L, Long::sum);
                if (connection.appType == AppType.UNKNOWN) {
                    synchronized (this) {
                        // no-op; counters handled below through aggregate loop
                    }
                }
                if (connection.sni != null && !connection.sni.isBlank()) {
                    domainCounts.merge(connection.sni, 1L, Long::sum);
                }
            });

            for (Connection connection : fp.getConnectionTracker().getAllConnections()) {
                if (connection.appType == AppType.UNKNOWN) {
                    totalUnknown++;
                } else {
                    totalClassified++;
                }
            }
        }

        StringBuilder builder = new StringBuilder();
        builder.append('\n').append("╔══════════════════════════════════════════════════════════════╗\n");
        builder.append("║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        builder.append("╠══════════════════════════════════════════════════════════════╣\n");

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0.0;
        double unknownPct = total > 0 ? (100.0 * totalUnknown / total) : 0.0;

        builder.append(String.format("║ Total Connections:    %10d                           ║%n", total));
        builder.append(String.format("║ Classified:           %10d (%.1f%%)                  ║%n", totalClassified, classifiedPct));
        builder.append(String.format("║ Unidentified:         %10d (%.1f%%)                  ║%n", totalUnknown, unknownPct));
        builder.append("╠══════════════════════════════════════════════════════════════╣\n");
        builder.append("║                    APPLICATION DISTRIBUTION                   ║\n");
        builder.append("╠══════════════════════════════════════════════════════════════╣\n");

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort(Map.Entry.comparingByValue(Comparator.reverseOrder()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0.0;
            int barLen = (int) (pct / 5.0);
            builder.append(String.format("║ %-15s %8d %5.1f%% %-20s   ║%n",
                    entry.getKey().displayName(), entry.getValue(), pct, "#".repeat(Math.max(0, barLen))));
        }

        builder.append("╚══════════════════════════════════════════════════════════════╝\n");
        return builder.toString();
    }

    record AggregatedStats(long totalProcessed,
                           long totalForwarded,
                           long totalDropped,
                           long totalConnections) {
    }
}