package com.packetanalyzer;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class GlobalConnectionTable {
    private final List<ConnectionTracker> trackers;

    GlobalConnectionTable(int numFps) {
        trackers = new ArrayList<>(numFps);
        for (int index = 0; index < numFps; index++) {
            trackers.add(null);
        }
    }

    synchronized void registerTracker(int fpId, ConnectionTracker tracker) {
        if (fpId >= 0 && fpId < trackers.size()) {
            trackers.set(fpId, tracker);
        }
    }

    synchronized GlobalStats getGlobalStats() {
        long activeConnections = 0;
        long totalConnectionsSeen = 0;
        Map<AppType, Long> appDistribution = new EnumMap<>(AppType.class);
        Map<String, Long> domainCounts = new HashMap<>();

        for (ConnectionTracker tracker : trackers) {
            if (tracker == null) {
                continue;
            }

            ConnectionTracker.TrackerStats stats = tracker.getStats();
            activeConnections += stats.activeConnections();
            totalConnectionsSeen += stats.totalConnectionsSeen();

            tracker.forEach(connection -> {
                appDistribution.merge(connection.appType, 1L, Long::sum);
                if (connection.sni != null && !connection.sni.isBlank()) {
                    domainCounts.merge(connection.sni, 1L, Long::sum);
                }
            });
        }

        List<Map.Entry<String, Long>> topDomains = new ArrayList<>(domainCounts.entrySet());
        topDomains.sort(Map.Entry.comparingByValue(Comparator.reverseOrder()));
        if (topDomains.size() > 20) {
            topDomains = topDomains.subList(0, 20);
        }

        return new GlobalStats(activeConnections, totalConnectionsSeen, appDistribution, topDomains);
    }

    synchronized String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder builder = new StringBuilder();
        builder.append('\n').append("╔══════════════════════════════════════════════════════════════╗\n");
        builder.append("║               CONNECTION STATISTICS REPORT                    ║\n");
        builder.append("╠══════════════════════════════════════════════════════════════╣\n");
        builder.append(String.format("║ Active Connections:     %10d                          ║%n", stats.totalActiveConnections()));
        builder.append(String.format("║ Total Connections Seen: %10d                          ║%n", stats.totalConnectionsSeen()));
        builder.append("╠══════════════════════════════════════════════════════════════╣\n");
        builder.append("║                    APPLICATION BREAKDOWN                      ║\n");
        builder.append("╠══════════════════════════════════════════════════════════════╣\n");

        long total = stats.appDistribution().values().stream().mapToLong(Long::longValue).sum();
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution().entrySet());
        sortedApps.sort(Map.Entry.comparingByValue(Comparator.reverseOrder()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0.0;
            builder.append(String.format("║ %-20s %10d (%.1f%%)           ║%n",
                    entry.getKey().displayName(), entry.getValue(), pct));
        }

        if (!stats.topDomains().isEmpty()) {
            builder.append("╠══════════════════════════════════════════════════════════════╣\n");
            builder.append("║                      TOP DOMAINS                             ║\n");
            builder.append("╠══════════════════════════════════════════════════════════════╣\n");
            for (Map.Entry<String, Long> entry : stats.topDomains()) {
                String domain = entry.getKey();
                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }
                builder.append(String.format("║ %-40s %10d           ║%n", domain, entry.getValue()));
            }
        }

        builder.append("╚══════════════════════════════════════════════════════════════╝\n");
        return builder.toString();
    }

    record GlobalStats(long totalActiveConnections,
                       long totalConnectionsSeen,
                       Map<AppType, Long> appDistribution,
                       List<Map.Entry<String, Long>> topDomains) {
    }
}