package com.packetanalyzer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class PacketAnalyzerApp {
    private PacketAnalyzerApp() {
    }

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer (Java)");
        System.out.println("====================================");

        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        boolean threaded = false;
        int index = 0;
        if ("--threaded".equalsIgnoreCase(args[0]) || "--mt".equalsIgnoreCase(args[0])) {
            threaded = true;
            index = 1;
        }

        if (args.length - index < 2) {
            printUsage();
            System.exit(1);
        }

        Path inputFile = Path.of(args[index]);
        Path outputFile = Path.of(args[index + 1]);

        BlockingRules rules = new BlockingRules();
        for (int argIndex = index + 2; argIndex < args.length; argIndex++) {
            String arg = args[argIndex];
            if ("--block-ip".equals(arg) && argIndex + 1 < args.length) {
                rules.blockIp(args[++argIndex]);
            } else if ("--block-app".equals(arg) && argIndex + 1 < args.length) {
                rules.blockApp(args[++argIndex]);
            } else if ("--block-domain".equals(arg) && argIndex + 1 < args.length) {
                rules.blockDomain(args[++argIndex]);
            }
        }

        try {
            if (threaded) {
                ThreadedDpiEngine.Config config = new ThreadedDpiEngine.Config();
                ThreadedDpiEngine engine = new ThreadedDpiEngine(config, rules);
                engine.process(inputFile, outputFile);
            } else {
                run(inputFile, outputFile, rules);
            }
        } catch (IOException ex) {
            System.err.println("[Error] " + ex.getMessage());
            System.exit(1);
        }
    }

    private static void run(Path inputFile, Path outputFile, BlockingRules rules) throws IOException {
        Map<FiveTuple, Flow> flows = new LinkedHashMap<>();
        Map<AppType, Long> appStats = new EnumMap<>(AppType.class);
        List<String> detectedDomains = new ArrayList<>();

        long totalPackets = 0;
        long forwarded = 0;
        long dropped = 0;

        try (PcapReader reader = new PcapReader(); PcapWriter writer = new PcapWriter()) {
            if (!reader.open(inputFile)) {
                return;
            }

            writer.open(outputFile);
            writer.writeGlobalHeader(reader.getGlobalHeader(), reader.isLittleEndianFile());

            ObjectPool<ParsedPacket> parsedPool = new ObjectPool<>(128, ParsedPacket::new);
            ParsedPacket parsed = parsedPool.acquire();
            RawPacket raw;

            System.out.println("[DPI] Processing packets...");

            while ((raw = reader.readNextPacket()) != null) {
                totalPackets++;

                if (!PacketParser.parse(raw, parsed)) {
                    continue;
                }

                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }

                FiveTuple tuple = new FiveTuple(
                        parsed.srcIpRaw,
                        parsed.destIpRaw,
                        parsed.srcPort,
                        parsed.destPort,
                        parsed.protocol);

                Flow flow = flows.computeIfAbsent(tuple, Flow::new);
                flow.packets++;
                flow.bytes += raw.data().length;

                classifyFlow(raw, parsed, flow, detectedDomains);

                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(tuple.srcIp(), flow.appType, flow.sni);
                    if (flow.blocked) {
                        System.out.println("[BLOCKED] " + parsed.srcIp + " -> " + parsed.destIp
                                + " (" + flow.appType.displayName()
                                + (flow.sni.isEmpty() ? "" : ": " + flow.sni) + ")");
                    }
                }

                appStats.merge(flow.appType, 1L, Long::sum);

                if (flow.blocked) {
                    dropped++;
                } else {
                    forwarded++;
                    writer.writePacket(raw);
                }

                parsed.reset();
                parsed = parsedPool.acquire();
            }

            parsedPool.release(parsed);
            printReport(totalPackets, forwarded, dropped, flows, appStats, detectedDomains);
        }
    }

    private static void classifyFlow(RawPacket raw,
                                     ParsedPacket parsed,
                                     Flow flow,
                                     List<String> detectedDomains) {
        byte[] data = raw.data();

        if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS)
                && flow.sni.isEmpty()
                && parsed.hasTcp
                && parsed.destPort == 443) {
            String sni = SniExtractor.extract(data, parsed.payloadOffset, parsed.payloadLength);
            if (sni != null) {
                flow.sni = sni;
                flow.appType = AppType.fromSni(flow.sni);
                detectedDomains.add(flow.sni);
            }
        }

        if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP)
                && flow.sni.isEmpty()
                && parsed.hasTcp
                && parsed.destPort == 80) {
            String host = HttpHostExtractor.extract(data, parsed.payloadOffset, parsed.payloadLength);
            if (host != null) {
                flow.sni = host;
                flow.appType = AppType.fromSni(flow.sni);
                detectedDomains.add(flow.sni);
            }
        }

        if (flow.appType == AppType.UNKNOWN
                && (parsed.destPort == 53 || parsed.srcPort == 53)) {
            flow.appType = AppType.DNS;
            String query = DnsExtractor.extractQuery(data, parsed.payloadOffset, parsed.payloadLength);
            if (query != null) {
                flow.sni = query;
                detectedDomains.add(query);
            }
        }

        if (flow.appType == AppType.UNKNOWN) {
            if (parsed.destPort == 443) {
                flow.appType = AppType.HTTPS;
            } else if (parsed.destPort == 80) {
                flow.appType = AppType.HTTP;
            }
        }
    }

    private static void printReport(long totalPackets,
                                    long forwarded,
                                    long dropped,
                                    Map<FiveTuple, Flow> flows,
                                    Map<AppType, Long> appStats,
                                    List<String> detectedDomains) {
        System.out.println();
        System.out.println("====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets: " + totalPackets);
        System.out.println("  Forwarded:     " + forwarded);
        System.out.println("  Dropped:       " + dropped);
        System.out.println("  Active flows:  " + flows.size());
        System.out.println("====================================");
        System.out.println("Application breakdown:");

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appStats.entrySet());
        sortedApps.sort(Map.Entry.<AppType, Long>comparingByValue(Comparator.reverseOrder()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = totalPackets > 0 ? (100.0 * entry.getValue() / totalPackets) : 0.0;
            System.out.printf(Locale.ROOT, "  %-16s %8d  %5.1f%%%n",
                    entry.getKey().displayName(), entry.getValue(), pct);
        }

        if (!detectedDomains.isEmpty()) {
            System.out.println();
            System.out.println("[Detected Applications/Domains]");
            detectedDomains.stream().distinct().forEach(domain -> System.out.println("  - " + domain));
        }
    }

    private static void printUsage() {
        System.out.println("Usage: PacketAnalyzerApp [--threaded] <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>       Block traffic from source IP");
        System.out.println("  --block-app <app>     Block application (YouTube, Facebook, etc.)");
        System.out.println("  --block-domain <dom>  Block domain substring");
        System.out.println("  --threaded            Use the multithreaded DPI engine");
    }
}