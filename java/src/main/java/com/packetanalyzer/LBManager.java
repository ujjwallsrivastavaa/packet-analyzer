package com.packetanalyzer;

import java.util.ArrayList;
import java.util.List;

final class LBManager {
    private final List<LoadBalancer> lbs = new ArrayList<>();

    LBManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<PacketJob>> fpQueues, int queueSize) {
        for (int lbId = 0; lbId < numLbs; lbId++) {
            List<ThreadSafeQueue<PacketJob>> lbFpQueues = new ArrayList<>(fpsPerLb);
            int fpStart = lbId * fpsPerLb;
            for (int index = 0; index < fpsPerLb; index++) {
                lbFpQueues.add(fpQueues.get(fpStart + index));
            }
            lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart, queueSize));
        }

        System.out.println("[LBManager] Created " + numLbs + " load balancers, " + fpsPerLb + " FPs each");
    }

    void startAll() {
        for (LoadBalancer lb : lbs) {
            lb.start();
        }
    }

    void stopAll() {
        for (LoadBalancer lb : lbs) {
            lb.stop();
        }
    }

    LoadBalancer getLBForPacket(FiveTuple tuple) {
        int hash = tuple.hashCode() & Integer.MAX_VALUE;
        return lbs.get(hash % lbs.size());
    }

    boolean allInputQueuesEmpty() {
        for (LoadBalancer lb : lbs) {
            if (!lb.isInputQueueEmpty()) {
                return false;
            }
        }
        return true;
    }

    AggregatedStats getAggregatedStats() {
        long totalReceived = 0;
        long totalDispatched = 0;
        for (LoadBalancer lb : lbs) {
            LoadBalancer.LBStats stats = lb.getStats();
            totalReceived += stats.packetsReceived();
            totalDispatched += stats.packetsDispatched();
        }
        return new AggregatedStats(totalReceived, totalDispatched);
    }

    record AggregatedStats(long totalReceived, long totalDispatched) {
    }
}