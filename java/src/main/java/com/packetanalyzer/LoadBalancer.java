package com.packetanalyzer;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

final class LoadBalancer {
    private final int lbId;
    private final int fpStartId;
    private final int numFps;
    private final ThreadSafeQueue<PacketJob> inputQueue;
    private final List<ThreadSafeQueue<PacketJob>> fpQueues;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong packetsReceived = new AtomicLong();
    private final AtomicLong packetsDispatched = new AtomicLong();
    private final long[] perFpCounts;

    private Thread thread;

    LoadBalancer(int lbId, List<ThreadSafeQueue<PacketJob>> fpQueues, int fpStartId, int queueSize) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();
        this.inputQueue = new ThreadSafeQueue<>(queueSize);
        this.fpQueues = fpQueues;
        this.perFpCounts = new long[fpQueues.size()];
    }

    void start() {
        if (running.getAndSet(true)) {
            return;
        }

        thread = new Thread(this::run, "LB-" + lbId);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP" + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
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

        System.out.println("[LB" + lbId + "] Stopped");
    }

    ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    boolean isRunning() {
        return running.get();
    }

    boolean isInputQueueEmpty() {
        return inputQueue.empty();
    }

    LBStats getStats() {
        long[] countsCopy;
        synchronized (perFpCounts) {
            countsCopy = perFpCounts.clone();
        }
        return new LBStats(packetsReceived.get(), packetsDispatched.get(), countsCopy);
    }

    private void run() {
        while (running.get() || !inputQueue.empty()) {
            Optional<PacketJob> jobOpt = inputQueue.popWithTimeout(Duration.ofMillis(100));
            if (jobOpt.isEmpty()) {
                continue;
            }

            PacketJob job = jobOpt.get();
            packetsReceived.incrementAndGet();

            int fpIndex = selectFP(job.tuple);
            fpQueues.get(fpIndex).push(job);
            packetsDispatched.incrementAndGet();
            synchronized (perFpCounts) {
                perFpCounts[fpIndex]++;
            }
        }
    }

    private int selectFP(FiveTuple tuple) {
        int hash = tuple.hashCode() & Integer.MAX_VALUE;
        return hash % numFps;
    }

    record LBStats(long packetsReceived, long packetsDispatched, long[] perFpPackets) {
    }
}