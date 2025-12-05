package com.packetanalyzer;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

final class ThreadSafeQueue<T> {
    private final ArrayBlockingQueue<T> queue;
    private final AtomicBoolean shutdown = new AtomicBoolean(false);

    ThreadSafeQueue(int maxSize) {
        this.queue = new ArrayBlockingQueue<>(maxSize);
    }

    void push(T item) {
        while (!shutdown.get()) {
            try {
                if (queue.offer(item, 100, TimeUnit.MILLISECONDS)) {
                    return;
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    Optional<T> popWithTimeout(Duration timeout) {
        try {
            T item = queue.poll(timeout.toMillis(), TimeUnit.MILLISECONDS);
            return Optional.ofNullable(item);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    boolean empty() {
        return queue.isEmpty();
    }

    int size() {
        return queue.size();
    }

    void shutdown() {
        shutdown.set(true);
    }

    boolean isShutdown() {
        return shutdown.get();
    }
}