package com.packetanalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

final class ObjectPool<T> {
    private final List<T> available;
    private final Supplier<T> factory;

    ObjectPool(int initialSize, Supplier<T> factory) {
        this.factory = factory;
        this.available = new ArrayList<>(initialSize);
        for (int i = 0; i < initialSize; i++) {
            available.add(factory.get());
        }
    }

    T acquire() {
        if (!available.isEmpty()) {
            return available.remove(available.size() - 1);
        }
        return factory.get();
    }

    void release(T object) {
        available.add(object);
    }
}
