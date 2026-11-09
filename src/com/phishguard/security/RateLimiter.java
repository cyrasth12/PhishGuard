package com.phishguard.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe sliding window rate limiter for API endpoints.
 */
public class RateLimiter {
    private final int maxRequestsPerMinute;
    private final Map<String, RequestCounter> clientRequests = new ConcurrentHashMap<>();

    public RateLimiter(int maxRequestsPerMinute) {
        this.maxRequestsPerMinute = maxRequestsPerMinute;
    }

    public boolean allowRequest(String clientId) {
        long now = System.currentTimeMillis();
        RequestCounter counter = clientRequests.compute(clientId, (key, existing) -> {
            if (existing == null || (now - existing.timestamp) > 60000) {
                return new RequestCounter(now, new AtomicInteger(1));
            } else {
                existing.count.incrementAndGet();
                return existing;
            }
        });

        return counter.count.get() <= maxRequestsPerMinute;
    }

    private static class RequestCounter {
        final long timestamp;
        final AtomicInteger count;

        RequestCounter(long timestamp, AtomicInteger count) {
            this.timestamp = timestamp;
            this.count = count;
        }
    }
}
