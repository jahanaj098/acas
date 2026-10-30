package com.acas.engine;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * RateLimiter enforces request throttling for hunts.
 * Supports: RPS (requests/sec), RPM (requests/min), max concurrent, time-based stop.
 */
public class RateLimiter {
    private volatile int requestsPerSec = 5;
    private volatile int requestsPerMin = 300;
    private volatile int maxConcurrent = 2;
    private volatile int stopAfterMinutes = 0;
    private volatile boolean enabled = true;

    private final AtomicInteger concurrentCount = new AtomicInteger(0);
    private final AtomicLong huntStartTime = new AtomicLong(0);
    private final AtomicLong lastRequestTime = new AtomicLong(0);
    private final AtomicLong requestCountLastSecond = new AtomicLong(0);
    private final AtomicLong requestCountLastMinute = new AtomicLong(0);
    private final AtomicLong lastSecondWindowStart = new AtomicLong(0);
    private final AtomicLong lastMinuteWindowStart = new AtomicLong(0);

    public RateLimiter() {
    }

    /**
     * Configure rate limiting parameters.
     */
    public void configure(int rps, int rpm, int maxConcurrent, int stopAfterMinutes, boolean enabled) {
        this.requestsPerSec = Math.max(1, rps);
        this.requestsPerMin = Math.max(1, rpm);
        this.maxConcurrent = Math.max(1, maxConcurrent);
        this.stopAfterMinutes = Math.max(0, stopAfterMinutes);
        this.enabled = enabled;
    }

    /**
     * Mark hunt start time.
     */
    public void startHunt() {
        huntStartTime.set(System.currentTimeMillis());
        lastRequestTime.set(System.currentTimeMillis());
        requestCountLastSecond.set(0);
        requestCountLastMinute.set(0);
        lastSecondWindowStart.set(System.currentTimeMillis());
        lastMinuteWindowStart.set(System.currentTimeMillis());
        concurrentCount.set(0);
    }

    /**
     * Acquire a permit to send a request. Blocks until rate limits allow.
     * Returns false if hunt should stop (time-based limit exceeded).
     */
    public boolean acquirePermit() throws InterruptedException {
        if (!enabled) {
            concurrentCount.incrementAndGet();
            return !shouldStopByTime();
        }

        // 1. Check time-based stop
        if (shouldStopByTime()) {
            return false;
        }

        // 2. Check concurrent limit
        while (concurrentCount.get() >= maxConcurrent) {
            Thread.sleep(10);
            if (shouldStopByTime()) {
                return false;
            }
        }
        concurrentCount.incrementAndGet();

        // 3. Wait for RPS window
        long now = System.currentTimeMillis();
        long secondWindowAge = now - lastSecondWindowStart.get();
        if (secondWindowAge >= 1000) {
            lastSecondWindowStart.set(now);
            requestCountLastSecond.set(0);
        }

        while (requestCountLastSecond.get() >= requestsPerSec) {
            long sleepMs = Math.max(1, 1000 - secondWindowAge);
            Thread.sleep(Math.min(sleepMs, 50));
            now = System.currentTimeMillis();
            secondWindowAge = now - lastSecondWindowStart.get();
            if (secondWindowAge >= 1000) {
                lastSecondWindowStart.set(now);
                requestCountLastSecond.set(0);
            }
            if (shouldStopByTime()) {
                return false;
            }
        }
        requestCountLastSecond.incrementAndGet();

        // 4. Wait for RPM window
        long minuteWindowAge = now - lastMinuteWindowStart.get();
        if (minuteWindowAge >= 60000) {
            lastMinuteWindowStart.set(now);
            requestCountLastMinute.set(0);
        }

        while (requestCountLastMinute.get() >= requestsPerMin) {
            long sleepMs = Math.max(1, 60000 - minuteWindowAge);
            Thread.sleep(Math.min(sleepMs, 100));
            now = System.currentTimeMillis();
            minuteWindowAge = now - lastMinuteWindowStart.get();
            if (minuteWindowAge >= 60000) {
                lastMinuteWindowStart.set(now);
                requestCountLastMinute.set(0);
            }
            if (shouldStopByTime()) {
                return false;
            }
        }
        requestCountLastMinute.incrementAndGet();

        lastRequestTime.set(now);
        return !shouldStopByTime();
    }

    /**
     * Release a permit after request completes.
     */
    public void releasePermit() {
        concurrentCount.decrementAndGet();
    }

    /**
     * Check if hunt should stop based on time interval.
     */
    private boolean shouldStopByTime() {
        if (stopAfterMinutes <= 0) {
            return false;
        }
        long elapsedMs = System.currentTimeMillis() - huntStartTime.get();
        long thresholdMs = stopAfterMinutes * 60_000L;
        return elapsedMs >= thresholdMs;
    }

    /**
     * Get current concurrent request count.
     */
    public int getConcurrentCount() {
        return concurrentCount.get();
    }

    /**
     * Get elapsed hunt time in seconds.
     */
    public long getElapsedSeconds() {
        if (huntStartTime.get() == 0) {
            return 0;
        }
        return (System.currentTimeMillis() - huntStartTime.get()) / 1000;
    }

    /**
     * Get requests sent in last second.
     */
    public long getRequestsLastSecond() {
        return requestCountLastSecond.get();
    }

    /**
     * Get requests sent in last minute.
     */
    public long getRequestsLastMinute() {
        return requestCountLastMinute.get();
    }

    /**
     * Get rate limit configuration as string.
     */
    public String getConfigSummary() {
        if (!enabled) {
            return "Rate limiting: DISABLED";
        }
        return String.format("RPS=%d | RPM=%d | MaxConcurrent=%d | StopAfter=%d min",
                requestsPerSec, requestsPerMin, maxConcurrent, stopAfterMinutes);
    }
}
