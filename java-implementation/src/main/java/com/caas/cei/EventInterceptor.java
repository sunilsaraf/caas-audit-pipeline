package com.caas.cei;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Intercepts and captures compliance-relevant events.
 * Provides a hook mechanism to intercept events before they cause state mutations.
 */
public class EventInterceptor {
    private final BlockingQueue<ComplianceEvent> eventQueue;
    private final List<Consumer<ComplianceEvent>> handlers;
    private final List<ComplianceEvent> interceptedEvents;
    private int eventCount;

    public EventInterceptor(int maxQueueSize) {
        this.eventQueue = new LinkedBlockingQueue<>(maxQueueSize);
        this.handlers = new ArrayList<>();
        this.interceptedEvents = new ArrayList<>();
        this.eventCount = 0;
    }

    public EventInterceptor() {
        this(10000);
    }

    /**
     * Register a handler function to be called when events are intercepted.
     */
    public void registerHandler(Consumer<ComplianceEvent> handler) {
        handlers.add(handler);
    }

    /**
     * Intercept a compliance event.
     *
     * @param event The compliance event to intercept
     * @return true if event was successfully intercepted, false otherwise
     */
    public boolean intercept(ComplianceEvent event) {
        try {
            // Add to queue for processing
            eventQueue.offer(event);

            // Keep track for completeness verification
            synchronized (this) {
                interceptedEvents.add(event);
                eventCount++;
            }

            // Call registered handlers
            for (Consumer<ComplianceEvent> handler : handlers) {
                try {
                    handler.accept(event);
                } catch (Exception e) {
                    System.err.println("Handler error: " + e.getMessage());
                }
            }

            return true;
        } catch (Exception e) {
            System.err.println("Failed to intercept event: " + e.getMessage());
            return false;
        }
    }

    /**
     * Retrieve an event from the queue.
     *
     * @param timeoutMs Maximum time to wait for an event in milliseconds (null = non-blocking)
     * @return ComplianceEvent if available, null otherwise
     */
    public ComplianceEvent getEvent(Long timeoutMs) {
        try {
            if (timeoutMs == null) {
                return eventQueue.poll();
            } else {
                return eventQueue.poll(timeoutMs, TimeUnit.MILLISECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    public ComplianceEvent getEvent() {
        return getEvent(null);
    }

    /**
     * Get the total number of intercepted events.
     */
    public synchronized int getEventCount() {
        return eventCount;
    }

    /**
     * Verify that all expected events were captured.
     *
     * @param expectedCount Expected number of events
     * @return true if actual count matches expected count
     */
    public synchronized boolean verifyCompleteness(int expectedCount) {
        return eventCount == expectedCount;
    }

    /**
     * Get list of all intercepted events.
     */
    public synchronized List<ComplianceEvent> getInterceptedEvents() {
        return new ArrayList<>(interceptedEvents);
    }
}
