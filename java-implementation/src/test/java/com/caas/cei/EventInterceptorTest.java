package com.caas.cei;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Compliance Event Interceptor (CEI)
 */
class EventInterceptorTest {

    @Test
    void testInterceptEvent() {
        EventInterceptor interceptor = new EventInterceptor();
        
        ComplianceEvent event = new ComplianceEvent(
            UUID.randomUUID().toString(),
            EventType.OBJECT_CREATE,
            Instant.now(),
            "tenant-1",
            "test-bucket"
        );
        
        boolean result = interceptor.intercept(event);
        
        assertTrue(result);
        assertEquals(1, interceptor.getEventCount());
    }

    @Test
    void testGetEvent() {
        EventInterceptor interceptor = new EventInterceptor();
        
        ComplianceEvent event = new ComplianceEvent(
            UUID.randomUUID().toString(),
            EventType.OBJECT_CREATE,
            Instant.now(),
            "tenant-1",
            "test-bucket"
        );
        
        interceptor.intercept(event);
        ComplianceEvent retrieved = interceptor.getEvent();
        
        assertNotNull(retrieved);
        assertEquals(event.getEventId(), retrieved.getEventId());
    }

    @Test
    void testVerifyCompleteness() {
        EventInterceptor interceptor = new EventInterceptor();
        
        // Intercept 3 events
        for (int i = 0; i < 3; i++) {
            ComplianceEvent event = new ComplianceEvent(
                UUID.randomUUID().toString(),
                EventType.OBJECT_CREATE,
                Instant.now(),
                "tenant-1",
                "test-bucket"
            );
            interceptor.intercept(event);
        }
        
        assertTrue(interceptor.verifyCompleteness(3));
        assertFalse(interceptor.verifyCompleteness(2));
        assertFalse(interceptor.verifyCompleteness(4));
    }

    @Test
    void testHandlerRegistration() {
        EventInterceptor interceptor = new EventInterceptor();
        AtomicInteger handlerCallCount = new AtomicInteger(0);
        
        interceptor.registerHandler(event -> {
            handlerCallCount.incrementAndGet();
        });
        
        ComplianceEvent event = new ComplianceEvent(
            UUID.randomUUID().toString(),
            EventType.OBJECT_CREATE,
            Instant.now(),
            "tenant-1",
            "test-bucket"
        );
        
        interceptor.intercept(event);
        
        assertEquals(1, handlerCallCount.get());
    }

    @Test
    void testEventFilter() {
        EventFilter filter = new EventFilter();
        filter.addTenantFilter("tenant-1");
        
        ComplianceEvent event1 = new ComplianceEvent(
            UUID.randomUUID().toString(),
            EventType.OBJECT_CREATE,
            Instant.now(),
            "tenant-1",
            "test-bucket"
        );
        
        ComplianceEvent event2 = new ComplianceEvent(
            UUID.randomUUID().toString(),
            EventType.OBJECT_CREATE,
            Instant.now(),
            "tenant-2",
            "test-bucket"
        );
        
        assertTrue(filter.matches(event1));
        assertFalse(filter.matches(event2));
    }

    @Test
    void testComplianceEventHash() {
        ComplianceEvent event = new ComplianceEvent(
            "evt-123",
            EventType.OBJECT_CREATE,
            Instant.parse("2024-01-01T12:00:00Z"),
            "tenant-1",
            "test-bucket"
        );
        
        String hash1 = event.computeHash();
        String hash2 = event.computeHash();
        
        // Hash should be deterministic
        assertEquals(hash1, hash2);
        assertEquals(64, hash1.length()); // SHA-256 hex
    }
}
