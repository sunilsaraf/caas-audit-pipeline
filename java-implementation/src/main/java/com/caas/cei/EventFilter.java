package com.caas.cei;

import java.util.ArrayList;
import java.util.List;

/**
 * Filters events based on criteria.
 */
public class EventFilter {
    private final List<String> tenantFilters;
    private final List<String> bucketFilters;
    private final List<EventType> eventTypeFilters;

    public EventFilter() {
        this.tenantFilters = new ArrayList<>();
        this.bucketFilters = new ArrayList<>();
        this.eventTypeFilters = new ArrayList<>();
    }

    public void addTenantFilter(String tenantId) {
        tenantFilters.add(tenantId);
    }

    public void addBucketFilter(String bucket) {
        bucketFilters.add(bucket);
    }

    public void addEventTypeFilter(EventType eventType) {
        eventTypeFilters.add(eventType);
    }

    /**
     * Check if event matches filter criteria.
     *
     * @param event Event to check
     * @return true if event matches all active filters
     */
    public boolean matches(ComplianceEvent event) {
        if (!tenantFilters.isEmpty() && !tenantFilters.contains(event.getTenantId())) {
            return false;
        }

        if (!bucketFilters.isEmpty() && !bucketFilters.contains(event.getBucket())) {
            return false;
        }

        if (!eventTypeFilters.isEmpty() && !eventTypeFilters.contains(event.getEventType())) {
            return false;
        }

        return true;
    }
}
