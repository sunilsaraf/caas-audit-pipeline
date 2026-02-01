package com.caas.cei;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a compliance-relevant event.
 */
public class ComplianceEvent {
    private String eventId;
    private EventType eventType;
    private Instant timestamp;
    private String tenantId;
    private String bucket;
    private String objectKey;
    private String principal;
    private Map<String, Object> metadata;

    private static final Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();

    public ComplianceEvent(String eventId, EventType eventType, Instant timestamp,
                          String tenantId, String bucket) {
        this.eventId = eventId;
        this.eventType = eventType;
        this.timestamp = timestamp;
        this.tenantId = tenantId;
        this.bucket = bucket;
        this.metadata = new HashMap<>();
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("event_id", eventId);
        map.put("event_type", eventType.getValue());
        map.put("timestamp", timestamp.toString());
        map.put("tenant_id", tenantId);
        map.put("bucket", bucket);
        map.put("object_key", objectKey);
        map.put("principal", principal);
        map.put("metadata", metadata);
        return map;
    }

    public String computeHash() {
        try {
            String jsonData = gson.toJson(toMap());
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(jsonData.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    // Getters and Setters
    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public EventType getEventType() {
        return eventType;
    }

    public void setEventType(EventType eventType) {
        this.eventType = eventType;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getBucket() {
        return bucket;
    }

    public void setBucket(String bucket) {
        this.bucket = bucket;
    }

    public String getObjectKey() {
        return objectKey;
    }

    public void setObjectKey(String objectKey) {
        this.objectKey = objectKey;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }
}
