package com.caas.cal;

import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents a single audit record.
 */
public class AuditRecord {
    private String recordId;
    private String eventId;
    private Instant timestamp;
    private String eventType;
    private String tenantId;
    private String bucket;
    private String objectKey;
    private String policyCommitment;
    private Map<String, Object> metadata;
    private String previousHash;
    private String recordHash;

    private static final Gson gson = new Gson();

    public AuditRecord(String recordId, String eventId, Instant timestamp,
                      String eventType, String tenantId, String bucket) {
        this.recordId = recordId;
        this.eventId = eventId;
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.tenantId = tenantId;
        this.bucket = bucket;
        this.metadata = new HashMap<>();
    }

    public String computeHash() {
        try {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("record_id", recordId);
            data.put("event_id", eventId);
            data.put("timestamp", timestamp.toString());
            data.put("event_type", eventType);
            data.put("tenant_id", tenantId);
            data.put("bucket", bucket);
            data.put("object_key", objectKey);
            data.put("policy_commitment", policyCommitment);
            data.put("metadata", metadata);
            data.put("previous_hash", previousHash);

            String jsonData = gson.toJson(data);
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
    public String getRecordId() {
        return recordId;
    }

    public String getEventId() {
        return eventId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getBucket() {
        return bucket;
    }

    public String getObjectKey() {
        return objectKey;
    }

    public void setObjectKey(String objectKey) {
        this.objectKey = objectKey;
    }

    public String getPolicyCommitment() {
        return policyCommitment;
    }

    public void setPolicyCommitment(String policyCommitment) {
        this.policyCommitment = policyCommitment;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public String getRecordHash() {
        return recordHash;
    }

    public void setRecordHash(String recordHash) {
        this.recordHash = recordHash;
    }
}
