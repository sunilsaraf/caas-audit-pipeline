package com.caas.pac;

import java.util.*;

/**
 * Represents a compliance policy.
 */
public class Policy {
    private String policyId;
    private String version;
    private String name;
    private List<PolicyStatement> statements;
    private Map<String, Object> metadata;

    public Policy(String policyId, String version, String name, 
                 List<PolicyStatement> statements) {
        this.policyId = policyId;
        this.version = version;
        this.name = name;
        this.statements = statements;
        this.metadata = new HashMap<>();
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("PolicyId", policyId);
        map.put("Version", version);
        map.put("Name", name);
        
        List<Map<String, Object>> stmtMaps = new ArrayList<>();
        for (PolicyStatement stmt : statements) {
            stmtMaps.add(stmt.toMap());
        }
        map.put("Statements", stmtMaps);
        map.put("Metadata", metadata);
        
        return map;
    }

    // Getters and Setters
    public String getPolicyId() {
        return policyId;
    }

    public void setPolicyId(String policyId) {
        this.policyId = policyId;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<PolicyStatement> getStatements() {
        return statements;
    }

    public void setStatements(List<PolicyStatement> statements) {
        this.statements = statements;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }
}
