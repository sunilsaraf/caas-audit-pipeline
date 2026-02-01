package com.caas.cei;

/**
 * Types of compliance-relevant events.
 */
public enum EventType {
    OBJECT_CREATE("object.create"),
    OBJECT_UPDATE("object.update"),
    OBJECT_DELETE("object.delete"),
    OBJECT_READ("object.read"),
    POLICY_CREATE("policy.create"),
    POLICY_UPDATE("policy.update"),
    POLICY_DELETE("policy.delete");

    private final String value;

    EventType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
