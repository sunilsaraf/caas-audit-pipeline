package com.caas.pac;

/**
 * Policy effect types.
 */
public enum PolicyEffect {
    ALLOW("Allow"),
    DENY("Deny");

    private final String value;

    PolicyEffect(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
