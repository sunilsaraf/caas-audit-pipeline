package com.caas.pac;

/**
 * Policy action types.
 */
public enum PolicyAction {
    READ("s3:GetObject"),
    WRITE("s3:PutObject"),
    DELETE("s3:DeleteObject"),
    LIST("s3:ListBucket"),
    ALL("s3:*");

    private final String value;

    PolicyAction(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
