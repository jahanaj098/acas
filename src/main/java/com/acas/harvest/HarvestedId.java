package com.acas.harvest;

import java.time.Instant;

public class HarvestedId {
    private final String value;
    private final IdType type;
    private final String fieldName;
    private final String endpointPattern;
    private final String actorName;
    private final String source;
    private final Instant discoveredAt;

    public HarvestedId(String value,
                       IdType type,
                       String fieldName,
                       String endpointPattern,
                       String actorName,
                       String source) {
        this.value = value;
        this.type = type;
        this.fieldName = fieldName;
        this.endpointPattern = endpointPattern;
        this.actorName = actorName;
        this.source = source;
        this.discoveredAt = Instant.now();
    }

    public String getValue() { return value; }
    public IdType getType() { return type; }
    public String getFieldName() { return fieldName; }
    public String getEndpointPattern() { return endpointPattern; }
    public String getActorName() { return actorName; }
    public String getSource() { return source; }
    public Instant getDiscoveredAt() { return discoveredAt; }
}
