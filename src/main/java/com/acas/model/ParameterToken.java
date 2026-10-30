package com.acas.model;

public class ParameterToken {
    private final String name;
    private final String value;
    private final String actorId;
    private final String type; // URL, BODY, COOKIE

    public ParameterToken(String name, String value, String actorId, String type) {
        this.name = name;
        this.value = value;
        this.actorId = actorId;
        this.type = type;
    }

    public String getName() { return name; }
    public String getValue() { return value; }
    public String getActorId() { return actorId; }
    public String getType() { return type; }
}
