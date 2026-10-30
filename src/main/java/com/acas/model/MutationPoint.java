package com.acas.model;

import java.util.LinkedHashMap;
import java.util.Map;

/** One exact, reviewable mutable location. It is not an approval to mutate by itself. */
public final class MutationPoint {
    public String pointId;
    public String location;
    public String name;
    public String selector;
    public String encoding = "raw";
    public String valueType = "string";
    public String originalValue;
    public String valueHash;
    public String schema = "string";
    public OperationSafety mutationSafety = OperationSafety.UNKNOWN;
    public boolean requiresReview = true;
    public boolean replayable = true;
    public Map<String,String> metadata = new LinkedHashMap<>();
}
