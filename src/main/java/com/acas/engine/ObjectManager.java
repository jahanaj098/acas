package com.acas.engine;

import burp.api.montoya.MontoyaApi;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ObjectManager is the "Brain" of ACAS.
 * It tracks relationships between Actors and the Objects they own or access.
 */
public class ObjectManager {
    private final MontoyaApi api;
    
    // Maps Object Type (e.g. "user_id") -> (Value -> Set of Owner Actor IDs)
    private final Map<String, Map<String, Set<String>>> objectOwnership = new ConcurrentHashMap<>();
    
    // Maps Actor ID -> List of Objects they "own"
    private final Map<String, List<ObjectEntry>> actorObjects = new ConcurrentHashMap<>();

    public ObjectManager(MontoyaApi api) {
        this.api = api;
    }

    public void registerOwnership(String actorId, String type, String value, double confidence, String source) {
        objectOwnership.computeIfAbsent(type, k -> new ConcurrentHashMap<>())
                       .computeIfAbsent(value, k -> Collections.newSetFromMap(new ConcurrentHashMap<>()))
                       .add(actorId);

        List<ObjectEntry> entries = actorObjects.computeIfAbsent(actorId, k -> Collections.synchronizedList(new ArrayList<>()));
        boolean exists = entries.stream().anyMatch(e -> e.type.equals(type) && e.value.equals(value));
        
        if (!exists) {
            entries.add(new ObjectEntry(type, value, confidence, System.currentTimeMillis(), source));
            api.logging().logToOutput("ACAS: Learned ownership for Actor[" + actorId + "]: " + type + "=" + value + " from " + source);
        }
    }

    public List<ObjectEntry> getObjectsForActor(String actorId) {
        return actorObjects.getOrDefault(actorId, Collections.emptyList());
    }

    public Map<String, Map<String, Set<String>>> getFullMap() {
        return Collections.unmodifiableMap(objectOwnership);
    }

    public Set<String> getAllActorIds() {
        return Collections.unmodifiableSet(actorObjects.keySet());
    }

    public static class ObjectEntry {
        public final String type;
        public final String value;
        public final double confidence;
        public final long discoveredAt;
        public final String source;

        public ObjectEntry(String type, String value, double confidence, long discoveredAt, String source) {
            this.type = type;
            this.value = value;
            this.confidence = confidence;
            this.discoveredAt = discoveredAt;
            this.source = source;
        }
    }
}
