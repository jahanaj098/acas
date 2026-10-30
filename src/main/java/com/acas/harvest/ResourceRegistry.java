package com.acas.harvest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class ResourceRegistry {
    private static final String MANUAL_CANDIDATE_FIELD = "manual_candidate";
    private final Map<String, Map<String, List<HarvestedId>>> store = new ConcurrentHashMap<>();
    private final Map<String, List<HarvestedId>> byFieldName = new ConcurrentHashMap<>();
    private volatile Instant lastHarvestAt = null;

    public void register(HarvestedId id) {
        if (id == null || id.getValue() == null || id.getValue().isBlank()) {
            return;
        }

        // Avoid unbounded duplicate growth for the same actor/pattern/value/source tuple.
        List<HarvestedId> existing = store
            .getOrDefault(id.getEndpointPattern(), Map.of())
            .getOrDefault(id.getActorName(), List.of());
        boolean duplicate = existing.stream().anyMatch(e ->
            safeEq(e.getValue(), id.getValue())
                && safeEq(e.getFieldName(), id.getFieldName())
                && safeEq(e.getSource(), id.getSource()));
        if (duplicate) {
            return;
        }

        store
            .computeIfAbsent(id.getEndpointPattern(), k -> new ConcurrentHashMap<>())
            .computeIfAbsent(id.getActorName(), k -> Collections.synchronizedList(new ArrayList<>()))
            .add(id);

        byFieldName
            .computeIfAbsent(id.getFieldName(), k -> Collections.synchronizedList(new ArrayList<>()))
            .add(id);

        lastHarvestAt = Instant.now();
    }

    public List<String> getIdsByPatternAndActor(String pattern, String actorName) {
        return store
            .getOrDefault(pattern, Map.of())
            .getOrDefault(actorName, List.of())
            .stream()
            .filter(this::isGeneralId)
            .map(HarvestedId::getValue)
            .filter(v -> v != null && !v.isBlank())
            .distinct()
            .collect(Collectors.toList());
    }

    public Set<String> getActorsForPattern(String pattern) {
        return new HashSet<>(store.getOrDefault(pattern, Map.of()).keySet());
    }

    public List<String> getCrossActorIds(String endpointPattern, String requestingActor, String targetActor) {
        List<String> requestorIds = getIdsByPatternAndActor(endpointPattern, requestingActor);
        Set<String> requestorSet = new HashSet<>(requestorIds);

        return getIdsByPatternAndActor(endpointPattern, targetActor)
            .stream()
            .filter(id -> !requestorSet.contains(id))
            .distinct()
            .collect(Collectors.toList());
    }

    public boolean hasCrossActorIds(String endpointPattern) {
        return getCrossActorPatternCount(endpointPattern) > 0;
    }

    public List<String> getIdsByFieldName(String fieldName) {
        return byFieldName
            .getOrDefault(fieldName, List.of())
            .stream()
            .map(HarvestedId::getValue)
            .filter(v -> v != null && !v.isBlank())
            .distinct()
            .collect(Collectors.toList());
    }

    public List<HarvestedId> getAllIdsByActor(String actorName) {
        return store.values().stream()
            .flatMap(m -> m.getOrDefault(actorName, List.of()).stream())
            .filter(this::isGeneralId)
            .collect(Collectors.toList());
    }

    public List<String> getKnownNeighbours(String endpointPattern, long numericId, int range) {
        List<String> all = store
            .getOrDefault(endpointPattern, Map.of())
            .values().stream()
            .flatMap(List::stream)
            .filter(this::isGeneralId)
            .map(HarvestedId::getValue)
            .filter(v -> v != null && v.matches("\\d+"))
            .collect(Collectors.toList());

        return all.stream()
            .filter(v -> {
                long val = Long.parseLong(v);
                return Math.abs(val - numericId) <= range;
            })
            .distinct()
            .collect(Collectors.toList());
    }

    public int getTotalHarvestedCount() {
        return store.values().stream()
            .flatMap(m -> m.values().stream())
            .mapToInt(List::size)
            .sum();
    }

    public Map<String, Integer> getSummaryByActor() {
        Map<String, Integer> summary = new HashMap<>();
        store.values().forEach(actorMap ->
            actorMap.forEach((actor, ids) ->
                summary.merge(actor, ids.size(), Integer::sum)));
        return summary;
    }

    public int getPatternCount() {
        return store.size();
    }

    public int getCrossActorPatternCount() {
        return (int) store.keySet().stream().filter(this::hasCrossActorIds).count();
    }

    public int getCrossActorPatternCount(String endpointPattern) {
        Map<String, List<HarvestedId>> actorMap = store.getOrDefault(endpointPattern, Map.of());
        return actorMap.size() >= 2 ? 1 : 0;
    }

    public Set<String> getAllPatterns() {
        return new HashSet<>(store.keySet());
    }

    public List<String> getAllKnownIds() {
        return store.values().stream()
            .flatMap(m -> m.values().stream())
            .flatMap(List::stream)
            .filter(this::isGeneralId)
            .map(HarvestedId::getValue)
            .filter(v -> v != null && !v.isBlank())
            .distinct()
            .collect(Collectors.toList());
    }

    public List<String> getManualCandidates() {
        return byFieldName
            .getOrDefault(MANUAL_CANDIDATE_FIELD, List.of())
            .stream()
            .map(HarvestedId::getValue)
            .filter(v -> v != null && !v.isBlank())
            .distinct()
            .collect(Collectors.toList());
    }

    public List<String> getManualCandidatesByPatternAndActor(String pattern, String actorName) {
        return byFieldName
            .getOrDefault(MANUAL_CANDIDATE_FIELD, List.of())
            .stream()
            .filter(id -> safeEq(id.getEndpointPattern(), pattern))
            .filter(id -> safeEq(id.getActorName(), actorName))
            .map(HarvestedId::getValue)
            .filter(v -> v != null && !v.isBlank())
            .distinct()
            .collect(Collectors.toList());
    }

    public String getLatestIdForPatternActor(String endpointPattern, String actorName) {
        return store
            .getOrDefault(endpointPattern, Map.of())
            .getOrDefault(actorName, List.of())
            .stream()
            .filter(this::isGeneralId)
            .sorted((a, b) -> b.getDiscoveredAt().compareTo(a.getDiscoveredAt()))
            .map(HarvestedId::getValue)
            .filter(v -> v != null && !v.isBlank())
            .findFirst()
            .orElse(null);
    }

    public List<String> getNumericIdsByActor(String actorName) {
        return getAllIdsByActor(actorName).stream()
            .map(HarvestedId::getValue)
            .filter(v -> v != null && v.matches("\\d+"))
            .distinct()
            .collect(Collectors.toList());
    }

    public Instant getLastHarvestAt() {
        return lastHarvestAt;
    }

    public Set<String> getAllActors() {
        return store.values().stream()
            .flatMap(m -> m.keySet().stream())
            .collect(Collectors.toCollection(HashSet::new));
    }

    public void addManualId(String value, String endpointPattern, String actorName, String fieldName) {
        if (value == null || value.isBlank()) {
            return;
        }
        String pattern = endpointPattern == null || endpointPattern.isBlank() ? "MANUAL" : endpointPattern;
        String actor = actorName == null || actorName.isBlank() ? "Manual" : actorName;
        String field = fieldName == null || fieldName.isBlank() ? "manual_id" : fieldName;
        register(new HarvestedId(value.trim(), IdType.UNKNOWN, field, pattern, actor, "MANUAL"));
    }

    private boolean safeEq(String a, String b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.equals(b);
    }

    private boolean isGeneralId(HarvestedId id) {
        if (id == null) {
            return false;
        }
        return !MANUAL_CANDIDATE_FIELD.equalsIgnoreCase(id.getFieldName());
    }
}
