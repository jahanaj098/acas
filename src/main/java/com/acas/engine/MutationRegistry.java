package com.acas.engine;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class MutationRegistry {
    private final MontoyaApi api;
    private final List<MutationDefinition> mutations = new ArrayList<>();
    private final List<MatchReplaceRule> matchReplaceRules = new ArrayList<>();
    private final Gson gson = new Gson();
    private static final String MUTATION_KEY = "acas_mutations";
    private static final String MATCH_REPLACE_KEY = "acas_match_replace_rules";

    public MutationRegistry(MontoyaApi api) {
        this.api = api;
        loadDefaults();
        loadFromPersistence();
        loadMatchReplaceRules();
    }

    private void loadDefaults() {
        // ACAS focused mode: only the two deterministic authorization-consistency
        // tests are registered. All other techniques are delegated to the Hermes agent.
        mutations.add(new MutationDefinition("A1 Clean Anonymous", "Strip all session headers (Cookie, Authorization, Bearer token) completely and fire the request with zero authentication. A 200 with the same data means the endpoint is publicly accessible without any login.", MutationDefinition.Category.A, true, false));
        mutations.add(new MutationDefinition("B1 Session Swap", "Replace only the session identifiers (Cookie and Authorization header) with each other actor's session while keeping the request byte-identical. Getting the owner's data back confirms a horizontal or vertical authorization break.", MutationDefinition.Category.B, true, false));
    }

    public List<MutationDefinition> getAll() {
        return new ArrayList<>(mutations);
    }

    public List<MutationDefinition> getCustomMutations() {
        return mutations.stream().filter(m -> m.isCustom).collect(Collectors.toList());
    }

    public List<MutationDefinition> getEnabled() {
        return mutations.stream().filter(MutationDefinition::isEnabled).collect(Collectors.toList());
    }

    public List<MatchReplaceRule> getMatchReplaceRules() {
        return new ArrayList<>(matchReplaceRules);
    }

    public void addMatchReplaceRule(MatchReplaceRule rule) {
        if (rule == null) {
            return;
        }
        matchReplaceRules.add(rule);
        saveMatchReplaceRules();
    }

    public void removeMatchReplaceRule(String id) {
        if (id == null || id.trim().isEmpty()) {
            return;
        }
        matchReplaceRules.removeIf(r -> id.equals(r.id));
        saveMatchReplaceRules();
    }

    public void replaceMatchReplaceRules(List<MatchReplaceRule> rules) {
        matchReplaceRules.clear();
        if (rules != null) {
            for (MatchReplaceRule rule : rules) {
                if (rule != null) {
                    rule.normalize();
                    matchReplaceRules.add(rule);
                }
            }
        }
        saveMatchReplaceRules();
    }

    public boolean isEnabledCode(String typeName) {
        if (typeName == null || typeName.isEmpty()) return true;
        return mutations.stream()
            .filter(MutationDefinition::isEnabled)
            .map(m -> m.name != null ? m.name.trim() : "")
            .map(name -> name.isEmpty() ? "" : name.split("\\s+")[0])
            .anyMatch(code -> code.equalsIgnoreCase(typeName));
    }

    public void addCustom(MutationDefinition custom) {
        mutations.add(custom);
        saveToPersistence();
    }

    public void removeCustom(String name) {
        mutations.removeIf(m -> m.isCustom && m.name.equals(name));
        saveToPersistence();
    }

    public void resetToDefaults() {
        mutations.clear();
        loadDefaults();
        saveToPersistence();
    }

    public void replaceCustomMutations(List<MutationDefinition> customMutations) {
        mutations.removeIf(m -> m.isCustom);
        if (customMutations != null) {
            for (MutationDefinition mutation : customMutations) {
                if (mutation != null) {
                    mutations.add(mutation);
                }
            }
        }
        saveToPersistence();
    }

    public void saveToPersistence() {
        try {
            api.persistence().extensionData().setString(MUTATION_KEY, gson.toJson(mutations));
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error saving mutations: " + e.getMessage());
        }
    }

    public void saveMatchReplaceRules() {
        try {
            api.persistence().extensionData().setString(MATCH_REPLACE_KEY, gson.toJson(matchReplaceRules));
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error saving match/replace rules: " + e.getMessage());
        }
    }

    private void loadFromPersistence() {
        try {
            String json = api.persistence().extensionData().getString(MUTATION_KEY);
            if (json != null && !json.isEmpty()) {
                Type listType = new TypeToken<List<MutationDefinition>>() {}.getType();
                List<MutationDefinition> loaded = gson.fromJson(json, listType);
                if (loaded != null && !loaded.isEmpty()) {
                    for (MutationDefinition persisted : loaded) {
                        if (persisted == null || persisted.name == null) continue;
                        MutationDefinition existing = mutations.stream()
                            .filter(m -> persisted.name.equals(m.name))
                            .findFirst()
                            .orElse(null);
                        if (existing != null) {
                            existing.setEnabled(persisted.isEnabled());
                            existing.customHeaderName = persisted.customHeaderName;
                            existing.customHeaderValue = persisted.customHeaderValue;
                            existing.customMethod = persisted.customMethod;
                        } else {
                            mutations.add(persisted);
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error loading mutations: " + e.getMessage());
        }
    }

    private void loadMatchReplaceRules() {
        try {
            String json = api.persistence().extensionData().getString(MATCH_REPLACE_KEY);
            if (json == null || json.isEmpty()) {
                return;
            }
            Type listType = new TypeToken<List<MatchReplaceRule>>() {}.getType();
            List<MatchReplaceRule> loaded = gson.fromJson(json, listType);
            if (loaded != null) {
                matchReplaceRules.clear();
                for (MatchReplaceRule rule : loaded) {
                    if (rule != null) {
                        rule.normalize();
                        matchReplaceRules.add(rule);
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("ACAS: Error loading match/replace rules: " + e.getMessage());
        }
    }
}
