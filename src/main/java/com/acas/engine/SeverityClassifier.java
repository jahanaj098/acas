package com.acas.engine;

import burp.api.montoya.MontoyaApi;
import com.acas.model.AcasFinding;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentHashMap;

public class SeverityClassifier {
    private static final String SUPPRESSIONS_PREF_KEY = "acas.suppressions";
    
    private final java.util.concurrent.ConcurrentLinkedDeque<AcasFinding> findings = new java.util.concurrent.ConcurrentLinkedDeque<>();
    private final List<AcasFinding> reviewQueue = new CopyOnWriteArrayList<>();
    private final DeduplicationFilter deduplicationFilter = new DeduplicationFilter();
    private final DeduplicationFilter reviewDeduplicationFilter = new DeduplicationFilter();
    private final Set<String> suppressions = ConcurrentHashMap.newKeySet();
    private final MontoyaApi api;
    private final List<FindingListener> listeners = new java.util.concurrent.CopyOnWriteArrayList<>();

    public SeverityClassifier() {
        this(null);
    }

    public SeverityClassifier(MontoyaApi api) {
        this.api = api;
        loadSuppressions();
    }

    public interface FindingListener {
        void onNewFinding(AcasFinding finding);
    }

    public void addListener(FindingListener listener) {
        listeners.add(listener);
    }

    public boolean addFindingIfUnique(AcasFinding finding) {
        if (finding == null) return false;
        if (isSuppressed(finding)) return false;

        if (deduplicationFilter.isDuplicate(finding)) {
            return false;
        }

        findings.add(finding);
        
        for (FindingListener l : listeners) {
            l.onNewFinding(finding);
        }
        
        return true;
    }

    public boolean addReviewFindingIfUnique(AcasFinding finding) {
        if (finding == null) return false;
        if (isSuppressed(finding)) return false;
        if (reviewDeduplicationFilter.isDuplicate(finding)) {
            return false;
        }
        reviewQueue.add(finding);
        return true;
    }

    public boolean promoteReviewFinding(String findingId) {
        AcasFinding finding = findInReviewQueue(findingId);
        if (finding == null) return false;

        reviewQueue.remove(finding);
        finding.setConfidenceScore(85);
        finding.setConfirmedByDiff(true);
        return addFindingIfUnique(finding);
    }

    public boolean suppressReviewFinding(String findingId) {
        AcasFinding finding = findInReviewQueue(findingId);
        if (finding == null) return false;
        reviewQueue.remove(finding);
        suppressions.add(suppressionKey(finding));
        saveSuppressions();
        return true;
    }

    public int suppressAllReviewFindings() {
        int count = 0;
        for (AcasFinding finding : new java.util.ArrayList<>(reviewQueue)) {
            if (finding == null) continue;
            suppressions.add(suppressionKey(finding));
            count++;
        }
        reviewQueue.clear();
        saveSuppressions();
        return count;
    }

    public Set<String> getSuppressions() {
        return java.util.Collections.unmodifiableSet(suppressions);
    }

    public boolean removeSuppression(String key) {
        if (key == null) return false;
        boolean removed = suppressions.remove(key);
        if (removed) saveSuppressions();
        return removed;
    }

    public boolean isSuppressed(AcasFinding finding) {
        if (finding == null) return false;
        return suppressions.contains(suppressionKey(finding));
    }

    public List<AcasFinding> getAllFindings() {
        // Snapshot-on-read: safe for UI thread consumption without holding a lock
        return java.util.Collections.unmodifiableList(new java.util.ArrayList<>(findings));
    }

    /** Re-evaluate cached automatic results without replaying requests or deleting evidence. */
    public void revalidateProbeFindings(String url, String method) {
        ResponseComparator comparator = new ResponseComparator();
        for (AcasFinding finding : findings) {
            if (!java.util.Objects.equals(url, finding.getUrl())
                    || !java.util.Objects.equals(method, finding.getMethod())) continue;
            if (!Set.of("Passive Probe", "Session Swap", "Anonymous Test").contains(
                    finding.getSource() == null ? "" : finding.getSource())) continue;
            String owner = finding.getBaseResponse() == null ? "" : new String(finding.getBaseResponse(), java.nio.charset.StandardCharsets.UTF_8);
            String swapped = finding.getMutatedResponse() == null ? "" : new String(finding.getMutatedResponse(), java.nio.charset.StandardCharsets.UTF_8);
            if (comparator.hasOwnerDataEvidence(owner, swapped)) continue;
            finding.setSeverity("INFO");
            finding.setConfidenceScore(0);
            finding.setConfirmedByDiff(false);
            finding.setContainsOwnerData(false);
            finding.setLabel("NO_CONFIRMED_BYPASS");
            finding.setAnalysisNote("Re-evaluated: no matching owner data. Similar formatting or response length does not confirm an authorization bypass.");
        }
    }

    /** Removes every finding (confirmed + review) that references the named actor,
     *  used when an actor is deleted so the Result Matrix stays in sync. */
    public int removeFindingsByActor(String actorName) {
        if (actorName == null) return 0;
        int[] removed = {0};
        java.util.function.Predicate<AcasFinding> matches = f -> f != null
            && (actorName.equals(f.getOwnerActorName()) || actorName.equals(f.getReplayerActorName()));
        findings.removeIf(f -> { boolean m = matches.test(f); if (m) removed[0]++; return m; });
        reviewQueue.removeIf(matches);
        // Reset dedup so a fresh capture of the same endpoint can re-add rows later.
        deduplicationFilter.clear();
        reviewDeduplicationFilter.clear();
        return removed[0];
    }

    public List<AcasFinding> exportFindings() {
        return new java.util.ArrayList<>(findings);
    }

    public List<AcasFinding> getReviewFindings() {
        return java.util.Collections.unmodifiableList(reviewQueue);
    }

    public void clearFindings() {
        findings.clear();
        reviewQueue.clear();
        suppressions.clear();
        deduplicationFilter.clear();
        reviewDeduplicationFilter.clear();
    }

    public void replaceFindings(List<AcasFinding> importedFindings) {
        clearFindings();
        if (importedFindings == null) return;
        for (AcasFinding finding : importedFindings) {
            if (finding == null) continue;
            addFindingIfUnique(finding);
        }
    }

    /**
     * Get all findings that match a specific endpoint pattern.
     */
    public List<AcasFinding> getFindingsForEndpoint(String endpointPattern) {
        if (endpointPattern == null) return java.util.Collections.emptyList();
        return findings.stream()
            .filter(f -> endpointPattern.equals(f.getEndpointPattern()))
            .collect(java.util.stream.Collectors.toList());
    }

    /**
     * Get all findings matching a method + normalized path combo.
     */
    public List<AcasFinding> getFindingsForEndpoint(String method, String normalizedPath) {
        if (method == null || normalizedPath == null) return java.util.Collections.emptyList();
        return findings.stream()
            .filter(f -> method.equals(f.getMethod()) && normalizedPath.equals(f.getEndpointPattern()))
            .collect(java.util.stream.Collectors.toList());
    }

    /**
     * Check if any finding of CRITICAL or HIGH severity exists.
     */
    public boolean hasHighSeverityFindings() {
        return findings.stream().anyMatch(f -> 
            "CRITICAL".equals(f.getSeverity()) || "HIGH".equals(f.getSeverity()));
    }

    /**
     * Check if any finding of MEDIUM severity exists (but no CRITICAL/HIGH).
     */
    public boolean hasMediumSeverityOnly() {
        boolean hasMedium = findings.stream().anyMatch(f -> "MEDIUM".equals(f.getSeverity()));
        return hasMedium && !hasHighSeverityFindings();
    }

    public boolean removeReviewFinding(String findingId) {
        AcasFinding finding = findInReviewQueue(findingId);
        if (finding == null) return false;
        return reviewQueue.remove(finding);
    }

    public AcasFinding getReviewFinding(String findingId) {
        return findInReviewQueue(findingId);
    }

    private AcasFinding findInReviewQueue(String findingId) {
        if (findingId == null) return null;
        for (AcasFinding finding : reviewQueue) {
            if (findingId.equals(finding.getId())) {
                return finding;
            }
        }
        return null;
    }

    private String suppressionKey(AcasFinding finding) {
        // Fix #5: Include HTTP Method in the key so suppressing GET /api/user
        // does NOT accidentally suppress POST /api/user findings.
        String method   = finding.getMethod()           != null ? finding.getMethod()           : "-";
        String endpoint = finding.getEndpointPattern()  != null ? finding.getEndpointPattern()  : "-";
        String actor    = finding.getReplayerActorName() != null ? finding.getReplayerActorName() : "-";
        String mutation = finding.getMutationType()     != null ? finding.getMutationType()     : "-";
        return method + "|" + endpoint + "|" + actor + "|" + mutation;
    }

    private void loadSuppressions() {
        if (api == null) return;
        try {
            String saved = api.persistence().preferences().getString(SUPPRESSIONS_PREF_KEY);
            if (saved != null && !saved.isEmpty()) {
                java.util.Arrays.stream(saved.split("\\r?\\n"))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .forEach(suppressions::add);
            }
        } catch (Exception ignored) {
        }
    }

    private void saveSuppressions() {
        if (api == null) return;
        try {
            api.persistence().preferences().setString(SUPPRESSIONS_PREF_KEY, String.join("\n", suppressions));
        } catch (Exception ignored) {
        }
    }
}
