package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import com.acas.engine.ObjectManager;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import com.acas.store.ActorStore;
import com.acas.util.HttpUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ObjectMapPanel extends JPanel {


    private final MontoyaApi api;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final ActorStore store;
    private final ObjectManager objectManager;
    private final Timer refreshTimer;
    private final JTextArea detailsArea;
    private final JComboBox<String> endpointCombo;
    private final burp.api.montoya.ui.editor.HttpRequestEditor requestEditor;
    private final burp.api.montoya.ui.editor.HttpResponseEditor responseEditor;
    private final List<RowRecord> displayedRows = new ArrayList<>();
    private final List<RelatedMessage> currentMatches = new ArrayList<>();
    private boolean suppressEndpointEvents = false;

    public ObjectMapPanel(MontoyaApi api, ActorStore store, ObjectManager objectManager) {
        this.api = api;
        this.store = store;
        this.objectManager = objectManager;
        setLayout(new BorderLayout(0, 0));

        tableModel = new DefaultTableModel(new Object[]{"Owner", "Type", "Value", "Source", "Confidence"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onRowSelected();
            }
        });

        detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        detailsArea.setText("Select an Object Map row to view related request/response details.");

        endpointCombo = new JComboBox<>();
        endpointCombo.addActionListener(e -> {
            if (!suppressEndpointEvents) {
                showSelectedEndpoint();
            }
        });

        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();

        add(buildHeader(), BorderLayout.NORTH);
        add(buildMainContent(), BorderLayout.CENTER);

        refreshTimer = new Timer(3000, e -> refresh());
        refreshTimer.start();
        refresh();
    }

    private JComponent buildMainContent() {
        JScrollPane tableScroll = new JScrollPane(table);

        JPanel detailTop = new JPanel(new BorderLayout(6, 6));
        detailTop.setBorder(new EmptyBorder(6, 8, 4, 8));
        detailTop.add(new JScrollPane(detailsArea), BorderLayout.CENTER);

        JPanel endpointPicker = new JPanel(new BorderLayout(6, 0));
        endpointPicker.add(new JLabel("Related endpoint:"), BorderLayout.WEST);
        endpointPicker.add(endpointCombo, BorderLayout.CENTER);
        JPanel sendButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton sendRepeater = new JButton("Send to Repeater");
        JButton sendIntruder = new JButton("Send to Intruder");
        sendRepeater.addActionListener(e -> sendSelectedRelatedToRepeater());
        sendIntruder.addActionListener(e -> sendSelectedRelatedToIntruder());
        sendButtons.add(sendRepeater);
        sendButtons.add(sendIntruder);
        endpointPicker.add(sendButtons, BorderLayout.EAST);
        detailTop.add(endpointPicker, BorderLayout.SOUTH);

        JSplitPane reqRespSplit = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            requestEditor.uiComponent(),
            responseEditor.uiComponent()
        );
        reqRespSplit.setDividerLocation(500);

        JPanel detailBottom = new JPanel(new BorderLayout());
        detailBottom.add(reqRespSplit, BorderLayout.CENTER);

        JSplitPane detailSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, detailTop, detailBottom);
        detailSplit.setResizeWeight(0.28);
        detailSplit.setDividerLocation(140);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailSplit);
        mainSplit.setResizeWeight(0.45);
        mainSplit.setDividerLocation(220);
        return mainSplit;
    }

    private void refresh() {
        if (!isShowing()) return;
        SwingUtilities.invokeLater(() -> {
            RowRecord selectedBefore = null;
            int selectedViewRow = table.getSelectedRow();
            if (selectedViewRow >= 0) {
                int selectedModelRow = table.convertRowIndexToModel(selectedViewRow);
                if (selectedModelRow >= 0 && selectedModelRow < displayedRows.size()) {
                    selectedBefore = displayedRows.get(selectedModelRow);
                }
            }

            tableModel.setRowCount(0);
            displayedRows.clear();
            for (ActorProfile actor : store.getAllActors()) {
                String actorId = actor.getId();
                for (ObjectManager.ObjectEntry entry : objectManager.getObjectsForActor(actorId)) {
                    displayedRows.add(new RowRecord(actorId, actor.getName(), entry));
                    tableModel.addRow(new Object[]{
                        actor.getName(),
                        entry.type,
                        entry.value,
                        entry.source,
                        String.format("%.1f", entry.confidence)
                    });
                }
            }

            if (tableModel.getRowCount() == 0) {
                suppressEndpointEvents = true;
                endpointCombo.removeAllItems();
                suppressEndpointEvents = false;
                detailsArea.setText("Select an Object Map row to view related request/response details.");
                clearEditors();
                return;
            }

            int reselectionModelIndex = findMatchingRowIndex(selectedBefore);
            if (reselectionModelIndex >= 0) {
                int reselectionViewIndex = table.convertRowIndexToView(reselectionModelIndex);
                if (reselectionViewIndex >= 0) {
                    table.setRowSelectionInterval(reselectionViewIndex, reselectionViewIndex);
                    onRowSelected();
                    return;
                }
            }

            if (table.getSelectedRow() < 0) {
                table.setRowSelectionInterval(0, 0);
            }
            onRowSelected();
        });
    }

    private void onRowSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return;
        }

        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= displayedRows.size()) {
            return;
        }

        RowRecord row = displayedRows.get(modelRow);
        currentMatches.clear();
        currentMatches.addAll(findRelatedMessages(row));

        detailsArea.setText(buildDetailsText(row, currentMatches.size()));
        suppressEndpointEvents = true;
        endpointCombo.removeAllItems();
        if (currentMatches.isEmpty()) {
            endpointCombo.addItem("No related endpoint found");
            suppressEndpointEvents = false;
            clearEditors();
            return;
        }

        for (RelatedMessage item : currentMatches) {
            endpointCombo.addItem(item.label);
        }
        endpointCombo.setSelectedIndex(0);
        suppressEndpointEvents = false;
        showSelectedEndpoint();
    }

    private String buildDetailsText(RowRecord row, int relatedCount) {
        StringBuilder sb = new StringBuilder();
        sb.append("Owner: ").append(nullSafe(row.ownerName)).append("\n");
        sb.append("Type: ").append(nullSafe(row.entry.type)).append("\n");
        sb.append("Value: ").append(nullSafe(row.entry.value)).append("\n");
        sb.append("Source: ").append(nullSafe(row.entry.source)).append("\n");
        sb.append("Confidence: ").append(String.format("%.2f", row.entry.confidence)).append("\n");
        sb.append("Related Captured Requests: ").append(relatedCount);
        return sb.toString();
    }

    private void showSelectedEndpoint() {
        int idx = endpointCombo.getSelectedIndex();
        if (idx < 0 || idx >= currentMatches.size()) {
            return;
        }
        RelatedMessage item = currentMatches.get(idx);

        try {
            burp.api.montoya.http.message.requests.HttpRequest req =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    burp.api.montoya.core.ByteArray.byteArray(item.requestBytes)
                );
            req = HttpUtils.ensureRequestService(req, item.fallbackUrl);
            requestEditor.setRequest(req);
        } catch (Exception ignored) {
            clearEditors();
            return;
        }

        try {
            if (item.responseBytes != null && item.responseBytes.length > 0) {
                responseEditor.setResponse(
                    burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                        burp.api.montoya.core.ByteArray.byteArray(item.responseBytes)
                    )
                );
            } else {
                responseEditor.setResponse(
                    burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                        burp.api.montoya.core.ByteArray.byteArray(
                            "HTTP/1.1 204 No Content\r\nX-ACAS: Response not available\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1)
                        )
                    )
                );
            }
        } catch (Exception ignored) {
            // Request may exist even when response is null.
        }
    }

    private List<RelatedMessage> findRelatedMessages(RowRecord row) {
        List<RelatedMessage> out = new ArrayList<>();
        if (row == null || row.actorId == null || row.entry == null || row.entry.value == null) {
            return out;
        }

        Set<String> dedupe = new LinkedHashSet<>();
        String needle = row.entry.value;

        for (CapturedEndpoint endpoint : store.getCapturedEndpoints()) {
            if (endpoint == null || !row.actorId.equals(endpoint.getActorId())) {
                continue;
            }
            if (!containsValue(endpoint, needle)) {
                continue;
            }

            String label = "Captured: " + safeMethod(endpoint.getMethod()) + " " + safeUrl(endpoint.getOriginalUrl(), endpoint.getNormalizedPath());
            byte[] req = endpoint.getOriginalRequestBytes();
            byte[] resp = endpoint.getOriginalResponseBytes();
            if (req == null || req.length == 0) {
                continue;
            }
            String sig = label + "|" + new String(req, StandardCharsets.ISO_8859_1).hashCode();
            if (dedupe.add(sig)) {
                out.add(new RelatedMessage(label, req, resp, endpoint.getOriginalUrl()));
            }
        }

        store.getActorById(row.actorId).ifPresent(actor -> {
            for (ActorProfile.HistoryEntry history : actor.getCaptureHistory()) {
                if (history == null) {
                    continue;
                }
                if (!containsValue(history, needle)) {
                    continue;
                }

                byte[] req = toIsoBytes(history.request);
                if (req.length == 0) {
                    continue;
                }
                byte[] resp = toIsoBytes(history.response);
                String label = "History: " + safeMethod(history.method) + " " + safeUrl(history.url, history.url) + " [" + history.status + "]";
                String sig = label + "|" + new String(req, StandardCharsets.ISO_8859_1).hashCode();
                if (dedupe.add(sig)) {
                    out.add(new RelatedMessage(label, req, resp, history.url));
                }
            }
        });

        return out;
    }

    private void clearEditors() {
        try {
            requestEditor.setRequest(
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                    burp.api.montoya.core.ByteArray.byteArray(
                        "GET / HTTP/1.1\r\nHost: acas.local\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1)
                    )
                )
            );
        } catch (Exception ignored) {
        }
        try {
            responseEditor.setResponse(
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                    burp.api.montoya.core.ByteArray.byteArray(
                        "HTTP/1.1 204 No Content\r\nX-ACAS: No related endpoint selected\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1)
                    )
                )
            );
        } catch (Exception ignored) {
        }
    }

    private boolean containsValue(CapturedEndpoint endpoint, String value) {
        if (endpoint == null || value == null || value.isEmpty()) {
            return false;
        }

        String url = endpoint.getOriginalUrl();
        if (url != null && url.contains(value)) {
            return true;
        }

        String path = endpoint.getNormalizedPath();
        if (path != null && path.contains(value)) {
            return true;
        }

        byte[] req = endpoint.getOriginalRequestBytes();
        if (req != null && req.length > 0) {
            String reqText = new String(req, StandardCharsets.ISO_8859_1);
            if (reqText.contains(value)) {
                return true;
            }
        }

        byte[] resp = endpoint.getOriginalResponseBytes();
        if (resp != null && resp.length > 0) {
            String respText = new String(resp, StandardCharsets.ISO_8859_1);
            if (respText.contains(value)) {
                return true;
            }
        }

        return false;
    }

    private boolean containsValue(ActorProfile.HistoryEntry entry, String value) {
        if (entry == null || value == null || value.isEmpty()) {
            return false;
        }
        if (entry.url != null && entry.url.contains(value)) {
            return true;
        }
        if (entry.request != null && entry.request.contains(value)) {
            return true;
        }
        return entry.response != null && entry.response.contains(value);
    }

    private byte[] toIsoBytes(String text) {
        if (text == null) {
            return new byte[0];
        }
        return text.getBytes(StandardCharsets.ISO_8859_1);
    }

    private String safeMethod(String method) {
        return (method == null || method.trim().isEmpty()) ? "?" : method;
    }

    private String safeUrl(String primary, String fallback) {
        if (primary != null && !primary.trim().isEmpty()) {
            return primary;
        }
        if (fallback != null && !fallback.trim().isEmpty()) {
            return fallback;
        }
        return "(unknown URL)";
    }

    private String nullSafe(String input) {
        return input != null ? input : "";
    }

    private void sendSelectedRelatedToRepeater() {
        int idx = endpointCombo.getSelectedIndex();
        if (idx < 0 || idx >= currentMatches.size()) {
            return;
        }
        RelatedMessage item = currentMatches.get(idx);
        if (item.requestBytes == null || item.requestBytes.length == 0) {
            return;
        }
        burp.api.montoya.http.message.requests.HttpRequest req =
            burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                burp.api.montoya.core.ByteArray.byteArray(item.requestBytes)
            );
        req = HttpUtils.ensureRequestService(req, item.fallbackUrl);
        String title = HttpUtils.buildRepeaterTabName("ACAS ObjectMap", req, item.fallbackUrl, item.label);
        api.repeater().sendToRepeater(req, title);
    }

    private void sendSelectedRelatedToIntruder() {
        int idx = endpointCombo.getSelectedIndex();
        if (idx < 0 || idx >= currentMatches.size()) {
            return;
        }
        RelatedMessage item = currentMatches.get(idx);
        if (item.requestBytes == null || item.requestBytes.length == 0) {
            return;
        }
        burp.api.montoya.http.message.requests.HttpRequest req =
            burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                burp.api.montoya.core.ByteArray.byteArray(item.requestBytes)
            );
        req = HttpUtils.ensureRequestService(req, item.fallbackUrl);
        api.intruder().sendToIntruder(req);
    }

    private int findMatchingRowIndex(RowRecord target) {
        if (target == null) {
            return -1;
        }
        for (int i = 0; i < displayedRows.size(); i++) {
            RowRecord candidate = displayedRows.get(i);
            if (sameRow(candidate, target)) {
                return i;
            }
        }
        return -1;
    }

    private boolean sameRow(RowRecord a, RowRecord b) {
        if (a == null || b == null || a.entry == null || b.entry == null) {
            return false;
        }
        return java.util.Objects.equals(a.actorId, b.actorId)
            && java.util.Objects.equals(a.entry.type, b.entry.type)
            && java.util.Objects.equals(a.entry.value, b.entry.value)
            && java.util.Objects.equals(a.entry.source, b.entry.source);
    }

    private JPanel buildHeader() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(2, 16, 6, 16));
        return p;
    }

    private static final class RowRecord {
        private final String actorId;
        private final String ownerName;
        private final ObjectManager.ObjectEntry entry;

        private RowRecord(String actorId, String ownerName, ObjectManager.ObjectEntry entry) {
            this.actorId = actorId;
            this.ownerName = ownerName;
            this.entry = entry;
        }
    }

    private static final class RelatedMessage {
        private final String label;
        private final byte[] requestBytes;
        private final byte[] responseBytes;
        private final String fallbackUrl;

        private RelatedMessage(String label, byte[] requestBytes, byte[] responseBytes, String fallbackUrl) {
            this.label = label;
            this.requestBytes = requestBytes != null ? requestBytes : new byte[0];
            this.responseBytes = responseBytes != null ? responseBytes : new byte[0];
            this.fallbackUrl = fallbackUrl;
        }
    }

}
