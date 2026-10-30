package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.acas.util.HttpUtils;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;
import com.acas.engine.HuntManager;
import com.acas.store.ActorStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.datatransfer.StringSelection;
import java.awt.Toolkit;
import java.util.ArrayList;
import java.util.List;

public class ActorsPanel extends JPanel {

    private final MontoyaApi api;
    private final ActorStore store;
    private final HuntManager huntManager;
    private final com.acas.notification.NotificationService notifier;

    private final DefaultTableModel actorModel;
    private final JTable actorTable;

    private final DefaultTableModel historyModel;
    private final JTable historyTable;

    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;
    private final JLabel countLabel = new JLabel("0 actors");
    private final JLabel historyLabel = new JLabel("Captured History (0)");
    private final JButton recordToggleBtn = new JButton("Record selected");
    private boolean rebuildingActors;
    private final java.util.concurrent.atomic.AtomicBoolean refreshPending = new java.util.concurrent.atomic.AtomicBoolean();

    // Layout components
    private final JSplitPane horizontalViewer = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

    public ActorsPanel(MontoyaApi api, ActorStore store, HuntManager huntManager) {
        this(api,store,huntManager,null);
    }
    public ActorsPanel(MontoyaApi api, ActorStore store, HuntManager huntManager,com.acas.notification.NotificationService notifier) {
        this.notifier=notifier;
        this.api = api;
        this.store = store;
        this.huntManager = huntManager;
        setLayout(new BorderLayout(0, 0));

        // 1. Actor Table (Left)
        actorModel = new DefaultTableModel(new Object[]{"Monitor", "Name", "Recognised account", "Role", "Session", "Items", "Identity lookup"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        actorTable = new NativeHistoryTable(actorModel);
        ((NativeHistoryTable) actorTable).setActorColors(row -> {
            ActorProfile actor = store.getActor(getActorIdAtRow(row));
            return actor == null ? null : safeColor(actor.getColor(), null);
        });
        AcasTheme.styleTable(actorTable);
        actorTable.getColumnModel().getColumn(0).setCellRenderer(new ColorRenderer());
        actorTable.getColumnModel().getColumn(0).setMinWidth(90);
        actorTable.getColumnModel().getColumn(0).setPreferredWidth(100); // Colour + status
        actorTable.getColumnModel().getColumn(1).setPreferredWidth(100); // Name
        actorTable.getColumnModel().getColumn(2).setPreferredWidth(160); // Recognised account
        actorTable.getColumnModel().getColumn(2).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer(){
            @Override public Component getTableCellRendererComponent(JTable table,Object value,boolean selected,boolean focus,int row,int col){
                putClientProperty("html.disable",Boolean.TRUE);
                super.getTableCellRendererComponent(table,value,selected,focus,row,col);
                setToolTipText("Recognised account: "+String.valueOf(value));return this;
            }
        });
        actorTable.getColumnModel().getColumn(3).setPreferredWidth(80); // Role
        actorTable.getColumnModel().getColumn(4).setPreferredWidth(90); // Session
        actorTable.getColumnModel().getColumn(5).setPreferredWidth(50); // Items
        actorTable.getColumnModel().getColumn(6).setPreferredWidth(160); // Identity lookup
        actorTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && !rebuildingActors) { updateHistoryView(); updateRecordingButton(); }
        });

        actorTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    inspectSelectedActor();
                }
            }
            @Override public void mousePressed(MouseEvent e) { if (e.isPopupTrigger()) showActorContextMenu(e); }
            @Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) showActorContextMenu(e); }
        });

        // 2. History Table (Right-Top)
        historyModel = new DefaultTableModel(new Object[]{"#", "URL", "Status", "Length", "Method"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        historyTable = new NativeHistoryTable(historyModel);
        ((NativeHistoryTable) historyTable).setActorColors(row -> {
            ActorProfile actor = store.getActor(getActorIdAtRow(actorTable.getSelectedRow()));
            return actor == null ? null : safeColor(actor.getColor(), null);
        });
        AcasTheme.styleTable(historyTable);
        historyTable.setAutoCreateRowSorter(true);
        historyTable.getColumnModel().getColumn(0).setPreferredWidth(40); // #
        historyTable.getColumnModel().getColumn(1).setPreferredWidth(400); // URL
        historyTable.getColumnModel().getColumn(2).setPreferredWidth(50); // Status
        historyTable.getColumnModel().getColumn(3).setPreferredWidth(60); // Length
        historyTable.getColumnModel().getColumn(4).setPreferredWidth(60); // Method
        
        historyTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) updateRequestViewer();
        });

        historyTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { if (e.isPopupTrigger()) showHistoryContextMenu(e); }
            @Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) showHistoryContextMenu(e); }
        });

        // 3. Editors & Layouts
        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();
        
        // Setup Horizontal Layout
        horizontalViewer.setLeftComponent(requestViewer.uiComponent());
        horizontalViewer.setRightComponent(responseViewer.uiComponent());
        horizontalViewer.setDividerLocation(400);

        JPopupMenu viewerMenu = new JPopupMenu();
        JMenuItem viewerRepeater = new JMenuItem("Send Current Viewer Request to Repeater");
        JMenuItem viewerIntruder = new JMenuItem("Send Current Viewer Request to Intruder");
        viewerRepeater.addActionListener(e -> sendSelectedToRepeater());
        viewerIntruder.addActionListener(e -> sendSelectedToIntruder());
        viewerMenu.add(viewerRepeater);
        viewerMenu.add(viewerIntruder);
        if (requestViewer.uiComponent() instanceof JComponent) {
            ((JComponent) requestViewer.uiComponent()).setComponentPopupMenu(viewerMenu);
        }

        // Layout Assembly
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setDividerLocation(440);

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(buildActorToolbar(), BorderLayout.NORTH); // New Pro Toolbar
        leftPanel.add(new JScrollPane(actorTable), BorderLayout.CENTER);
        
        // Remove bottom controls - they are now in the toolbar

        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.add(buildHistoryToolbar(), BorderLayout.NORTH);

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setTopComponent(new JScrollPane(historyTable));
        rightSplit.setBottomComponent(horizontalViewer);
        rightSplit.setDividerLocation(200);
        rightPanel.add(rightSplit, BorderLayout.CENTER);

        mainSplit.setLeftComponent(leftPanel);
        mainSplit.setRightComponent(rightPanel);
        add(mainSplit, BorderLayout.CENTER);

        setupShortcuts();
        store.addChangeListener(this::refresh);
        refresh();
    }

    private JComponent buildActorToolbar() {
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setBorder(new EmptyBorder(6, 8, 6, 8));

        JButton colorBtn = new JButton("Color");
        JButton deleteBtn = new JButton("Delete");
        AcasTheme.styleButton(colorBtn);
        AcasTheme.styleButton(deleteBtn);

        // Record toggle keeps its colored state (set in refresh()).
        recordToggleBtn.setForeground(Color.WHITE);
        recordToggleBtn.setFont(AcasTheme.UI_BOLD);
        recordToggleBtn.setFocusPainted(false);
        recordToggleBtn.setBorder(BorderFactory.createEmptyBorder(5, 14, 5, 14));
        recordToggleBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        colorBtn.addActionListener(e -> changeActorColor());
        recordToggleBtn.addActionListener(e -> toggleRecording());
        deleteBtn.addActionListener(e -> deleteSelected());

        JButton sendSession=new JButton("⚡ Send updated session to Hermes");
        sendSession.setName("sendUpdatedSession");
        sendSession.setFont(AcasTheme.UI_BOLD);
        sendSession.setBackground(new Color(88, 101, 242));
        sendSession.setForeground(Color.WHITE);
        sendSession.setFocusPainted(false);
        sendSession.setBorder(BorderFactory.createEmptyBorder(5, 12, 5, 12));
        sendSession.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        sendSession.setEnabled(notifier!=null);
        sendSession.setToolTipText("Send fresh session credentials for this actor directly to Hermes via Discord.");
        sendSession.addActionListener(e -> {
            int row=actorTable.getSelectedRow();
            if(row<0){JOptionPane.showMessageDialog(this,"Select the actor whose updated session should be sent.");return;}
            new HermesExportDialog(this,api,store,null,notifier,true,getActorIdAtRow(row)).setVisible(true);
        });
        toolbar.add(sendSession);
        toolbar.add(Box.createHorizontalStrut(6));
        toolbar.add(recordToggleBtn);
        JButton stopAllBtn=new JButton("Stop all capture");
        stopAllBtn.setName("stopAllCapture");
        stopAllBtn.addActionListener(e -> stopRecording());
        toolbar.add(stopAllBtn);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(colorBtn);
        toolbar.add(Box.createHorizontalStrut(6));
        toolbar.add(deleteBtn);
        toolbar.add(Box.createHorizontalGlue());
        countLabel.setFont(AcasTheme.UI_SMALL);
        countLabel.setForeground(AcasTheme.MUTED);
        toolbar.add(countLabel);

        return toolbar;
    }

    private void toggleRecording() {
        int row=actorTable.getSelectedRow();
        if(row<0) {JOptionPane.showMessageDialog(this,"Select the actor whose traffic you want to record.");return;}
        String id=getActorIdAtRow(row);
        if(java.util.Objects.equals(id,store.getActiveActorId()))stopRecording();
        else setActiveActor(id);
        updateRecordingButton();
    }

    private JPanel buildHistoryToolbar() {
        JPanel historyHeader = new JPanel(new BorderLayout());
        historyHeader.setBorder(new EmptyBorder(4, 10, 4, 10));
        
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        left.add(historyLabel);
        
        historyHeader.add(left, BorderLayout.WEST);
        return historyHeader;
    }

    private void changeActorColor() {
        int row = actorTable.getSelectedRow();
        if (row < 0) return;
        String id = getActorIdAtRow(row);
        store.getActorById(id).ifPresent(actor -> {
            if (actor.getPwnfoxColor() != null) {
                JOptionPane.showMessageDialog(this, "Colour follows X-PwnFox-Color: " + actor.getPwnfoxColor()
                    + ". Refresh the actor session from a different container to change it.");
                return;
            }
            Color c = JColorChooser.showDialog(this, "Choose Actor Color", safeColor(actor.getColor(), new Color(0x66, 0x66, 0x66)));
            if (c != null) {
                String hex = String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
                actor.setColor(hex);
                store.updateActor(actor);
                refresh();
                actorTable.repaint();
            }
        });
    }

    private void updateSelectedActorCookie() {
        int row = actorTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(this, "Select an actor first.", "ACAS", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String id = getActorIdAtRow(row);
        if (id == null) return;

        store.getActorById(id).ifPresent(actor -> {
            String currentCookie = findHeaderValue(actor, "Cookie");
            String updated = (String) JOptionPane.showInputDialog(
                this,
                "Paste the refreshed Cookie header value. Leave blank to remove the Cookie header.",
                "Update Cookie for " + actor.getName(),
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                currentCookie != null ? currentCookie : ""
            );

            if (updated == null) {
                return;
            }

            String normalized = normalizeCookieHeaderValue(updated);
            List<String[]> headers = actor.getHeaders() == null ? new ArrayList<>() : new ArrayList<>(actor.getHeaders());
            headers.removeIf(header -> header != null && header.length > 0 && header[0] != null && "cookie".equalsIgnoreCase(header[0].trim()));
            if (!normalized.isEmpty()) {
                headers.add(new String[]{"Cookie", normalized});
            }

            actor.setHeaders(headers);
            store.updateActor(actor);
            refresh();
        });
    }

    private void rebindSelectedActorOrigin(String actorId) {
        if (actorId == null) return;
        ActorProfile actor = store.getActor(actorId);
        if (actor == null) return;
        String current = "";
        try { current = com.acas.util.CanonicalOrigin.actor(actor); }
        catch (RuntimeException ignored) { }
        String origin = (String) JOptionPane.showInputDialog(this,
            "Enter the new exact HTTP(S) origin.\nThis clears identity recognition and marks this actor's captures stale.",
            "ACAS - Rebind Actor Origin", JOptionPane.WARNING_MESSAGE, null, null, current);
        if (origin == null || origin.isBlank()) return;
        int choice = JOptionPane.showConfirmDialog(this,
            "Rebind " + actor.getName() + " from " + (current.isBlank() ? "(unresolved)" : current) + " to " + origin.trim()
                + "?\n\nSessions, identity proofs and replay eligibility will be invalidated until verified again.",
            "Confirm Origin Rebind", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) return;
        try {
            store.rebindActorOrigin(actorId, origin.trim(), true);
            refresh();
        } catch (RuntimeException invalid) {
            JOptionPane.showMessageDialog(this, invalid.getMessage(), "ACAS - Invalid Origin", JOptionPane.ERROR_MESSAGE);
        }
    }

    private String findHeaderValue(ActorProfile actor, String headerName) {
        if (actor == null || actor.getHeaders() == null || headerName == null) {
            return null;
        }

        for (String[] header : actor.getHeaders()) {
            if (header == null || header.length < 2 || header[0] == null) {
                continue;
            }
            if (headerName.equalsIgnoreCase(header[0].trim())) {
                return header[1];
            }
        }
        return null;
    }

    private String normalizeCookieHeaderValue(String value) {
        if (value == null) {
            return "";
        }

        String normalized = value.trim();
        if (normalized.regionMatches(true, 0, "Cookie:", 0, 7)) {
            normalized = normalized.substring(7).trim();
        }
        return normalized;
    }

    private void setActiveActor() {
        int row = actorTable.getSelectedRow();
        if (row < 0) return;
        String selectedId = getActorIdAtRow(row);
        setActiveActor(selectedId);
    }

    private void setActiveActor(String id) {
        if (id == null) return;

        store.setActiveActorId(id);
    }

    private void stopRecording() {
        store.stopAllCapture();
    }

    private void setupShortcuts() {
        InputMap im = historyTable.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap am = historyTable.getActionMap();
        
        im.put(KeyStroke.getKeyStroke("control R"), "sendToRepeater");
        am.put("sendToRepeater", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { sendSelectedToRepeater(); }
        });

        im.put(KeyStroke.getKeyStroke("control I"), "sendToIntruder");
        am.put("sendToIntruder", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { sendSelectedToIntruder(); }
        });
    }

    private void showHistoryContextMenu(MouseEvent e) {
        int row = historyTable.rowAtPoint(e.getPoint());
        if (row < 0) return;
        historyTable.setRowSelectionInterval(row, row);
        
        JPopupMenu menu = new JPopupMenu();
        JMenuItem rep = new JMenuItem("Send to Repeater (Ctrl+R)");
        JMenuItem intr = new JMenuItem("Send to Intruder (Ctrl+I)");
        JMenuItem comReq = new JMenuItem("Send to Comparer (request)");
        JMenuItem comRes = new JMenuItem("Send to Comparer (response)");
        JMenuItem updateSession = new JMenuItem("Update Actor Session (use this request's cookies/tokens)");
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        JMenuItem deleteItem = new JMenuItem("Delete Item");

        rep.addActionListener(al -> sendSelectedToRepeater());
        intr.addActionListener(al -> sendSelectedToIntruder());
        updateSession.addActionListener(al -> updateActorSessionFromHistory());
        comReq.addActionListener(al -> sendSelectedToComparer(true));
        comRes.addActionListener(al -> sendSelectedToComparer(false));
        copyUrl.addActionListener(al -> {
            getSelectedHistoryEntry(entry -> {
                StringSelection selection = new StringSelection(entry.url);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            });
        });
        deleteItem.addActionListener(al -> deleteSelectedHistory());

        menu.add(rep); menu.add(intr);
        menu.add(new JSeparator());
        menu.add(updateSession);
        menu.add(new JSeparator());
        menu.add(comReq); menu.add(comRes);
        menu.add(new JSeparator());
        menu.add(copyUrl);
        menu.add(deleteItem);
        menu.show(historyTable, e.getX(), e.getY());
    }

    private void updateActorSessionFromHistory() {
        int actorRow = actorTable.getSelectedRow();
        if (actorRow < 0) return;
        String actorId = getActorIdAtRow(actorRow);
        if (actorId == null) return;
        getSelectedHistoryEntry(entry -> {
            try {
                HttpRequest req = HttpRequest.httpRequest(entry.request);
                boolean ok = store.updateActorSession(actorId, req);
                refresh();
                updateHistoryView();
                JOptionPane.showMessageDialog(this,
                    ok ? "Actor session updated from this request's identity headers." : "No change — actor not found.",
                    "ACAS — Update Session", ok ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Update failed: " + ex.getMessage(), "ACAS", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    private void sendSelectedToRepeater() {
        getSelectedHistoryEntry(entry -> {
            HttpRequest req = HttpRequest.httpRequest(entry.request);
            HttpRequest prepared = HttpUtils.ensureRequestService(req, entry.url);
            String title = HttpUtils.buildRepeaterTabName("ACAS Actors", prepared, entry.url, null);
            api.repeater().sendToRepeater(prepared, title);
        });
    }
    private void sendSelectedToIntruder() {
        getSelectedHistoryEntry(entry -> {
            HttpRequest req = HttpRequest.httpRequest(entry.request);
            api.intruder().sendToIntruder(HttpUtils.ensureRequestService(req, entry.url));
        });
    }
    private void sendSelectedToComparer(boolean isRequest) {
        getSelectedHistoryEntry(entry -> {
            HttpRequest req = HttpRequest.httpRequest(entry.request);
            HttpResponse res = HttpResponse.httpResponse(entry.response);
            api.comparer().sendToComparer(isRequest ? req.toByteArray() : res.toByteArray());
        });
    }

    private void deleteSelectedHistory() {
        int actorRow = actorTable.getSelectedRow();
        int histRow = historyTable.getSelectedRow();
        if (actorRow < 0 || histRow < 0) return;
        int modelRow = historyTable.convertRowIndexToModel(histRow);
        store.deleteHistoryEntry(getActorIdAtRow(actorRow), modelRow);
        updateHistoryView();
    }

    private void getSelectedHistoryEntry(java.util.function.Consumer<ActorProfile.HistoryEntry> consumer) {
        int actorRow = actorTable.getSelectedRow();
        int histRow = historyTable.getSelectedRow();
        if (actorRow < 0 || histRow < 0) return;
        
        int modelRow = historyTable.convertRowIndexToModel(histRow);
        store.getActorById(getActorIdAtRow(actorRow)).ifPresent(actor -> {
            if (modelRow < actor.getCaptureHistory().size()) {
                ActorProfile.HistoryEntry entry = actor.getCaptureHistory().get(modelRow);
                consumer.accept(entry);
            }
        });
    }

    private String shownHistoryActor;
    private List<ActorProfile.HistoryEntry> shownHistory=java.util.List.of();
    private void updateHistoryView() {
        String selected=getActorIdAtRow(actorTable.getSelectedRow());
        ActorProfile selectedActor=store.getActor(selected);
        List<ActorProfile.HistoryEntry> snapshot=selectedActor==null?java.util.List.of():new java.util.ArrayList<>(selectedActor.getCaptureHistory());
        if(java.util.Objects.equals(selected,shownHistoryActor) && snapshot.equals(shownHistory))return;
        shownHistoryActor=selected;shownHistory=snapshot;
        historyModel.setRowCount(0);
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);
        int row = actorTable.getSelectedRow();
        if (row < 0) {
            historyLabel.setText("Captured History (0)");
            return;
        }
        store.getActorById(getActorIdAtRow(row)).ifPresent(actor -> {
            List<ActorProfile.HistoryEntry> history = actor.getCaptureHistory();
            historyLabel.setText("Captured History (" + history.size() + ") for " + actor.getName());
            for (int i = 0; i < history.size(); i++) {
                ActorProfile.HistoryEntry entry = history.get(i);
                historyModel.addRow(new Object[]{i + 1, entry.url, entry.status, entry.length, entry.method});
            }
        });
    }

    private void updateRequestViewer() {
        int actorRow = actorTable.getSelectedRow();
        int histRow = historyTable.getSelectedRow();
        if (actorRow < 0 || histRow < 0) return;
        int modelRow = historyTable.convertRowIndexToModel(histRow);
        store.getActorById(getActorIdAtRow(actorRow)).ifPresent(actor -> {
            if (modelRow < actor.getCaptureHistory().size()) {
                ActorProfile.HistoryEntry entry = actor.getCaptureHistory().get(modelRow);
                HttpRequest req = HttpRequest.httpRequest(entry.request);
                req = HttpUtils.ensureRequestService(req, entry.url);
                requestViewer.setRequest(req);
                responseViewer.setResponse(HttpResponse.httpResponse(entry.response));
            }
        });
    }

    private void deleteSelected() {
        int row = actorTable.getSelectedRow();
        if (row >= 0) {
            String id = getActorIdAtRow(row);
            String actorName = store.getActorById(id).map(ActorProfile::getName).orElse("Unknown");
            int choice = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to delete actor '" + actorName + "'?\nThis will remove their profile and all associated history.",
                "ACAS - Delete Actor", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice == JOptionPane.YES_OPTION) {
                store.removeActor(id);
                // Keep the Result Matrix in sync — drop this actor's findings too.
                Container parent = getParent();
                while (parent != null && !(parent instanceof AcasPanel)) parent = parent.getParent();
                if (parent instanceof AcasPanel) {
                    ((AcasPanel) parent).onActorDeleted(actorName);
                }
            }
        }
    }

    private void showActorContextMenu(MouseEvent e) {
        int row = actorTable.rowAtPoint(e.getPoint());
        if (row < 0) return;
        actorTable.setRowSelectionInterval(row, row);
        
        String id = getActorIdAtRow(row);
        ActorProfile actor = id != null ? store.getActorById(id).orElse(null) : null;
        String actorName = actor != null ? actor.getName() : "Actor";
        boolean isCurrentActive = java.util.Objects.equals(id, store.getActiveActorId());
        
        JPopupMenu menu = new JPopupMenu();
        JMenuItem recordToggle = new JMenuItem(isCurrentActive ? "⏹ Stop Recording " + actorName : "⏺ Record Activity (" + actorName + ")");
        JMenuItem sendHermes = new JMenuItem("⚡ Send updated session to Hermes");
        JMenuItem cookie = new JMenuItem("Update Cookie / Session...");
        JMenuItem clearHistory = new JMenuItem("Clear Captured History");
        JMenuItem delete = new JMenuItem("Delete Actor");
        
        recordToggle.addActionListener(al -> {
            if (isCurrentActive) {
                stopRecording();
            } else {
                setActiveActor(id);
            }
            updateRecordingButton();
        });
        sendHermes.addActionListener(al -> {
            new HermesExportDialog(this, api, store, null, notifier, true, id).setVisible(true);
        });
        cookie.addActionListener(al -> updateSelectedActorCookie());
        clearHistory.addActionListener(al -> {
            int choice = JOptionPane.showConfirmDialog(this, 
                "Are you sure you want to clear ALL captured history for " + actorName + "?",
                "ACAS - Clear History", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice == JOptionPane.YES_OPTION) {
                store.clearActorHistory(id);
                updateHistoryView();
            }
        });
        delete.addActionListener(al -> deleteSelected());
        
        menu.add(recordToggle);
        menu.addSeparator();
        menu.add(sendHermes);
        menu.add(cookie);
        menu.addSeparator();
        menu.add(clearHistory);
        menu.add(delete);
        menu.show(actorTable, e.getX(), e.getY());
    }

    /**
     * Auto Re-Hunt on Session Refresh:
     * When user updates an actor's session, check for ERR_SESSION_EXPIRED endpoints
     * and offer to re-hunt them.
     */
    private void checkAutoReHunt(String actorId) {
        if (actorId == null) return;
        
        List<CapturedEndpoint> failedEndpoints = new ArrayList<>();
        for (CapturedEndpoint ep : store.getCapturedEndpoints()) {
            if (ep.getActorId().equals(actorId) && 
                ep.getHuntStatus() == CapturedEndpoint.HuntStatus.ERROR &&
                ep.getHuntErrorCode().contains("SESSION_EXPIRED")) {
                failedEndpoints.add(ep);
            }
        }

        // Also include STALE endpoints for this actor
        for (CapturedEndpoint ep : store.getCapturedEndpoints()) {
            if (ep.getActorId().equals(actorId) && 
                ep.getHuntStatus() == CapturedEndpoint.HuntStatus.STALE &&
                !failedEndpoints.contains(ep)) {
                failedEndpoints.add(ep);
            }
        }

        if (failedEndpoints.isEmpty()) {
            JOptionPane.showMessageDialog(this, 
                "No failed or stale endpoints found for this actor.",
                "ACAS — Re-Hunt Check", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String actorName = store.getActorById(actorId).map(ActorProfile::getName).orElse("Unknown");
        int choice = JOptionPane.showConfirmDialog(this, 
            "Actor '" + actorName + "' has " + failedEndpoints.size() + " endpoint(s) that failed\n" +
            "due to expired session or are stale.\n\n" +
            "Re-hunt them now with the updated session?",
            "ACAS — Re-Hunt Failed Endpoints", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);

        if (choice == JOptionPane.YES_OPTION) {
            // Navigate to Hunt Hub and start hunt
            Container parent = getParent();
            while (parent != null && !(parent instanceof AcasPanel)) parent = parent.getParent();
            if (parent instanceof AcasPanel) {
                AcasPanel acas = (AcasPanel) parent;
                acas.switchToHuntHub();
                huntManager.startHunt(failedEndpoints,
                    msg -> acas.getHuntHubPanel().addLog(msg),
                    event -> acas.getHuntHubPanel().addMutationEvent(event),
                    progress -> { },
                    () -> { }
                );
            }
        }
    }

    private void inspectSelectedActor() {
        int row = actorTable.getSelectedRow();
        if (row < 0) return;
        String id = getActorIdAtRow(row);
        store.getActorById(id).ifPresent(actor -> {
            Window parent = SwingUtilities.getWindowAncestor(this);
            ActorInspectionDialog dialog = new ActorInspectionDialog(parent, api, actor);
            dialog.setVisible(true);
        });
    }

    /** Decode a hex color, tolerating null/blank/invalid values (PwnFox names, 8-digit, etc.). */
    static Color safeColor(String hex, Color fallback) {
        if (hex == null || hex.isBlank()) return fallback;
        try {
            return Color.decode(hex.trim());
        } catch (Exception e) {
            return fallback;
        }
    }

    private String getActorIdAtRow(int row) {
        List<ActorProfile> actors = store.getAllActors();
        return (row >= 0 && row < actors.size()) ? actors.get(row).getId() : null;
    }

    private String sessionStatusText(ActorProfile.VerificationStatus status) {
        if (status == null) return "–";
        switch (status) {
            case VERIFIED: return "✓ live";
            case EXPIRED:  return "⚠ expired";
            case UNVERIFIED: return "unverified";
            default: return "–";
        }
    }

    public void refresh() {
        if(!refreshPending.compareAndSet(false,true))return;
        SwingUtilities.invokeLater(() -> {
            refreshPending.set(false);
            int selectedRow = actorTable.getSelectedRow();
            rebuildingActors=true;
            try {
            actorModel.setRowCount(0);
            List<ActorProfile> actors = store.getAllActors();
            String activeId = store.getActiveActorId();


            actorTable.setRowHeight(28);
            for (ActorProfile actor : actors) {
                String status = actor.isRecording() ? "REC " : "";
                if (actor.hasCredentials()) status += "READY";
                actorModel.addRow(new Object[]{
                    new Object[]{actor.getColor(), status},
                    actor.getName(),
                    com.acas.export.ActorIdentityRules.recognisedAccount(store,actor),
                    actor.getRole(),
                    sessionStatusText(actor.getVerificationStatus()),
                    actor.getCaptureHistory().size(),
                    actor.getIdentityLookupStatus()
                });
            }
            countLabel.setText(actors.size() + " actor(s)");
            if (selectedRow >= 0 && selectedRow < actors.size()) {
                actorTable.setRowSelectionInterval(selectedRow, selectedRow);
            }
            } finally {rebuildingActors=false;}
            updateHistoryView();
            updateRecordingButton();
        });
    }
    private void updateRecordingButton() {
        String selected=getActorIdAtRow(actorTable.getSelectedRow());
        boolean recording=selected!=null && selected.equals(store.getActiveActorId());
        recordToggleBtn.setText(recording?"Stop recording":"Record selected");
        recordToggleBtn.setEnabled(selected!=null);
        recordToggleBtn.setBackground(recording?new Color(220,38,38):new Color(239,99,52));
        recordToggleBtn.setToolTipText(recording?"Stop automatic capture and probes":"Record only this actor's matching traffic");
    }
    private static class ColorRenderer extends javax.swing.table.DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, "", isSelected, hasFocus, row, column);
            setIcon(null);
            setToolTipText(null);
            setIconTextGap(8);
            setHorizontalAlignment(SwingConstants.LEFT);
            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 4));
            if (value instanceof Object[]) {
                Object[] data = (Object[]) value;
                String hex = (String) (data[0] != null ? data[0] : "#666666");
                String statusText = (String) data[1];
                Color color = safeColor(hex, new Color(0x66, 0x66, 0x66));
                // Paint the swatch directly: font glyphs and nested renderer layouts
                // can hide the colour under Burp's look and feel.
                setIcon(new Icon() {
                    public int getIconWidth() { return 16; }
                    public int getIconHeight() { return 16; }
                    public void paintIcon(Component c, Graphics g, int x, int y) {
                        Graphics2D graphics = (Graphics2D) g.create();
                        try {
                            graphics.setColor(color);
                            graphics.fillRoundRect(x, y, 15, 15, 4, 4);
                            graphics.setColor(table.getForeground());
                            graphics.drawRoundRect(x, y, 15, 15, 4, 4);
                        } finally {
                            graphics.dispose();
                        }
                    }
                });
                setText(statusText.contains("REC") ? "REC" : statusText.contains("READY") ? "Ready" : "Idle");
                setToolTipText("Actor colour: " + hex + " — " + getText());
            }
            return this;
        }
    }
}
