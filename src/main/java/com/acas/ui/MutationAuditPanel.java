package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.acas.engine.HuntManager.MutationEvent;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

public class MutationAuditPanel extends JPanel {

    private static final int MAX_LOG_ROWS = 5000;
    
    private final MontoyaApi api;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextArea consoleLog;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    
    private final List<MutationEvent> eventBuffer = new ArrayList<>();
    private final Deque<String> textLogBuffer = new ArrayDeque<>();
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

    public MutationAuditPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(10, 12, 10, 12));

        // Top bar
        JPanel topBar = new JPanel(new BorderLayout());
        JLabel title = new JLabel("Global Execution Log (Transient, Max 5000)");
        title.setFont(new Font("SansSerif", Font.BOLD, 14));
        title.setForeground(new Color(200, 200, 200));
        
        JButton clearBtn = new JButton("Clear Log");
        clearBtn.addActionListener(e -> clearLog());
        
        topBar.add(title, BorderLayout.WEST);
        topBar.add(clearBtn, BorderLayout.EAST);
        add(topBar, BorderLayout.NORTH);

        // Center split (Table Top, Payload Bottom)
        tableModel = new DefaultTableModel(new Object[]{"Time", "Actor", "Mutation Code", "Description", "Target URL", "Status", "Length"}, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        table = new JTable(tableModel);
        table.setRowHeight(24);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFont(new Font("SansSerif", Font.PLAIN, 12));
        
        table.getColumnModel().getColumn(0).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);
        table.getColumnModel().getColumn(3).setPreferredWidth(250);
        table.getColumnModel().getColumn(4).setPreferredWidth(300);
        table.getColumnModel().getColumn(5).setPreferredWidth(60);
        table.getColumnModel().getColumn(6).setPreferredWidth(70);
        
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onRowSelected();
            }
        });

        // Console log
        consoleLog = new JTextArea();
        consoleLog.setEditable(false);
        consoleLog.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        consoleLog.setBackground(new Color(30, 30, 30));
        consoleLog.setForeground(new Color(180, 255, 180));
        JScrollPane consoleScroll = new JScrollPane(consoleLog);
        consoleScroll.setBorder(BorderFactory.createTitledBorder("Live Text Log"));

        // Editors
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();
        
        JSplitPane payloadSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responseEditor.uiComponent());
        payloadSplit.setResizeWeight(0.5);
        payloadSplit.setDividerLocation(400);
        payloadSplit.setBorder(BorderFactory.createTitledBorder("Inspect Selected Payload"));

        JSplitPane bottomSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, consoleScroll, payloadSplit);
        bottomSplit.setResizeWeight(0.3);
        bottomSplit.setDividerLocation(150);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), bottomSplit);
        mainSplit.setResizeWeight(0.5);
        mainSplit.setDividerLocation(300);

        add(mainSplit, BorderLayout.CENTER);
    }

    public void logMutationEvent(MutationEvent event) {
        SwingUtilities.invokeLater(() -> {
            // Manage buffers
            if (eventBuffer.size() >= MAX_LOG_ROWS) {
                eventBuffer.remove(0);
                tableModel.removeRow(0);
            }
            if (textLogBuffer.size() >= MAX_LOG_ROWS) {
                textLogBuffer.removeFirst();
            }

            eventBuffer.add(event);
            
            String timeStr = LocalTime.now().format(timeFormatter);
            tableModel.addRow(new Object[]{
                timeStr,
                event.actorName != null ? event.actorName : "Unknown",
                event.mutationType,
                event.mutationDescription,
                event.endpointMethod + " " + event.endpointPath,
                event.statusCode,
                event.responseLength
            });

            // Auto-scroll table if it was at the bottom
            int lastRow = table.getRowCount() - 1;
            boolean atBottom = true;
            if (table.getSelectedRow() >= 0 && table.getSelectedRow() != lastRow - 1) {
                atBottom = false;
            }
            if (atBottom) {
                table.scrollRectToVisible(table.getCellRect(lastRow, 0, true));
            }

            // Text console log
            String logLine = String.format("[%s] [Actor: %s] [%s] %s -> %s %s | Status: %d (%d bytes)",
                timeStr, 
                event.actorName != null ? event.actorName : "Anon",
                event.mutationType,
                event.mutationDescription,
                event.endpointMethod,
                event.endpointPath,
                event.statusCode,
                event.responseLength
            );
            
            textLogBuffer.addLast(logLine);
            consoleLog.setText(String.join("\n", textLogBuffer));
            
            // Auto-scroll text area
            consoleLog.setCaretPosition(consoleLog.getDocument().getLength());
        });
    }

    private void onRowSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        
        if (modelRow >= 0 && modelRow < eventBuffer.size()) {
            MutationEvent ev = eventBuffer.get(modelRow);
            if (ev.requestBytes != null) {
                requestEditor.setRequest(HttpRequest.httpRequest(burp.api.montoya.http.HttpService.httpService("https://dummy.acas"), ByteArray.byteArray(ev.requestBytes)));
            } else {
                requestEditor.setRequest(HttpRequest.httpRequest(""));
            }
            
            if (ev.responseBytes != null) {
                responseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(ev.responseBytes)));
            } else {
                responseEditor.setResponse(HttpResponse.httpResponse(""));
            }
        }
    }

    private void clearLog() {
        eventBuffer.clear();
        textLogBuffer.clear();
        tableModel.setRowCount(0);
        consoleLog.setText("");
        requestEditor.setRequest(HttpRequest.httpRequest(""));
        responseEditor.setResponse(HttpResponse.httpResponse(""));
    }
}
