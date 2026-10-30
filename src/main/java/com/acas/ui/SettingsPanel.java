package com.acas.ui;

import com.acas.engine.MutationDefinition;
import com.acas.engine.HuntManager;
import com.acas.engine.MutationRegistry;
import com.acas.engine.SeverityClassifier;
import com.acas.notification.NotificationService;
import com.acas.model.WorkspaceBackup;
import com.acas.store.ActorStore;
import com.google.gson.Gson;

import javax.swing.filechooser.FileNameExtensionFilter;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class SettingsPanel extends JPanel {


    private final ActorStore store;
    private final HuntManager huntManager;
    private final MutationRegistry mutationRegistry;
    private final SeverityClassifier severityClassifier;
    private final NotificationService notifier;
    private final Gson gson = new Gson();

    private final JPasswordField tgBotToken = new JPasswordField(30);
    private final JTextField tgChatId = new JTextField(20);
    private final JPasswordField hermesTgBotToken = new JPasswordField(30);
    private final JTextField hermesTgChatId = new JTextField(20);
    private final JPasswordField discordWebhook = new JPasswordField(40);
    private final JComboBox<String> hermesDestinations = new JComboBox<>(new String[]{"Telegram only", "Discord only", "Telegram and Discord"});
    private boolean loadingDestination;

    private final JRadioButton triggerStatusDiff = new JRadioButton("Status code difference");
    private final JRadioButton triggerAnyDiff = new JRadioButton("Any difference (status or length)");
    private final JRadioButton triggerManual = new JRadioButton("Manual only");

    private final String[] credentialKeys={"session_headers","csrf_headers","context_headers","session_cookies","csrf_cookies"};
    private final String[] credentialLabels={"Additional session headers:","Additional CSRF headers:","Additional account context headers:","Additional session cookie names:","Additional CSRF cookie names:"};
    private final JTextField[] credentialFields={new JTextField(40),new JTextField(40),new JTextField(40),new JTextField(40),new JTextField(40)};
    private final JTextArea blacklistArea = new JTextArea(14, 50);
    private final JCheckBox useBurpScope = new JCheckBox("Use Burp Target Scope");
    private final JCheckBox matrixOnlyHits = new JCheckBox("Result Matrix: record only hits (skip secure / Info rows)");

    public SettingsPanel(ActorStore store, HuntManager huntManager, MutationRegistry mutationRegistry, SeverityClassifier severityClassifier, NotificationService notifier) {
        this.store = store;
        this.huntManager = huntManager;
        this.mutationRegistry = mutationRegistry;
        this.severityClassifier = severityClassifier;
        this.notifier = notifier;
        setLayout(new BorderLayout());
        add(new JScrollPane(buildForm()), BorderLayout.CENTER);
        add(buildButtons(), BorderLayout.SOUTH);
        loadSettings();
        hermesDestinations.addActionListener(e->{
            if(!loadingDestination)store.setGlobalSetting("hermes_export_destination_explicit","true");
        });
    }

    private JPanel buildForm() {
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.setBorder(new EmptyBorder(12, 16, 12, 16));

        // 1. Hermes & Discord Integration (Priority #1)
        JPanel hermesPanel = card("Hermes / Discord Integration");
        hermesPanel.add(formRow("Discord Webhook:", discordWebhook));
        hermesPanel.add(Box.createVerticalStrut(6));
        
        JPanel dcBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        dcBtnRow.setAlignmentX(LEFT_ALIGNMENT);
        JButton testDc = new JButton("Test Discord Connection"); 
        AcasTheme.styleButton(testDc);
        testDc.addActionListener(e -> {
            saveSettings();
            NotificationFeedback.send(this, testDc, () -> notifier.sendDiscordReport("ACAS connected successfully!"));
        });
        dcBtnRow.add(testDc);
        hermesPanel.add(dcBtnRow);

        JLabel dcHelp = new JLabel("Hermes runs on your VPS and listens for security test jobs sent to this Discord webhook.");
        dcHelp.setFont(new Font("SansSerif", Font.ITALIC, 11));
        dcHelp.setBorder(new EmptyBorder(6, 0, 4, 0));
        hermesPanel.add(dcHelp);

        hermesPanel.add(Box.createVerticalStrut(6));
        hermesPanel.add(formRow("Delivery Mode:", hermesDestinations));
        form.add(hermesPanel);
        form.add(Box.createVerticalStrut(12));

        // 2. Scope & Traffic Capture Rules
        JPanel scopePanel = card("Scope & Traffic Filtering");
        useBurpScope.setFont(AcasTheme.UI_BOLD);
        scopePanel.add(useBurpScope);
        JLabel scopeHelp = new JLabel("When checked, only requests inside your Burp Target Scope are captured and attributed to actors.");
        scopeHelp.setFont(new Font("SansSerif", Font.ITALIC, 11));
        scopeHelp.setBorder(new EmptyBorder(4, 0, 8, 0));
        scopePanel.add(scopeHelp);

        scopePanel.add(matrixOnlyHits);
        form.add(scopePanel);
        form.add(Box.createVerticalStrut(12));

        // 3. Custom Session & CSRF Header Recognition
        JPanel credentialPanel = card("Custom Session & CSRF Recognition");
        JLabel credHelp = new JLabel("Standard headers (Cookie, Authorization, Bearer, etc.) are recognized automatically. Add custom headers below:");
        credHelp.setFont(new Font("SansSerif", Font.PLAIN, 11));
        credHelp.setBorder(new EmptyBorder(0, 0, 6, 0));
        credentialPanel.add(credHelp);
        for (int i = 0; i < credentialKeys.length; i++) {
            credentialPanel.add(formRow(credentialLabels[i], credentialFields[i]));
            credentialPanel.add(Box.createVerticalStrut(4));
        }
        form.add(credentialPanel);
        form.add(Box.createVerticalStrut(12));

        // 4. Capture Blacklist (Clean & compact)
        JPanel blPanel = card("Traffic Blacklist (Skip static assets, analytics, noise)");
        blacklistArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane blScroll = new JScrollPane(blacklistArea);
        blScroll.setAlignmentX(LEFT_ALIGNMENT);
        blScroll.setPreferredSize(new Dimension(560, 160));
        blScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200));
        blPanel.add(blScroll);
        blPanel.add(Box.createVerticalStrut(6));

        JPanel blBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        blBtns.setAlignmentX(LEFT_ALIGNMENT);
        JButton resetBl = new JButton("Reset Blacklist to Defaults");
        AcasTheme.styleButton(resetBl);
        resetBl.addActionListener(e -> blacklistArea.setText(com.acas.util.CaptureFilter.DEFAULT_BLACKLIST));
        blBtns.add(resetBl);
        blPanel.add(blBtns);

        form.add(blPanel);
        form.add(Box.createVerticalStrut(12));

        // 5. Advanced / Backup Notifications (Collapsible Telegram settings)
        JPanel advancedPanel = card("Optional Telegram Notifications");
        advancedPanel.add(formRow("Telegram Bot Token:", tgBotToken));
        advancedPanel.add(Box.createVerticalStrut(4));
        advancedPanel.add(formRow("Telegram Chat ID:", tgChatId));
        advancedPanel.add(Box.createVerticalStrut(6));
        
        JPanel tgBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        tgBtnRow.setAlignmentX(LEFT_ALIGNMENT);
        JButton testTg = new JButton("Test Telegram"); 
        AcasTheme.styleButton(testTg);
        testTg.addActionListener(e -> {
            saveSettings();
            NotificationFeedback.send(this, testTg, () -> notifier.sendTelegramReport("ACAS connected successfully!"));
        });
        tgBtnRow.add(testTg);
        advancedPanel.add(tgBtnRow);
        form.add(advancedPanel);

        return form;
    }

    private JPanel buildButtons() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(4, 16, 8, 16));
        
        JLabel authorLabel = new JLabel("<html>Author: <a href='https://github.com/jahanaj098'>jahanaj098</a> (https://github.com/jahanaj098)</html>");
        authorLabel.setFont(AcasTheme.UI_SMALL);
        authorLabel.setForeground(AcasTheme.MUTED);
        authorLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        p.add(authorLabel, BorderLayout.WEST);
        
        JPanel rightBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton export = new JButton("Export Workspace");
        export.addActionListener(e -> exportWorkspace());

        JButton importBtn = new JButton("Import Workspace");
        importBtn.addActionListener(e -> importWorkspace());

        JButton reset = new JButton("Reset All Data");
        reset.addActionListener(e -> resetWorkspace());

        JButton save = new JButton("Save Settings");
        save.addActionListener(e -> {
            saveSettings();
            JOptionPane.showMessageDialog(this, "Settings saved.", "Saved", JOptionPane.INFORMATION_MESSAGE);
        });

        for (JButton b : new JButton[]{export, importBtn, reset}) AcasTheme.styleButton(b);
        AcasTheme.stylePrimaryButton(save);
        rightBtns.add(export);
        rightBtns.add(importBtn);
        rightBtns.add(reset);
        rightBtns.add(save);
        p.add(rightBtns, BorderLayout.EAST);
        return p;
    }

    private void saveSettings() {
        notifier.setTelegramBotToken(new String(tgBotToken.getPassword()));
        notifier.setTelegramChatId(tgChatId.getText().trim());
        notifier.setHermesTelegramBotToken(new String(hermesTgBotToken.getPassword()));
        notifier.setHermesTelegramChatId(hermesTgChatId.getText());
        store.setGlobalSetting("hermes_tg_bot_token", new String(hermesTgBotToken.getPassword()).trim());
        store.setGlobalSetting("hermes_tg_chat_id", hermesTgChatId.getText().trim());
        String discordEndpoint;
        try { discordEndpoint=com.acas.export.HermesDestinationSettings.validateDiscordWebhook(new String(discordWebhook.getPassword())); }
        catch(IllegalArgumentException invalid){javax.swing.JOptionPane.showMessageDialog(this,invalid.getMessage(),"Invalid Discord webhook",javax.swing.JOptionPane.ERROR_MESSAGE);return;}
        notifier.setDiscordWebhookUrl(discordEndpoint);
        store.setGlobalSetting("hermes_export_destinations",switch(hermesDestinations.getSelectedIndex()){case 1->"discord";case 2->"both";default->"telegram";});
        String trigger = triggerStatusDiff.isSelected() ? "status_diff" :
                         triggerAnyDiff.isSelected() ? "any_diff" : "manual";
        notifier.setAlertTrigger(trigger);
        // Persist globally (survives project switches and Burp restarts) so these
        // stay set until explicitly changed again.
        store.setGlobalSetting("tg_bot_token", new String(tgBotToken.getPassword()));
        store.setGlobalSetting("tg_chat_id", tgChatId.getText().trim());
        store.setGlobalSetting("discord_webhook", discordEndpoint);
        store.setGlobalSetting("alert_trigger", trigger);
        store.setGlobalSetting("capture_blacklist", blacklistArea.getText());

        for(int i=0;i<credentialKeys.length;i++)store.setGlobalSetting("credential_"+credentialKeys[i],credentialFields[i].getText().trim());
        store.setGlobalSetting("matrix_only_hits", matrixOnlyHits.isSelected() ? "true" : "false");

        com.acas.model.ScopeConfig scopeCfg = store.getScopeConfig();
        if (scopeCfg != null) {
            scopeCfg.setUseBurpScope(useBurpScope.isSelected());
            store.saveScopeConfig(scopeCfg);
        }
    }

    private void exportWorkspace() {
        saveSettings();

        WorkspaceBackup backup = new WorkspaceBackup();
        backup.setActors(store.exportActors());
        backup.setScopeConfig(store.getScopeConfig());
        backup.setCapturedEndpoints(store.exportCapturedEndpoints());
        backup.setQueuedHuntEndpoints(huntManager.getHuntQueue());
        backup.setFindings(severityClassifier.exportFindings());
        backup.setCustomMutations(mutationRegistry.getCustomMutations());
        backup.setSettings(store.exportKnownSettings());
        backup.setActiveActorId(store.getActiveActorId());

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export ACAS Workspace");
        chooser.setFileFilter(new FileNameExtensionFilter("ACAS Workspace Backup (*.json)", "json"));
        chooser.setSelectedFile(new java.io.File("acas-workspace-backup.json"));

        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        java.io.File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".json")) {
            file = new java.io.File(file.getParentFile(), file.getName() + ".json");
        }

        try {
            String json = gson.toJson(backup);
            com.acas.export.SecureFiles.write(file.toPath().toAbsolutePath().getParent(),file.getName(),json.getBytes(StandardCharsets.UTF_8),true);
            JOptionPane.showMessageDialog(this, "Workspace exported successfully.\n" + file.getAbsolutePath(), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importWorkspace() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import ACAS Workspace");
        chooser.setFileFilter(new FileNameExtensionFilter("ACAS Workspace Backup (*.json)", "json"));

        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        java.io.File file = chooser.getSelectedFile();
        int confirm = JOptionPane.showConfirmDialog(this,
            "Importing will replace the current workspace state. Continue?",
            "Confirm Import",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        try {
            Path path=file.toPath();
            if(Files.isSymbolicLink(path) || !Files.isRegularFile(path,java.nio.file.LinkOption.NOFOLLOW_LINKS))
                throw new IllegalStateException("Backup must be a regular file.");
            if(Files.size(path)>256L*1024*1024)throw new IllegalStateException("Backup exceeds the 256 MB import limit.");
            String json = Files.readString(path, StandardCharsets.UTF_8);
            WorkspaceBackup backup = gson.fromJson(json, WorkspaceBackup.class);
            if (backup == null) {
                throw new IllegalStateException("Backup file is empty or invalid.");
            }

            store.replaceWorkspaceState(backup.getActors(), backup.getScopeConfig(), backup.getCapturedEndpoints(), backup.getActiveActorId());
            huntManager.restoreQueuedEndpoints(backup.getQueuedHuntEndpoints());
            store.applyKnownSettings(backup.getSettings());
            mutationRegistry.resetToDefaults();
            mutationRegistry.replaceCustomMutations(backup.getCustomMutations());
            severityClassifier.replaceFindings(backup.getFindings());
            loadSettingsFromStore();

            JOptionPane.showMessageDialog(this, "Workspace imported successfully.", "Import Complete", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(), "Import Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void resetWorkspace() {
        int confirm = JOptionPane.showConfirmDialog(this,
            "This will permanently clear actors, captured endpoints, hunt queue, findings, scope, and custom mutations.\nTelegram/Discord settings will be preserved. Continue?",
            "Reset ACAS Workspace",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        store.clearWorkspaceState(false);
        huntManager.clearQueue();
        mutationRegistry.resetToDefaults();
        severityClassifier.clearFindings();
        loadSettings();
        JOptionPane.showMessageDialog(this, "Workspace cleared. Notification settings are preserved.", "Reset Complete", JOptionPane.INFORMATION_MESSAGE);
    }

    private void loadSettings() {
        loadSettingsFromStore();
        // Also update the notifier values immediately
        saveSettings();
    }

    private void loadSettingsFromStore() {
        tgBotToken.setText(globalOrLegacy("tg_bot_token"));
        tgChatId.setText(globalOrLegacy("tg_chat_id"));
        hermesTgBotToken.setText(store.getGlobalSetting("hermes_tg_bot_token"));
        hermesTgChatId.setText(store.getGlobalSetting("hermes_tg_chat_id"));
        discordWebhook.setText(globalOrLegacy("discord_webhook"));
        String delivery=com.acas.export.HermesDestinationSettings.resolve(store.getGlobalSetting("hermes_export_destinations"),
            "true".equals(store.getGlobalSetting("hermes_export_destination_explicit")),
            hermesTgBotToken.getPassword().length>0 && !hermesTgChatId.getText().isBlank(),
            discordWebhook.getPassword().length>0);
        loadingDestination=true;
        try{hermesDestinations.setSelectedIndex(switch(delivery){case "discord"->1;case "both"->2;default->0;});}
        finally{loadingDestination=false;}

        String trigger = globalOrLegacy("alert_trigger");
        if ("any_diff".equals(trigger)) triggerAnyDiff.setSelected(true);
        else if ("manual".equals(trigger)) triggerManual.setSelected(true);
        else triggerStatusDiff.setSelected(true);

        String bl = globalOrLegacy("capture_blacklist");
        blacklistArea.setText(bl == null || bl.trim().isEmpty()
            ? com.acas.util.CaptureFilter.DEFAULT_BLACKLIST : bl);

        for(int i=0;i<credentialKeys.length;i++)credentialFields[i].setText(store.getGlobalSetting("credential_"+credentialKeys[i]));
        matrixOnlyHits.setSelected("true".equalsIgnoreCase(store.getGlobalSetting("matrix_only_hits")));

        com.acas.model.ScopeConfig scopeCfg = store.getScopeConfig();
        useBurpScope.setSelected(scopeCfg == null || scopeCfg.isUseBurpScope());
    }

    /** Prefer the global (durable) value; fall back to any legacy project-scoped value. */
    private String globalOrLegacy(String key) {
        String g = store.getGlobalSetting(key);
        if (g != null && !g.isEmpty()) return g;
        return store.getSetting(key);
    }

    private JPanel formRow(String label, JComponent field) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setAlignmentX(LEFT_ALIGNMENT);
        JLabel l = new JLabel(label);
        l.setFont(new Font("SansSerif", Font.BOLD, 11));
        l.setPreferredSize(new Dimension(100, 24));
        row.add(l, BorderLayout.WEST);
        row.add(field, BorderLayout.CENTER);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        return row;
    }

    private JPanel card(String title) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        javax.swing.border.TitledBorder tb = BorderFactory.createTitledBorder(title);
        tb.setTitleColor(AcasTheme.ACCENT);
        tb.setTitleFont(AcasTheme.UI_BOLD);
        p.setBorder(BorderFactory.createCompoundBorder(tb, new EmptyBorder(8, 10, 10, 10)));
        p.setAlignmentX(LEFT_ALIGNMENT);
        return p;
    }

    private void showToast(String message, boolean success) {
        JOptionPane.showMessageDialog(this, message, "Connection Test",
            success ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.ERROR_MESSAGE);
    }
}
