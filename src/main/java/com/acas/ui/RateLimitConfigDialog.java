package com.acas.ui;

import javax.swing.*;
import java.awt.*;

public class RateLimitConfigDialog extends JDialog {
    private JSpinner requestsPerSecSpinner;
    private JSpinner requestsPerMinSpinner;
    private JSpinner maxConcurrentSpinner;
    private JSpinner intervalMinutesSpinner;
    private JCheckBox enableRateLimitCheckBox;
    private JCheckBox stopAfterIntervalCheckBox;
    private JLabel statusLabel;

    private int requestsPerSec = 5;
    private int requestsPerMin = 300;
    private int maxConcurrent = 2;
    private int intervalMinutes = 0;
    private boolean enableRateLimit = true;
    private boolean stopAfterInterval = false;

    public RateLimitConfigDialog(Window parent) {
        super(parent, "Hunt Rate Limiting Configuration", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        
        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // Header
        JLabel titleLabel = new JLabel("Request Rate & Throttling");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        contentPanel.add(titleLabel, BorderLayout.NORTH);

        // Main form panel
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Enable rate limit checkbox
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        enableRateLimitCheckBox = new JCheckBox("Enable Rate Limiting", enableRateLimit);
        formPanel.add(enableRateLimitCheckBox, gbc);

        // Requests per second
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        formPanel.add(new JLabel("Requests per Second:"), gbc);
        gbc.gridx = 1;
        requestsPerSecSpinner = new JSpinner(new SpinnerNumberModel(requestsPerSec, 1, 1000, 1));
        formPanel.add(requestsPerSecSpinner, gbc);

        // Requests per minute
        gbc.gridx = 0;
        gbc.gridy = 2;
        formPanel.add(new JLabel("Requests per Minute:"), gbc);
        gbc.gridx = 1;
        requestsPerMinSpinner = new JSpinner(new SpinnerNumberModel(requestsPerMin, 1, 10000, 10));
        formPanel.add(requestsPerMinSpinner, gbc);

        // Max concurrent requests
        gbc.gridx = 0;
        gbc.gridy = 3;
        formPanel.add(new JLabel("Max Concurrent Requests:"), gbc);
        gbc.gridx = 1;
        maxConcurrentSpinner = new JSpinner(new SpinnerNumberModel(maxConcurrent, 1, 100, 1));
        formPanel.add(maxConcurrentSpinner, gbc);

        // Stop after interval
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        stopAfterIntervalCheckBox = new JCheckBox("Stop hunt after interval", stopAfterInterval);
        formPanel.add(stopAfterIntervalCheckBox, gbc);

        // Interval in minutes
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 1;
        formPanel.add(new JLabel("Stop after (minutes):"), gbc);
        gbc.gridx = 1;
        intervalMinutesSpinner = new JSpinner(new SpinnerNumberModel(intervalMinutes, 0, 1440, 5));
        formPanel.add(intervalMinutesSpinner, gbc);

        // Separator
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 2;
        formPanel.add(new JSeparator(), gbc);

        // Status label
        gbc.gridx = 0;
        gbc.gridy = 7;
        gbc.gridwidth = 2;
        statusLabel = new JLabel("Status: Rate limiting ready");
        statusLabel.setFont(new Font("SansSerif", Font.ITALIC, 11));
        statusLabel.setForeground(new Color(100, 100, 100));
        formPanel.add(statusLabel, gbc);

        // Add form to content
        JScrollPane formScroll = new JScrollPane(formPanel);
        contentPanel.add(formScroll, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        
        JButton applyBtn = new JButton("Apply");
        applyBtn.addActionListener(e -> {
            requestsPerSec = (Integer) requestsPerSecSpinner.getValue();
            requestsPerMin = (Integer) requestsPerMinSpinner.getValue();
            maxConcurrent = (Integer) maxConcurrentSpinner.getValue();
            intervalMinutes = (Integer) intervalMinutesSpinner.getValue();
            enableRateLimit = enableRateLimitCheckBox.isSelected();
            stopAfterInterval = stopAfterIntervalCheckBox.isSelected();
            
            statusLabel.setText("✓ Settings applied successfully");
            statusLabel.setForeground(new Color(34, 139, 34));
        });
        buttonPanel.add(applyBtn);

        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.addActionListener(e -> {
            requestsPerSecSpinner.setValue(5);
            requestsPerMinSpinner.setValue(300);
            maxConcurrentSpinner.setValue(2);
            intervalMinutesSpinner.setValue(0);
            enableRateLimitCheckBox.setSelected(true);
            stopAfterIntervalCheckBox.setSelected(false);
            statusLabel.setText("Status: Reset to defaults");
            statusLabel.setForeground(new Color(100, 100, 100));
        });
        buttonPanel.add(resetBtn);

        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        buttonPanel.add(closeBtn);

        contentPanel.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(contentPanel);
        setSize(500, 420);
        setLocationRelativeTo(parent);
    }

    // Getters for configuration values
    public int getRequestsPerSec() { return requestsPerSec; }
    public int getRequestsPerMin() { return requestsPerMin; }
    public int getMaxConcurrent() { return maxConcurrent; }
    public int getIntervalMinutes() { return intervalMinutes; }
    public boolean isRateLimitEnabled() { return enableRateLimit; }
    public boolean isStopAfterInterval() { return stopAfterInterval; }

    // Setters for initial values
    public void setRequestsPerSec(int value) { 
        this.requestsPerSec = value;
        if (requestsPerSecSpinner != null) {
            requestsPerSecSpinner.setValue(value);
        }
    }
    public void setRequestsPerMin(int value) { 
        this.requestsPerMin = value;
        if (requestsPerMinSpinner != null) {
            requestsPerMinSpinner.setValue(value);
        }
    }
    public void setMaxConcurrent(int value) { 
        this.maxConcurrent = value;
        if (maxConcurrentSpinner != null) {
            maxConcurrentSpinner.setValue(value);
        }
    }
    public void setIntervalMinutes(int value) { 
        this.intervalMinutes = value;
        if (intervalMinutesSpinner != null) {
            intervalMinutesSpinner.setValue(value);
        }
    }
    public void setEnabledRateLimit(boolean enabled) { 
        this.enableRateLimit = enabled;
        if (enableRateLimitCheckBox != null) {
            enableRateLimitCheckBox.setSelected(enabled);
        }
    }
    public void setStopAfterInterval(boolean stop) { 
        this.stopAfterInterval = stop;
        if (stopAfterIntervalCheckBox != null) {
            stopAfterIntervalCheckBox.setSelected(stop);
        }
    }
}
