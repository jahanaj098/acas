package com.acas.ui;

import com.acas.notification.NotificationService.SendResult;
import java.awt.Component;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import javax.swing.*;

/** Keep network work off the UI thread and show only confirmed delivery outcomes. */
final class NotificationFeedback {
    private NotificationFeedback() {}

    static void send(Component parent, AbstractButton button, Supplier<CompletableFuture<SendResult>> action) {
        String text = button.getText();
        button.setEnabled(false);
        button.setText("Sending…");
        CompletableFuture<SendResult> pending;
        try { pending = action.get(); }
        catch (Exception error) {
            pending = CompletableFuture.completedFuture(new SendResult(false, "Could not prepare the report."));
        }
        pending.whenComplete((result, error) -> SwingUtilities.invokeLater(() -> {
            button.setEnabled(true);
            button.setText(text);
            boolean ok = error == null && result != null && result.success();
            String message = error == null && result != null ? result.message() : "Delivery could not be confirmed. Check the destination before retrying.";
            JOptionPane.showMessageDialog(parent, message, ok ? "Report sent" : "Send failed",
                ok ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.ERROR_MESSAGE);
        }));
    }
}
