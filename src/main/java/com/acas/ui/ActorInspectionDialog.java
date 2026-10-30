package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import com.acas.model.ActorProfile;

import javax.swing.*;
import java.awt.*;

public class ActorInspectionDialog extends JDialog {
    private final HttpRequestEditor requestEditor;

    public ActorInspectionDialog(Window parent, MontoyaApi api, ActorProfile actor) {
        super(parent, "Actor Registration: " + actor.getName(), ModalityType.APPLICATION_MODAL);
        setLayout(new BorderLayout());
        setSize(800, 600);
        setLocationRelativeTo(parent);

        // 1. Request Editor (Focus Only)
        requestEditor = api.userInterface().createHttpRequestEditor(burp.api.montoya.ui.editor.EditorOptions.READ_ONLY);
        if (actor.getCapturedFrom() != null) {
            requestEditor.setRequest(burp.api.montoya.http.message.requests.HttpRequest.httpRequest(actor.getCapturedFrom()));
        }

        add(requestEditor.uiComponent(), BorderLayout.CENTER);
    }
}
