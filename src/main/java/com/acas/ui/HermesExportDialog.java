package com.acas.ui;

import burp.api.montoya.MontoyaApi;
import com.acas.export.*;
import com.acas.store.ActorStore;
import com.acas.engine.SeverityClassifier;
import com.acas.notification.NotificationService;
import com.google.gson.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;

/** User-initiated export only; no automatic upload and no automatic Hermes execution. */
final class HermesExportDialog extends JDialog {
    private static final java.util.concurrent.locks.ReentrantLock DELIVERY_LOCK=new java.util.concurrent.locks.ReentrantLock();
    private final MontoyaApi api; private final ActorStore store; private final SeverityClassifier findings; private final NotificationService notifier;
    private HermesExport.Ledger ledger;
    private final HermesHistoryRegistry registry;
    private String registryTarget, registryDestination;
    private final JLabel rememberedTarget = new JLabel();
    private final JComboBox<String> destination = new JComboBox<>(new String[]{"Telegram JSON", "Telegram (encrypted)", "Discord (encrypted)", "Local JSON", "Discord JSON", "Telegram and Discord JSON"});
    private final JComboBox<String> mode = new JComboBox<>(new String[]{"Changes since last successful export","Full snapshot"});
    private final JComboBox<String> failureTest=new JComboBox<>(new String[]{"Off","Fail Telegram once","Fail Discord once"});
    private final JSpinner failureAfter=new JSpinner(new SpinnerNumberModel(0,0,100000,1));
    private final JTextField project = new JTextField();
    private final JTextArea objective = new JTextArea("Analyze authorization boundaries between the supplied actors. Report reproducible owner-data leaks with evidence. Active testing scope and permitted actions: not specified; obtain these before active testing.",4,60);
    private final JPasswordField password = new JPasswordField();
    private final JPasswordField confirmPassword = new JPasswordField();
    private final DefaultTableModel actors = new DefaultTableModel(new String[]{"Local actor ID","Actor","Hermes identity (reuse when continuing a project)"},0) {
        public boolean isCellEditable(int row,int column) { return column==2; }
    };
    private final JTable actorTable = new JTable(actors);
    private final JLabel status = new JLabel("Exported means saved/sent, not received or tested by Hermes.");
    private final JButton run = new JButton("Preview export…"), load = new JButton("Import export history / previous JSON"), recover = new JButton("Recover JSON from downloaded parts");
    private HermesExport.Batch pending; private Path directory;
    private List<DeliveryPlan> plans;
    private HermesOutbox.State outbox;
    private static final class DeliveryPlan {
        final boolean telegram,remote;
        final String destinationKey,stateKey;
        final HermesExport.Batch batch;
        final HermesExport.Ledger history;
        final byte[] bytes;
        final List<HermesArchive.FileData> files;
        final Map<String,String> identities;
        final HermesDelivery delivery;
        HermesOutbox.Item saved;
        Path folder;
        DeliveryPlan(boolean telegram,boolean remote,String key,String stateKey,HermesExport.Batch batch,
                     HermesExport.Ledger before,boolean full,List<HermesArchive.FileData> files,byte[] bytes,Map<String,String> identities) {
            this.telegram=telegram;this.remote=remote;this.destinationKey=key;this.stateKey=stateKey;this.batch=batch;
            this.files=files;this.bytes=bytes;this.identities=identities;this.delivery=new HermesDelivery(files);
            this.history=!full && batch.changedCount()==0?HermesExport.readLedger(HermesExport.JSON.toJson(before)):batch.next();
            this.history.actorCredentialHashes=batch.next().actorCredentialHashes;
            this.history.responseSnapshots=batch.next().responseSnapshots;
        }
        String name(){return remote?(telegram?"Telegram":"Discord"):"Local file";}
        DeliveryPlan(HermesOutbox.Item item,Path root) throws Exception {
            telegram=item.telegram;remote=item.remote;destinationKey=item.destinationKey;stateKey=item.stateKey;
            batch=item.batch;history=item.history;bytes=new byte[0];identities=item.identities;saved=item;
            files=HermesOutbox.files(root,item);folder=root.resolve(item.folder);
            delivery=new HermesDelivery(files,item.accepted,item.committed);
        }
    }
    private boolean busy;
    private final boolean useSettingsPreset;
    private final String sessionActorId;
    HermesExportDialog(Component parent, MontoyaApi api, ActorStore store, SeverityClassifier findings, NotificationService notifier) {
        this(parent,api,store,findings,notifier,false);
    }
    HermesExportDialog(Component parent, MontoyaApi api, ActorStore store, SeverityClassifier findings, NotificationService notifier,boolean useSettingsPreset) {
        this(parent,api,store,findings,notifier,useSettingsPreset,null);
    }
    HermesExportDialog(Component parent, MontoyaApi api, ActorStore store, SeverityClassifier findings, NotificationService notifier,boolean useSettingsPreset,String sessionActorId) {
        super(SwingUtilities.getWindowAncestor(parent),sessionActorId!=null?"Send updated session":useSettingsPreset?"Send Hermes JSON":"Hermes export options",ModalityType.APPLICATION_MODAL);
        this.sessionActorId=sessionActorId;
        this.useSettingsPreset=useSettingsPreset;
        this.api=api; this.store=store; this.findings=findings; this.notifier=notifier;
        this.registry=new HermesHistoryRegistry(api);
        String preset=HermesDestinationSettings.resolve(store.getGlobalSetting("hermes_export_destinations"),
            "true".equals(store.getGlobalSetting("hermes_export_destination_explicit")),
            !store.getGlobalSetting("hermes_tg_bot_token").isBlank() && !store.getGlobalSetting("hermes_tg_chat_id").isBlank(),
            !notifier.getDiscordWebhookUrl().isBlank());
        destination.setSelectedIndex(switch(preset){case "telegram"->0;case "both"->5;default->4;});
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new java.awt.event.WindowAdapter(){ public void windowClosing(java.awt.event.WindowEvent e){ if(!busy) dispose(); }});
        JPanel form = new JPanel(new GridLayout(0,2,8,6));
        form.add(new JLabel("Destination")); form.add(destination); form.add(new JLabel("Export mode")); form.add(mode);
        form.add(new JLabel("Project ID")); form.add(project);
        form.add(new JLabel("Remembered target")); form.add(rememberedTarget);
        form.add(new JLabel("Archive password (12+ characters; keep separately)")); form.add(password);
        form.add(new JLabel("Confirm archive password")); form.add(confirmPassword);
        form.add(new JLabel("Retry test (this attempt only)"));form.add(failureTest);
        form.add(new JLabel("Fail after this many successful files"));form.add(failureAfter);
        failureAfter.setEnabled(false);
        failureTest.addActionListener(e->failureAfter.setEnabled(!busy && failureTest.getSelectedIndex()!=0));
        failureTest.setToolTipText("Simulates a failure before upload. Other destinations send normally. Resets after this attempt or reopening.");
        failureAfter.setToolTipText("0 fails the first pending file; 1 sends one pending file, then fails the next. There must be another file to trigger the failure.");
        JPanel center = new JPanel(new BorderLayout(8,8)); center.add(form,BorderLayout.NORTH);
        JPanel details = new JPanel(new GridLayout(2,1,8,8)); details.add(new JScrollPane(actorTable));
        objective.setLineWrap(true); objective.setWrapStyleWord(true);
        JScrollPane brief = new JScrollPane(objective); brief.setBorder(BorderFactory.createTitledBorder("Testing objective, authorized scope and permitted actions")); details.add(brief); center.add(details,BorderLayout.CENTER);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        if(!useSettingsPreset){buttons.add(load);buttons.add(recover);}
        buttons.add(run);
        JPanel bottom = new JPanel(new BorderLayout()); bottom.add(buttons,BorderLayout.NORTH); bottom.add(status,BorderLayout.SOUTH);
        JPanel root = new JPanel(new BorderLayout(8,8)); root.setBorder(BorderFactory.createEmptyBorder(12,12,12,12));
        root.add(new JLabel("Includes live credentials. JSON sends readable files; encrypted exports require a password. Default destination comes from Settings."),BorderLayout.NORTH);
        if(!useSettingsPreset)root.add(center,BorderLayout.CENTER);
        root.add(bottom,BorderLayout.SOUTH); setContentPane(root);
        destination.addActionListener(e -> { if(!busy) readState(); });
        load.addActionListener(e -> importHistory()); recover.addActionListener(e -> recover()); run.addActionListener(e -> start());
        readState(); restoreOutbox(); setSize(1000,620); setLocationRelativeTo(parent);
        if(useSettingsPreset) {
            JPanel presetPanel = new JPanel(new BorderLayout(6,6));
            JTextArea summary=new JTextArea("Destination: "+destination.getSelectedItem()+"\nTarget: "+registryTarget+
                (sessionActorId==null?"\nUses the saved Settings destination and current credentials. Review the preview, then confirm sending.":
                    "\nSelected actor: "+store.getActor(sessionActorId).getName()+". Sends credentials only; no captured requests or responses.")+
                "\nFor destination changes, use Settings. For actor mapping or custom parameters, use More Export Options.",4,70);
            summary.setEditable(false);summary.setLineWrap(true);summary.setWrapStyleWord(true);
            presetPanel.add(new JScrollPane(summary), BorderLayout.CENTER);
            if(sessionActorId == null) {
                JPanel modeBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
                modeBar.add(new JLabel("Export mode:"));
                modeBar.add(mode);
                JButton resetHistoryBtn = new JButton("Reset History / Resend All");
                resetHistoryBtn.setToolTipText("Clear the export ledger so all captured endpoints are treated as new.");
                resetHistoryBtn.addActionListener(e -> {
                    if (JOptionPane.showConfirmDialog(this, "Reset export history for this target?\nThis marks all captured requests as unsent so they will be delivered in the next export.", "Reset Export History", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                        ledger = new HermesExport.Ledger();
                        ledger.projectId = project.getText().trim();
                        mode.setSelectedIndex(1); // Set to full snapshot
                        showLedger();
                    }
                });
                modeBar.add(resetHistoryBtn);
                presetPanel.add(modeBar, BorderLayout.SOUTH);
            }
            root.add(presetPanel,BorderLayout.CENTER);
            setSize(850,330);setLocationRelativeTo(parent);
        }
        if(useSettingsPreset)addWindowListener(new java.awt.event.WindowAdapter(){
            @Override public void windowOpened(java.awt.event.WindowEvent e) {
                // A restored approved batch retains its explicit Resume action.
                if(pending==null && run.isEnabled())SwingUtilities.invokeLater(()->{if(isShowing())start();});
            }
        });
    }
    private void restoreOutbox() {
        String path=api.persistence().preferences().getString(HermesOutbox.PREFERENCE_KEY);
        if(path==null || path.isBlank())return;
        try {
            directory=Path.of(path);outbox=HermesOutbox.read(directory);
            if(sessionActorId!=null && !outbox.complete()) {
                var savedBatch=outbox.items.getFirst().batch;
                String selectedIdentity=ledger.actorKeys.get(sessionActorId);
                if(!HermesSessionUpdate.isSession(savedBatch) || !savedBatch.document().has("sessionActorId")
                    || !Objects.equals(selectedIdentity,savedBatch.document().get("sessionActorId").getAsString())) {
                    run.setEnabled(false);status.setText("Another approved export is pending. Finish it through Export for Hermes before sending this actor's session.");
                    return;
                }
            }
            List<DeliveryPlan> restored=new ArrayList<>();
            for(var item:outbox.items)restored.add(new DeliveryPlan(item,directory));
            if(outbox.complete()){
                plans=restored;registryTarget=outbox.target;commitSharedHistory();
                api.persistence().preferences().setString(HermesOutbox.PREFERENCE_KEY,"");outbox=null;plans=null;readState();return;
            }
            plans=restored;pending=plans.getFirst().batch;
            busy=true;destination.setSelectedIndex(outbox.selection);busy=false;
            registryTarget=outbox.target;registryDestination=plans.getFirst().destinationKey;
            ledger=plans.getFirst().history;showLedger();rememberedTarget.setText(registryTarget);
            lock(false);run.setText("Resume saved delivery");
            status.setText("Saved export restored: "+plans.stream().map(p->p.name()+" "+p.delivery.accepted()+"/"+p.files.size()+" accepted"+(p.delivery.committed()?" (complete)":"")).toList());
        }catch(Exception failure){
            busy=false;run.setEnabled(false);load.setEnabled(false);destination.setEnabled(false);
            status.setText("Saved export cannot be restored. Restore its original files in "+path+" and reopen this dialog. "+failure.getMessage());
        }
    }
    private void saveOutbox(int selection) throws Exception {
        HermesOutbox.State state=new HermesOutbox.State();state.target=registryTarget;state.selection=selection;
        for(var plan:plans) {
            var item=new HermesOutbox.Item();item.telegram=plan.telegram;item.remote=plan.remote;
            item.destinationKey=plan.destinationKey;item.stateKey=plan.stateKey;item.folder=plan.folder.getFileName().toString();
            JsonObject metadata=new JsonObject();metadata.add("objective",plan.batch.document().get("objective"));
            if(plan.batch.document().has("format"))metadata.add("format",plan.batch.document().get("format"));
            if(HermesSessionUpdate.isSession(plan.batch))metadata.add("sessionActorId",plan.batch.document().getAsJsonObject("actor").get("actorId"));
            item.batch=new HermesExport.Batch(plan.batch.id(),metadata,plan.history,plan.batch.changedCount(),null);
            item.history=plan.history;item.identities=plan.identities;
            for(var file:plan.files)item.parts.add(new HermesOutbox.Part(file.name(),file.bytes().length,HermesExport.hash(file.bytes())));
            plan.saved=item;state.items.add(item);
        }
        HermesOutbox.save(directory,state);outbox=state;
        // Register the batch before any remote send, so a fresh Burp project can find it.
        api.persistence().preferences().setString(HermesOutbox.PREFERENCE_KEY,directory.toAbsolutePath().toString());
    }
    private boolean primaryTelegram(){return destination.getSelectedIndex()<2 || destination.getSelectedIndex()==5;}
    private String stateKey() { return "acas_hermes_history_"+(destination.getSelectedIndex()==5?"both":destination.getSelectedIndex()==3?"local":primaryTelegram()?"telegram":"discord"); }
    private String historyDestination() {
        if(destination.getSelectedIndex()==3)return null;
        if(destination.getSelectedIndex()==5)return sharedKey(destinationKey(true),destinationKey(false));
        return destinationKey(primaryTelegram());
    }
    private static String sharedKey(String telegram,String discord) {
        return telegram==null || discord==null?null:"both:"+HermesExport.hash(telegram+"\n"+discord);
    }
    private String destinationKey(boolean telegram) {
        String value=telegram?store.getGlobalSetting("hermes_tg_chat_id").trim():notifier.getDiscordWebhookUrl().trim();
        return value.isBlank()?null:telegram?"telegram:"+value:"discord:"+HermesExport.hash(value);
    }
    private void readState() {
        try {
            registryTarget=HermesHistoryRegistry.target(store);
            registryDestination=historyDestination();
            rememberedTarget.setText(registryTarget.isBlank()?"Capture target traffic first":registryTarget);
            if(registryDestination!=null && registryDestination.equals("telegram:")) registryDestination=null;
            HermesHistoryRegistry.Entry remembered=registryDestination!=null && !registryTarget.isBlank()?registry.read(registryTarget,registryDestination):null;
            if(remembered!=null) {
                HermesHistoryRegistry.mapActors(store,remembered);ledger=remembered.ledger;
                if(remembered.objective!=null)objective.setText(remembered.objective);
            } else {
                String text=api.persistence().extensionData().getString(stateKey());
                String binding=api.persistence().extensionData().getString(stateKey()+"_binding");
                if((binding!=null && !binding.equals(registryTarget+"\n"+registryDestination)) ||
                    (!primaryTelegram() && destination.getSelectedIndex()!=3 && binding==null))text=null;
                ledger=text==null || text.isBlank()?new HermesExport.Ledger():HermesExport.readLedger(text);
            }
            showLedger();
            // Migrate successful history from older ACAS versions without re-sending its data.
            if(remembered==null && ledger.lastBatchId!=null && registryDestination!=null && !registryTarget.isBlank())
                registry.save(registryTarget,registryDestination,ledger,HermesHistoryRegistry.identities(store,ledger),objective.getText());
        } catch(Exception e) { run.setEnabled(false); status.setText("Export history could not be read. Import a valid history before continuing."); }
    }
    private void showLedger() {
        project.setText(ledger.projectId); actors.setRowCount(0);
        String savedBrief=api.persistence().extensionData().getString("acas_hermes_brief_"+HermesExport.hash(ledger.projectId));
        if(savedBrief!=null && !savedBrief.isBlank())objective.setText(savedBrief);
        for(var a:store.getAllActors()) actors.addRow(new Object[]{a.getId(),a.getName(),ledger.actorKeys.getOrDefault(a.getId(),ledger.actorNames.isEmpty()?a.getId():"")});
        JComboBox<String> identities = new JComboBox<>(); identities.setEditable(true);
        ledger.actorNames.forEach((id,name)->identities.addItem(id));
        store.getAllActors().forEach(a->identities.addItem(a.getId()));
        actorTable.getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(identities));
        actorTable.getColumnModel().getColumn(2).setPreferredWidth(330);
        status.setText("History: "+ledger.exported.size()+" fingerprints. Blank actor: choose a saved identity or its local ID for a new user. "+ledger.actorNames);
        run.setEnabled(true);
        boolean encrypted=destination.getSelectedIndex()==1 || destination.getSelectedIndex()==2;
        password.setEnabled(encrypted); confirmPassword.setEnabled(encrypted);
    }
    private void importHistory() {
        JFileChooser chooser=new JFileChooser(); if(chooser.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;
        try {
            JsonObject json=JsonParser.parseString(Files.readString(chooser.getSelectedFile().toPath())).getAsJsonObject();
            ledger=HermesExport.readLedger((json.has("exportHistory")?json.get("exportHistory"):json).toString());
            showLedger();
            if(json.has("objective") && json.get("objective").isJsonPrimitive())objective.setText(json.get("objective").getAsString());
        } catch(Exception e) { error("Cannot import this file. Select a Hermes JSON export or export-history.json."); }
    }
    private void lock(boolean value) {
        busy=value; run.setEnabled(!value); load.setEnabled(!value && pending==null); recover.setEnabled(!value);
        failureTest.setEnabled(!value);failureAfter.setEnabled(!value && failureTest.getSelectedIndex()!=0);
        destination.setEnabled(!value && pending==null); mode.setEnabled(!value && pending==null); project.setEnabled(!value && pending==null);
        actorTable.setEnabled(!value && pending==null); objective.setEnabled(!value && pending==null);
        boolean encrypted=destination.getSelectedIndex()==1 || destination.getSelectedIndex()==2;
        password.setEnabled(!value && pending==null && encrypted); confirmPassword.setEnabled(!value && pending==null && encrypted);
    }
    private DeliveryPlan preparePlan(boolean telegram,boolean remote,HermesExport.Ledger before,boolean full,String brief,char[] secret,boolean encrypted,boolean shared) throws Exception {
        var batch=sessionActorId==null?HermesExport.prepare(store,findings,before,full,brief):HermesSessionUpdate.prepare(api,store,before,sessionActorId);
        byte[] bytes=batch.bytes();
        boolean nothingNew=!full && batch.changedCount()==0;
        List<HermesArchive.FileData> packed=nothingNew?List.of():remote?
            (encrypted?HermesArchive.pack(bytes,batch.id(),secret,HermesUploadLimits.partBytes(telegram)):
                HermesArchive.packJson(bytes,batch.id(),shared?HermesUploadLimits.DISCORD_PART_BYTES:HermesUploadLimits.partBytes(telegram))):List.of();
        if(remote)HermesUploadLimits.validate(packed,telegram);
        return new DeliveryPlan(telegram,remote,remote?destinationKey(telegram):null,
            "acas_hermes_history_"+(remote?(telegram?"telegram":"discord"):"local"),batch,before,full,packed,bytes,HermesHistoryRegistry.identities(store,batch.next()));
    }
    private void commitPlan(DeliveryPlan plan) throws Exception {
        if(HermesSessionUpdate.isSession(plan.batch))return; // Session delivery never advances capture history.
        if(plan.folder!=null)SecureFiles.write(plan.folder,"export-history.json",HermesExport.JSON.toJson(plan.history).getBytes(java.nio.charset.StandardCharsets.UTF_8),true);
        if(plan.destinationKey!=null && !registryTarget.isBlank())
            registry.save(registryTarget,plan.destinationKey,plan.history,plan.identities,plan.batch.document().get("objective").getAsString());
        String history=HermesExport.JSON.toJson(plan.history);
        api.persistence().extensionData().setString(plan.stateKey,history);
        api.persistence().extensionData().setString(plan.stateKey+"_binding",registryTarget+"\n"+plan.destinationKey);
        api.persistence().extensionData().setString("acas_hermes_project",history);
        api.persistence().extensionData().setString("acas_hermes_brief_"+HermesExport.hash(plan.history.projectId),plan.batch.document().get("objective").getAsString());
    }
    private void commitSharedHistory() {
        if(plans==null || plans.size()!=2 || !plans.get(0).batch.id().equals(plans.get(1).batch.id()))return;
        if(plans.stream().anyMatch(p->!p.delivery.committed()))return;
        if(HermesSessionUpdate.isSession(plans.getFirst().batch))return;
        DeliveryPlan tg=plans.stream().filter(p->p.telegram).findFirst().orElseThrow();
        DeliveryPlan dc=plans.stream().filter(p->!p.telegram).findFirst().orElseThrow();
        String key=sharedKey(tg.destinationKey,dc.destinationKey);
        registry.save(registryTarget,key,tg.history,tg.identities,tg.batch.document().get("objective").getAsString());
        api.persistence().extensionData().setString("acas_hermes_history_both",HermesExport.JSON.toJson(tg.history));
        api.persistence().extensionData().setString("acas_hermes_history_both_binding",registryTarget+"\n"+key);
    }
    private void start() {
        if(actorTable.isEditing())actorTable.getCellEditor().stopCellEditing();
        boolean telegram=primaryTelegram(),both=destination.getSelectedIndex()==5;
        boolean remote=destination.getSelectedIndex()!=3,encrypted=destination.getSelectedIndex()==1 || destination.getSelectedIndex()==2;
        int selection=destination.getSelectedIndex();
        int testDestination=failureTest.getSelectedIndex();
        if(testDestination!=0 && (!remote || (testDestination==1 && !telegram) || (testDestination==2 && telegram && !both))) {
            error("Select a failure test for a destination included in this export.");return;
        }
        HermesFailureSimulation simulation=new HermesFailureSimulation(testDestination,((Number)failureAfter.getValue()).intValue());
        if(pending==null) {
            String saved=api.persistence().preferences().getString(HermesOutbox.PREFERENCE_KEY);
            if(saved!=null && !saved.isBlank()){restoreOutbox();return;}
            if(!Objects.equals(registryTarget,HermesHistoryRegistry.target(store)) ||
                (remote && !Objects.equals(registryDestination,historyDestination()))) {
                readState();error("Target or destination changed. Review the refreshed export history and actor mappings.");return;
            }
            List<String> missing=new ArrayList<>();
            if(remote && telegram) {
                if(store.getGlobalSetting("hermes_tg_bot_token").isBlank())missing.add("Telegram — Hermes exports: Bot Token");
                if(destinationKey(true)==null)missing.add("Telegram — Hermes exports: Chat ID");
            }
            if(remote && (!telegram || both) && destinationKey(false)==null)missing.add("Discord: Webhook URL");
            if(!missing.isEmpty()){error("Selected destination: "+destination.getSelectedItem()+"\nMissing saved Settings fields:\n• "+String.join("\n• ",missing)+
                "\n\nSave these fields in Settings, or change Hermes export delivery to the service you want.");return;}
            if(remote && (!telegram || both)) {
                try {
                    if(HermesDestinationSettings.validateDiscordWebhook(notifier.getDiscordWebhookUrl()).isBlank())
                        throw new IllegalArgumentException();
                }catch(Exception invalid){error("Enter a valid Discord webhook URL in Settings.");return;}
            }
            if(project.getText().isBlank()){error("Enter a project ID.");return;}
            if(!project.getText().trim().equals(ledger.projectId)) {
                ledger=new HermesExport.Ledger();ledger.projectId=project.getText().trim();
            }
            for(int i=0;i<actors.getRowCount();i++)ledger.actorKeys.put(actors.getValueAt(i,0).toString(),Objects.toString(actors.getValueAt(i,2),"").trim());
            if(sessionActorId==null && ledger.actorKeys.values().stream().anyMatch(String::isBlank)){error("Open Export options and choose a Hermes identity for each unmapped actor.");return;}
            if(encrypted && password.getPassword().length<12){error("Use an archive password of at least 12 characters.");return;}
            if(encrypted && !Arrays.equals(password.getPassword(),confirmPassword.getPassword())){error("Archive passwords do not match.");return;}
            if(useSettingsPreset && remote) {
                directory=Path.of(System.getProperty("user.home"),".acas","hermes-exports");
            } else {
                JFileChooser chooser=new JFileChooser();chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                chooser.setDialogTitle("Save export files here");if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;
                directory=chooser.getSelectedFile().toPath();
            }
        }
        boolean full=mode.getSelectedIndex()==1;String brief=objective.getText();char[] secret=password.getPassword();
        lock(true);status.setText(pending==null?"Preparing destination previews…":"Retrying remaining deliveries…");
        new SwingWorker<String,String>() {
            protected String doInBackground() throws Exception {
                if(!DELIVERY_LOCK.tryLock()){Arrays.fill(secret,'\0');throw new IllegalStateException("Another export is running. Retry after it finishes.");}
                try {
                    if(pending==null) {
                        List<DeliveryPlan> prepared=new ArrayList<>();
                        prepared.add(preparePlan(telegram,remote,ledger,full,brief,secret,encrypted,both));
                        if(both) {
                            var shared=prepared.getFirst();
                            HermesUploadLimits.validate(shared.files,false);
                            prepared.add(new DeliveryPlan(false,true,destinationKey(false),"acas_hermes_history_discord",
                                shared.batch,ledger,full,shared.files,shared.bytes,shared.identities));
                        }
                        // Review every destination before writing or sending anything.
                        for(var plan:(both?prepared.subList(0,1):prepared))if(!confirmPreview(plan.batch,plan.bytes.length,both?"Discord (Hermes) + Telegram (backup)":plan.name(),!full && plan.batch.changedCount()==0,plan.files.size(),plan.destinationKey))
                            return "Export cancelled. No files sent and export history unchanged.";
                        SecureFiles.createDirectories(directory);
                        Path output=directory.resolve("acas-"+prepared.getFirst().batch.id());SecureFiles.createDirectories(output);directory=output;
                        for(var plan:prepared) {
                            plan.folder=output.resolve(plan.remote?(plan.telegram?"telegram":"discord"):"local");SecureFiles.createDirectories(plan.folder);
                            for(var file:plan.files)SecureFiles.write(plan.folder,file.name(),file.bytes(),false);
                            if(!plan.remote && (full || plan.batch.changedCount()>0))SecureFiles.write(plan.folder,"hermes.json",plan.bytes,false);
                        }
                        plans=prepared;
                        saveOutbox(selection);
                        pending=plans.getFirst().batch;
                    }
                    List<String> failures=new ArrayList<>(),completed=new ArrayList<>();
                    // A second dialog may have restored an older checkpoint. Refresh under the delivery lock.
                    var latest=HermesOutbox.read(directory);
                    for(int i=0;i<latest.items.size();i++) {
                        var item=latest.items.get(i);
                        for(var plan:plans)if(plan.batch.id().equals(item.batch.id()) && Objects.equals(plan.destinationKey,item.destinationKey)) {
                            item.accepted=Math.max(item.accepted,plan.delivery.accepted());
                            item.committed|=plan.delivery.committed();
                        }
                    }
                    List<DeliveryPlan> refreshed=new ArrayList<>();
                    for(var item:latest.items)refreshed.add(new DeliveryPlan(item,directory));
                    plans=refreshed;outbox=latest;
                    for(var plan:plans) {
                        try {
                            int acceptedBefore=plan.delivery.accepted();
                            if (acceptedBefore == 0 && !plan.files.isEmpty()) {
                                String introMsg;
                                if (plan.files.size() > 1) {
                                    introMsg = "📦 **Incoming Multi-Part ACAS Export** (" + plan.files.size() + " parts)\n"
                                        + "Batch: `" + plan.batch.id() + "`\n"
                                        + "Sending " + plan.files.size() + " parts for target `" + registryTarget + "`. All parts and manifest will arrive sequentially. Please assemble and run authorized tests.";
                                } else {
                                    introMsg = "🚀 **Incoming ACAS Export Bundle**\n"
                                        + "Batch: `" + plan.batch.id() + "`\n"
                                        + "Delivering export payload for target `" + registryTarget + "`. Please process and run authorized tests.";
                                }
                                publish(plan.name() + ": notifying Hermes before first attachment…");
                                try {
                                    notifier.sendHermesTextMessage(plan.telegram, introMsg).get();
                                } catch (Exception notifyErr) {
                                    // Log but proceed with file upload
                                    api.logging().logToError("ACAS Hermes pre-export notice failed: " + notifyErr.getMessage());
                                }
                            }
                            plan.delivery.resume(file->{
                                if(!Objects.equals(plan.destinationKey,destinationKey(plan.telegram)))
                                    throw new java.io.IOException("Destination settings changed. Restore the reviewed destination before retrying.");
                                simulation.beforeSend(plan.telegram,plan.delivery.accepted()-acceptedBefore);
                                if(plan.delivery.accepted()>0)Thread.sleep(1100);
                                publish(plan.name()+": sending attachment "+(plan.delivery.accepted()+1)+" of "+plan.files.size()+"…");
                                var result=(plan.telegram?notifier.sendHermesTelegramAttachment(file.name(),file.bytes()):notifier.sendDiscordAttachment(file.name(),file.bytes())).get();
                                if(!result.success())throw new java.io.IOException(result.message());
                            },(accepted,total)->{
                                plan.saved.accepted=accepted;HermesOutbox.save(directory,outbox);
                            },()->{
                                commitPlan(plan);plan.saved.committed=true;HermesOutbox.save(directory,outbox);
                            });
                            completed.add(plan.name());
                        }catch(Exception failure){failures.add(plan.name()+": "+failure.getMessage());}
                    }
                    if(!failures.isEmpty())throw new java.io.IOException("Completed: "+completed+". Pending: "+String.join("; ",failures)+". Retry resumes unacknowledged parts only.");
                    commitSharedHistory();
                    api.persistence().preferences().setString(HermesOutbox.PREFERENCE_KEY,"");
                    ledger=plans.getFirst().history;pending=null;plans=null;outbox=null;
                    return "Export complete for "+String.join(" and ",completed)+". Files and history saved in "+directory;
                }finally{Arrays.fill(secret,'\0');DELIVERY_LOCK.unlock();}
            }
            protected void process(List<String> messages){status.setText(messages.getLast());}
            protected void done(){
                try{status.setText(get());password.setText("");confirmPassword.setText("");}
                catch(Exception e){Throwable cause=e.getCause()==null?e:e.getCause();status.setText("Export incomplete. "+cause.getMessage());}
                failureTest.setSelectedIndex(0);
                lock(false);run.setText(pending==null?"Preview export…":"Retry remaining / finish export");
            }
        }.execute();
    }
    private void recover() {
        JFileChooser chooser=new JFileChooser(); chooser.setDialogTitle("Select the downloaded manifest (all parts must be beside it)");
        if(chooser.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return; Path input=chooser.getSelectedFile().toPath();
        JPasswordField field=new JPasswordField(); boolean needsPassword;
        try { needsPassword="acas-hermes-archive-1".equals(JsonParser.parseString(Files.readString(input)).getAsJsonObject().get("format").getAsString()); }
        catch(Exception e){error("Select a valid ACAS parts manifest.");return;}
        if(needsPassword && JOptionPane.showConfirmDialog(this,field,"Archive password",JOptionPane.OK_CANCEL_OPTION)!=JOptionPane.OK_OPTION)return;
        JFileChooser output=new JFileChooser(); output.setSelectedFile(new java.io.File("hermes-recovered.json"));
        if(output.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return; Path path=output.getSelectedFile().toPath();
        if(Files.exists(path)){error("Choose a new filename to avoid overwriting an existing file.");return;}
        char[] secret=field.getPassword(); lock(true);
        new SwingWorker<Void,Void>() {
            protected Void doInBackground() throws Exception {try{ SecureFiles.write(path.toAbsolutePath().getParent(),path.getFileName().toString(),HermesArchive.recover(input,secret),false);return null;}finally{Arrays.fill(secret,'\0');}}
            protected void done(){try{get();status.setText("Recovered JSON contains credentials: "+path);}catch(Exception e){error("Recovery failed: check the password, manifest and all numbered parts.");}finally{lock(false);}}
        }.execute();
    }
    private boolean confirmPreview(HermesExport.Batch batch,int bytes,String destinationName,boolean nothingNew,int attachmentCount,String destinationKey) throws Exception {
        java.util.concurrent.atomic.AtomicBoolean accepted=new java.util.concurrent.atomic.AtomicBoolean();
        SwingUtilities.invokeAndWait(()->{
            JTextArea text=new JTextArea("Destination: "+destinationName+"\nMode: "+batch.document().get("mode").getAsString()
                +"\nLocal retry files: "+directory
                +"\nTarget: "+registryTarget+(destinationName.equals("Telegram") && destinationKey!=null?"\nChat: "+destinationKey.substring("telegram:".length()):"")
                +(destinationName.equals("Discord") && destinationKey!=null?"\nWebhook fingerprint: "+destinationKey.substring("discord:".length()):"")
                +"\nProject: "+batch.next().projectId+"\nJSON size: "+String.format(java.util.Locale.ROOT,"%.1f KiB",bytes/1024.0)
                +"\n\nPREFLIGHT\n"+HermesPreflight.of(batch.document()).text()
                +"\n\nAttachments to send: "+attachmentCount
                +(failureTest.getSelectedIndex()==0?"":"\nRETRY TEST: "+failureTest.getSelectedItem()+" after "+failureAfter.getValue()+" successful files in this attempt. Other destinations send normally. Resets automatically.")
                +((failureTest.getSelectedIndex()==1 && destinationName.equals("Telegram") || failureTest.getSelectedIndex()==2 && destinationName.equals("Discord"))
                    && attachmentCount<=((Number)failureAfter.getValue()).intValue()?
                    "\nThis destination has too few pending files to trigger the selected test. Cancel and lower the count or capture new data.":"")
                +(destinationName.equals("Local file")?"":"\nPer-file budget: "+HermesUploadLimits.partBytes(destinationName.equals("Telegram"))+" bytes (larger exports split with a recovery manifest)")
                +(destination.getSelectedIndex()==5?"\nOne shared JSON batch: identical filenames and bytes go to Discord and Telegram. Attachment count is per destination.\nTelegram chat: "+store.getGlobalSetting("hermes_tg_chat_id")+"\nDiscord webhook fingerprint: "+destinationKey(false):"")
                +(HermesSessionUpdate.isSession(batch)?"\n\nSESSION UPDATE ONLY\nActor: "+batch.document().getAsJsonObject("actor").get("name").getAsString()
                    +"\nHermes actor ID: "+batch.document().getAsJsonObject("actor").get("actorId").getAsString()
                    +"\nOrigin: "+batch.document().getAsJsonObject("actor").get("origin").getAsString()
                    +"\nCredential revision: "+batch.document().get("credentialRevision").getAsLong()
                    +"\nIdentity lookup: "+batch.document().getAsJsonObject("actor").get("identityLookupStatus").getAsString()
                    +"\nRequests/responses included: 0. Existing capture export history will not change.":"\n\n"+batch.preview().description())
                +(nothingNew?"\n\nNothing has changed: no file will be sent.":"\n\nThis exact snapshot will be exported. Traffic arriving afterward is left for the next export."),21,72);
            text.setEditable(false);text.setLineWrap(true);text.setWrapStyleWord(true);text.setCaretPosition(0);
            JTabbedPane tabs=new JTabbedPane();
            tabs.addTab("Summary",new JScrollPane(text));
            addRequestDetails(tabs,"New",batch.preview().newDetails(),"New request identities. Requests to the same URL from different actors remain separate.");
            addRequestDetails(tabs,"Changed",batch.preview().changedDetails(),"One row per changed response record for a previously sent request. Multiple versions can share an endpoint.");
            addRequestDetails(tabs,"Skipped",batch.preview().skippedDetails(),"Unchanged captured requests omitted from this export. New probes or findings for these endpoints may still be included.");
            if(batch.document().get("mode").getAsString().equals("full") || !batch.preview().repeatedDetails().isEmpty())
                addRequestDetails(tabs,"Repeated",batch.preview().repeatedDetails(),"Previously sent requests included in a full snapshot; these can also have changed responses.");
            tabs.setPreferredSize(new Dimension(900,460));
            Object[] choices;
            if(nothingNew) {
                choices = new Object[]{"Re-send All (Full Snapshot)", "Close preview", "Cancel"};
            } else {
                choices = new Object[]{destinationName.equals("Local file") ? "Confirm save" : "Confirm send", "Cancel"};
            }
            int choice=JOptionPane.showOptionDialog(this,tabs,"Review Hermes export",JOptionPane.DEFAULT_OPTION,JOptionPane.PLAIN_MESSAGE,null,choices,choices[0]);
            if(nothingNew) {
                if(choice == 0) { // Re-send All (Full Snapshot)
                    mode.setSelectedIndex(1);
                    accepted.set(false);
                    SwingUtilities.invokeLater(this::start);
                } else {
                    accepted.set(false);
                }
            } else {
                accepted.set(choice==0);
            }
        });
        return accepted.get();
    }
    private static void addRequestDetails(JTabbedPane tabs,String label,List<HermesExport.RequestDetail> details,String explanation) {
        DefaultTableModel model=new DefaultTableModel(new String[]{"Actor","Hermes identity","Method","Endpoint URL"},0) {
            public boolean isCellEditable(int row,int column){return false;}
        };
        for(var detail:details)model.addRow(new Object[]{detail.actorName(),detail.actorId(),detail.method(),detail.url()});
        JTable table=new JTable(model) {
            public String getToolTipText(java.awt.event.MouseEvent event) {
                int row=rowAtPoint(event.getPoint()),column=columnAtPoint(event.getPoint());
                return row<0 || column<0?null:String.valueOf(getValueAt(row,column));
            }
        };
        table.setAutoCreateRowSorter(true);table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);table.setFillsViewportHeight(true);
        int[] widths={140,180,75,600};
        for(int i=0;i<widths.length;i++)table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        JPanel panel=new JPanel(new BorderLayout(0,8));
        JTextArea note=new JTextArea(explanation+(details.isEmpty()?" No requests in this category.":""));
        note.setEditable(false);note.setLineWrap(true);note.setWrapStyleWord(true);note.setRows(2);
        panel.add(note,BorderLayout.NORTH);panel.add(new JScrollPane(table),BorderLayout.CENTER);
        if(label.equals("Changed")) {
            JButton compare=new JButton("Compare selected response…");
            compare.setEnabled(false);
            table.getSelectionModel().addListSelectionListener(e->compare.setEnabled(table.getSelectedRow()>=0));
            compare.addActionListener(e->{
                int row=table.getSelectedRow();
                if(row>=0)showResponseComparison(panel,details.get(table.convertRowIndexToModel(row)));
            });
            panel.add(compare,BorderLayout.SOUTH);
        }
        tabs.addTab(label+" ("+details.size()+")",panel);
    }
    private static void showResponseComparison(Component parent,HermesExport.RequestDetail detail) {
        String old=detail.previousAvailable()?(detail.oldResponse()==null?"[No response captured]":detail.oldResponse()):"[Previous response unavailable: older export history retained fingerprints only.]";
        String current=detail.newResponse()==null?"[No response captured]":detail.newResponse();
        JTextArea before=new JTextArea(old),after=new JTextArea(current);
        for(JTextArea area:new JTextArea[]{before,after}) {
            area.setEditable(false);area.setFont(new Font(Font.MONOSPACED,Font.PLAIN,12));area.setCaretPosition(0);
        }
        if(detail.previousAvailable()) {
            int start=0,oldEnd=old.length(),newEnd=current.length();
            while(start<oldEnd && start<newEnd && old.charAt(start)==current.charAt(start))start++;
            while(oldEnd>start && newEnd>start && old.charAt(oldEnd-1)==current.charAt(newEnd-1)){oldEnd--;newEnd--;}
            try {
                var highlight=new javax.swing.text.DefaultHighlighter.DefaultHighlightPainter(new Color(190,140,40,110));
                before.getHighlighter().addHighlight(start,oldEnd,highlight);
                after.getHighlighter().addHighlight(start,newEnd,highlight);
                before.setCaretPosition(start);after.setCaretPosition(start);
            }catch(javax.swing.text.BadLocationException ex){throw new IllegalStateException(ex);}
        }
        JPanel left=new JPanel(new BorderLayout()),right=new JPanel(new BorderLayout());
        left.add(new JLabel("Previously exported response"),BorderLayout.NORTH);left.add(new JScrollPane(before));
        right.add(new JLabel("New response in this export"),BorderLayout.NORTH);right.add(new JScrollPane(after));
        JSplitPane split=new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,left,right);split.setResizeWeight(0.5);split.setPreferredSize(new Dimension(1000,500));split.setDividerLocation(500);
        JPanel content=new JPanel(new BorderLayout(0,8));
        JTextArea heading=new JTextArea(detail.actorName()+" ("+detail.actorId()+") — "+detail.method()+" "+detail.url()+"\nRaw response view: highlights span the first through last difference, including intervening unchanged text. Transport headers may also differ.");
        heading.setEditable(false);heading.setLineWrap(true);heading.setWrapStyleWord(true);heading.setRows(3);
        content.add(heading,BorderLayout.NORTH);content.add(split,BorderLayout.CENTER);
        JOptionPane.showMessageDialog(parent,content,"Response changes",JOptionPane.PLAIN_MESSAGE);
    }
    private void error(String text){JOptionPane.showMessageDialog(this,text,"Hermes export",JOptionPane.ERROR_MESSAGE);}
}
