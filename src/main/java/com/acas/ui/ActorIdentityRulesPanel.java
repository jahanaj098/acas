package com.acas.ui;

import com.acas.export.ActorIdentityRules;
import com.acas.store.ActorStore;
import javax.swing.*;
import java.awt.*;

final class ActorIdentityRulesPanel extends JPanel {
    private final JComboBox<String> saved=new JComboBox<>();
    private final JTextField endpoint=new JTextField(40),field=new JTextField(25);
    private final JComboBox<String> format=new JComboBox<>(new String[]{"JSON","Text label"});
    private final JComboBox<com.acas.model.ActorProfile> testActor=new JComboBox<>();
    private final JButton test=new JButton("Test identity endpoint");
    private final JTextArea testResult=new JTextArea(4,60);
    private final JLabel status=new JLabel("Use a trusted account endpoint that returns the currently authenticated user's identity.");
    ActorIdentityRulesPanel(ActorStore store) {
        setLayout(new BoxLayout(this,BoxLayout.Y_AXIS));setBorder(BorderFactory.createTitledBorder("Hermes actor recognition — per target"));
        add(row("Saved target rule",saved));add(row("Full identity endpoint URL (GET)",endpoint));add(row("Response format",format));add(row("User ID / username field",field));
        add(new JLabel("JSON: id, user.id or /user/id. Text label: Username (matches Username: jane)."));
        add(new JLabel("Saving or updating an actor automatically GETs this endpoint with that actor's credentials (no redirects)."));
        testActor.setRenderer(new DefaultListCellRenderer(){public Component getListCellRendererComponent(JList<?> list,Object value,int index,boolean selected,boolean focus){super.getListCellRendererComponent(list,value,index,selected,focus);if(value instanceof com.acas.model.ActorProfile a)setText(a.getName()+" ("+a.getRole()+") — "+a.getId());return this;}});
        add(row("Actor for test",testActor));add(test);
        testResult.setEditable(false);testResult.setLineWrap(true);testResult.setWrapStyleWord(true);add(new JScrollPane(testResult));
        Runnable refreshActors=()->{var selected=(com.acas.model.ActorProfile)testActor.getSelectedItem();testActor.removeAllItems();for(var actor:store.getAllActors()){testActor.addItem(actor);if(selected!=null && selected.getId().equals(actor.getId()))testActor.setSelectedItem(actor);}};
        store.addChangeListener(()->SwingUtilities.invokeLater(refreshActors));refreshActors.run();
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT));JButton save=new JButton("Save target rule"),remove=new JButton("Remove target rule");actions.add(save);actions.add(remove);add(actions);add(status);
        Runnable reload=()->{saved.removeAllItems();saved.addItem("New target rule");for(var rule:ActorIdentityRules.load(store))saved.addItem(rule.endpoint());};
        saved.addActionListener(e->{if(saved.getSelectedIndex()>0)for(var rule:ActorIdentityRules.load(store))if(rule.endpoint().equals(saved.getSelectedItem())){endpoint.setText(rule.endpoint());format.setSelectedItem(rule.format());field.setText(rule.field());}});
        save.addActionListener(e->update(store,false,reload));remove.addActionListener(e->update(store,true,reload));
        test.addActionListener(e->{
            var actor=(com.acas.model.ActorProfile)testActor.getSelectedItem();
            if(actor==null){testResult.setText("Save an actor first, then select it here.");return;}
            var draft=new ActorIdentityRules.Rule(endpoint.getText(),format.getSelectedItem().toString(),field.getText());
            String actorName=actor.getName();
            test.setEnabled(false);save.setEnabled(false);remove.setEnabled(false);testActor.setEnabled(false);endpoint.setEnabled(false);format.setEnabled(false);field.setEnabled(false);saved.setEnabled(false);
            testResult.setText("Testing "+actorName+" using the unsaved settings…");
            store.testActorIdentity(actor,draft).whenComplete((result,error)->SwingUtilities.invokeLater(()->{
                test.setEnabled(true);save.setEnabled(true);remove.setEnabled(true);testActor.setEnabled(true);endpoint.setEnabled(true);format.setEnabled(true);field.setEnabled(true);saved.setEnabled(true);
                if(error!=null){testResult.setText("Identity test failed. Check connection and actor credentials.");return;}
                testResult.setText("Actor: "+actorName+"\n"+(result.httpStatus()>0?"HTTP: "+result.httpStatus()+"\n":"")+(result.success()?"Found "+draft.field()+": "+result.value()+"\n":"")+result.message());
            }));
        });
        try{reload.run();}catch(Exception error){status.setText("Could not read saved identity rules.");}
    }
    private void update(ActorStore store,boolean remove,Runnable reload){try{ActorIdentityRules.save(store,new ActorIdentityRules.Rule(endpoint.getText(),format.getSelectedItem().toString(),field.getText()),remove);reload.run();if(!remove)store.refreshActorIdentities();status.setText(remove?"Target identity rule removed.":"Rule saved; identity lookup scheduled for matching actors. Export once to register their identities.");}catch(Exception error){JOptionPane.showMessageDialog(this,error.getMessage(),"Identity rule",JOptionPane.ERROR_MESSAGE);}}
    private JPanel row(String title,JComponent value){JPanel row=new JPanel(new BorderLayout(10,0));row.add(new JLabel(title),BorderLayout.WEST);row.add(value,BorderLayout.CENTER);return row;}
}
