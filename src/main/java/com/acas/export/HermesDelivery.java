package com.acas.export;

import java.util.List;

/** Receipt-based progress for one destination. Retrying never repeats acknowledged parts. */
public final class HermesDelivery {
    public interface Sender { void send(HermesArchive.FileData file) throws Exception; }
    public interface Checkpoint { void save(int accepted, int total) throws Exception; }
    public interface Commit { void save() throws Exception; }
    private final List<HermesArchive.FileData> files;
    private int accepted;
    private boolean committed;
    public HermesDelivery(List<HermesArchive.FileData> files) { this.files=List.copyOf(files); }
    public HermesDelivery(List<HermesArchive.FileData> files,int accepted,boolean committed) {
        this(files);
        if(accepted<0 || accepted>files.size() || (committed && accepted!=files.size()))
            throw new IllegalArgumentException("Invalid saved delivery progress");
        this.accepted=accepted;this.committed=committed;
    }
    public int accepted() { return accepted; }
    public boolean committed() { return committed; }
    public void resume(Sender sender,Checkpoint checkpoint,Commit commit) throws Exception {
        if(committed)return;
        if(accepted>0)checkpoint.save(accepted,files.size());
        while(accepted<files.size()) {
            sender.send(files.get(accepted));
            accepted++;
            checkpoint.save(accepted,files.size());
        }
        commit.save();
        committed=true;
    }
}
