package com.acas.export;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Durable approved batch and receipts. Upload credentials stay in Settings. */
public final class HermesOutbox {
    public static final String PREFERENCE_KEY="acas_hermes_pending_outbox";
    public static final String FILE_NAME="pending-delivery.json";
    private static final long MAX_OUTBOX_BYTES=64L*1024*1024;
    private static final long MAX_PART_BYTES=64L*1024*1024;
    public static class State {
        public String format="acas-hermes-outbox-1";
        public String target;
        public int selection;
        public List<Item> items=new ArrayList<>();
        public boolean complete(){return items.stream().allMatch(i->i.committed);}
    }
    public static class Item {
        public boolean telegram,remote,committed;
        public String destinationKey,stateKey,folder;
        public HermesExport.Batch batch;
        public HermesExport.Ledger history;
        public Map<String,String> identities;
        public List<Part> parts=new ArrayList<>();
        public int accepted;
    }
    public record Part(String name,int size,String sha256) {}
    public static void save(Path root,State state) throws Exception {
        byte[] bytes=HermesExport.JSON.toJson(state).getBytes(StandardCharsets.UTF_8);
        if(bytes.length>MAX_OUTBOX_BYTES)throw new IllegalArgumentException("Pending export checkpoint is too large");
        // Fail closed on filesystems without atomic replacement; never send without a durable checkpoint.
        SecureFiles.write(root,FILE_NAME,bytes,true);
    }
    public static State read(Path root) throws Exception {
        State state=HermesExport.JSON.fromJson(new String(SecureFiles.read(root,FILE_NAME,MAX_OUTBOX_BYTES),StandardCharsets.UTF_8),State.class);
        if(state==null || !"acas-hermes-outbox-1".equals(state.format) || state.target==null ||
            state.selection<0 || state.selection>5 || state.items==null || state.items.isEmpty() || state.items.size()>2)
            throw new IllegalArgumentException("Invalid pending export");
        Set<String> folders=new HashSet<>();
        for(Item i:state.items) {
            if(i==null || !Set.of("telegram","discord","local").contains(i.folder) || !folders.add(i.folder) ||
                i.parts==null || i.batch==null || i.history==null || i.identities==null ||
                i.accepted<0 || i.accepted>i.parts.size() || (i.committed && i.accepted!=i.parts.size()) ||
                !Objects.equals(i.stateKey,"acas_hermes_history_"+(i.remote?(i.telegram?"telegram":"discord"):"local")) ||
                (i.remote && (i.destinationKey==null || !i.destinationKey.startsWith(i.telegram?"telegram:":"discord:"))))
                throw new IllegalArgumentException("Invalid pending destination");
            Set<String> names=new HashSet<>();
            for(Part p:i.parts)if(p==null || p.name()==null || !p.name().matches("[a-zA-Z0-9_-][a-zA-Z0-9._-]*") ||
                p.size()<0 || p.size()>MAX_PART_BYTES || p.sha256()==null || !p.sha256().matches("[a-f0-9]{64}") || !names.add(p.name()))
                throw new IllegalArgumentException("Invalid pending file");
        }
        return state;
    }
    public static List<HermesArchive.FileData> files(Path root,Item item) throws Exception {
        List<HermesArchive.FileData> result=new ArrayList<>();
        for(int n=0;n<item.parts.size();n++) {
            Part part=item.parts.get(n);
            // Acknowledged parts are never opened or transmitted again.
            if(part.size()<0 || part.size()>MAX_PART_BYTES)throw new IllegalArgumentException("Pending file size is outside the permitted range");
            byte[] bytes=n<item.accepted?new byte[0]
                :SecureFiles.read(root.resolve(item.folder),part.name(),MAX_PART_BYTES);
            if(n>=item.accepted && (bytes.length!=part.size() || !HermesExport.hash(bytes).equals(part.sha256())))
                throw new IllegalArgumentException("Pending file changed: "+part.name()+". Restore the original file; it will not be regenerated.");
            result.add(new HermesArchive.FileData(part.name(),bytes));
        }
        return result;
    }
}
