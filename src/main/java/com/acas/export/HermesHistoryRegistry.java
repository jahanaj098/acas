package com.acas.export;

import burp.api.montoya.MontoyaApi;
import com.acas.model.ActorProfile;
import com.acas.store.ActorStore;
import java.net.URI;
import java.util.*;

/** Installation-wide export history, including response comparison snapshots; no bot secrets. */
public final class HermesHistoryRegistry {
    private final MontoyaApi api;
    public HermesHistoryRegistry(MontoyaApi api) { this.api=api; }
    public static final class Entry {
        public String format="acas-hermes-registry-1";
        public HermesExport.Ledger ledger;
        public String objective;
        public Map<String,String> credentialIdentities=new HashMap<>();
    }
    public static String target(ActorStore store) {
        SortedSet<String> origins=new TreeSet<>();
        store.getCapturedEndpoints().forEach(e -> addOrigin(origins,e.getOriginalUrl()));
        store.getAllActors().forEach(a -> {addOrigin(origins,a.getIdentitySourceUrl());a.getCaptureHistory().forEach(h -> addOrigin(origins,h.url));});
        return String.join(", ",origins);
    }
    private static void addOrigin(Set<String> origins,String value) {
        try {
            URI uri=URI.create(value);String scheme=uri.getScheme().toLowerCase(Locale.ROOT),host=uri.getHost();
            if(host==null || !(scheme.equals("http") || scheme.equals("https")))return;
            int port=uri.getPort();if(port==(scheme.equals("https")?443:80))port=-1;
            origins.add(scheme+"://"+host.toLowerCase(Locale.ROOT)+(port<0?"":":"+port));
        }catch(Exception ignored){}
    }
    private String storageKey(String target,String destination) {
        if(target==null || target.isBlank() || destination==null || destination.isBlank())throw new IllegalArgumentException("Target and destination are required");
        return "acas_hermes_registry_"+HermesExport.hash(target+"\n"+destination);
    }
    public Entry read(String target,String destination) {
        String text=api.persistence().preferences().getString(storageKey(target,destination));
        if(text==null || text.isBlank())return null;
        Entry entry=HermesExport.JSON.fromJson(text,Entry.class);
        if(entry==null || !"acas-hermes-registry-1".equals(entry.format) || entry.ledger==null || entry.credentialIdentities==null)
            throw new IllegalArgumentException("Invalid persistent export history");
        entry.ledger=HermesExport.readLedger(HermesExport.JSON.toJson(entry.ledger));return entry;
    }
    public void save(String target,String destination,HermesExport.Ledger ledger,Map<String,String> identities,String objective) {
        synchronized(HermesHistoryRegistry.class) {
            Entry entry=read(target,destination);
            if(entry==null || !Objects.equals(entry.ledger.projectId,ledger.projectId))entry=new Entry();
            HermesExport.Ledger copy=HermesExport.readLedger(HermesExport.JSON.toJson(ledger));
            if(entry.ledger!=null)copy.exported.addAll(entry.ledger.exported);
            entry.ledger=copy;
            entry.objective=objective;
            for(var identity:identities.entrySet())entry.credentialIdentities.merge(identity.getKey(),identity.getValue(),(a,b)->a.equals(b)?a:"");
            api.persistence().preferences().setString(storageKey(target,destination),HermesExport.JSON.toJson(entry));
        }
    }
    public static String credentials(ActorProfile actor,Set<String> identityHeaders) {
        List<String> values=new ArrayList<>();
        for(String[] h:actor.getHeaders()) {
            if(h==null || h.length<2 || h[0]==null || h[1]==null || h[1].isBlank())continue;
            String name=h[0].toLowerCase(Locale.ROOT);
            if(identityHeaders.contains(name))values.add(name+":"+h[1]);
        }
        if(values.isEmpty())return null;
        Collections.sort(values);return HermesExport.hash(values.toString());
    }
    public static Map<String,String> identities(ActorStore store,HermesExport.Ledger ledger) {
        Map<String,String> result=new HashMap<>();
        for(ActorProfile actor:store.getAllActors()) {
            String fingerprint=credentials(actor,store.getAllIdentityHeaderNames()),id=ledger.actorKeys.get(actor.getId());
            if(fingerprint!=null && id!=null && !id.isBlank())result.merge(fingerprint,id,(a,b)->a.equals(b)?a:"");
            if(id!=null && !id.isBlank())for(String account:ActorIdentityRules.fingerprints(store,actor))result.merge(account,id,(a,b)->a.equals(b)?a:"");
        }
        return result;
    }
    /** Never merge users on display name or colour alone. Unknown identities stay visibly unresolved. */
    public static void mapActors(ActorStore store,Entry entry) {
        Map<String,Integer> occurrences=new HashMap<>();
        Map<String,Set<String>> accountKeys=new HashMap<>();
        for(ActorProfile a:store.getAllActors()) {
            String f=credentials(a,store.getAllIdentityHeaderNames());if(f!=null)occurrences.merge(f,1,Integer::sum);
            Set<String> accounts=ActorIdentityRules.fingerprints(store,a);accountKeys.put(a.getId(),accounts);
            for(String account:accounts)occurrences.merge(account,1,Integer::sum);
        }
        for(ActorProfile actor:store.getAllActors()) {
            if(entry.ledger.actorKeys.containsKey(actor.getId()))continue;
            Set<String> accounts=accountKeys.get(actor.getId());
            if(!accounts.isEmpty()) {
                Set<String> matches=new HashSet<>();boolean ambiguous=false;
                for(String account:accounts) {
                    String candidate=entry.credentialIdentities.get(account);
                    if(occurrences.get(account)!=1 || "".equals(candidate))ambiguous=true;
                    if(candidate!=null && !candidate.isBlank())matches.add(candidate);
                }
                if(!ambiguous && matches.size()==1)entry.ledger.actorKeys.put(actor.getId(),matches.iterator().next());
                continue;
            }
            String fingerprint=credentials(actor,store.getAllIdentityHeaderNames());
            String match=fingerprint==null?null:entry.credentialIdentities.get(fingerprint);
            if(match!=null && !match.isBlank() && occurrences.get(fingerprint)==1)entry.ledger.actorKeys.put(actor.getId(),match);
        }
    }
}
