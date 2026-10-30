package com.acas.export;

import com.acas.model.ActorProfile;
import com.acas.store.ActorStore;
import com.google.gson.*;
import java.net.URI;
import java.util.*;

/** Identity is extracted only from an authenticated, captured GET of the configured endpoint. */
public final class ActorIdentityRules {
    private static final String KEY="hermes_actor_identity_rules_v1";
    public record Rule(String endpoint,String format,String field) {}
    public static List<Rule> load(ActorStore store) {
        String json=store.getGlobalSetting(KEY);
        if(json==null || json.isBlank())return new ArrayList<>();
        Rule[] rules=HermesExport.JSON.fromJson(json,Rule[].class);
        if(rules==null)throw new IllegalArgumentException("Invalid identity rules");
        List<Rule> out=new ArrayList<>();for(Rule r:rules)out.add(validate(r));return out;
    }
    public static String origin(String value) {
        return com.acas.util.CanonicalOrigin.of(value);
    }
    static String endpoint(String value) {
        URI uri=URI.create(value);String path=uri.getRawPath();return origin(value)+(path==null||path.isEmpty()?"/":path)+(uri.getRawQuery()==null?"":"?"+uri.getRawQuery());
    }
    public static Rule validate(Rule rule) {
        if(rule==null || rule.endpoint()==null || rule.field()==null || rule.field().trim().isEmpty())throw new IllegalArgumentException("Endpoint and identity field are required");
        if(!Set.of("JSON","Text label").contains(rule.format()))throw new IllegalArgumentException("Choose JSON or Text label");
        return new Rule(endpoint(rule.endpoint().trim()),rule.format(),rule.field().trim());
    }
    public static void save(ActorStore store,Rule rule,boolean remove) {
        rule=validate(rule);List<Rule> rules=load(store);String target=origin(rule.endpoint());
        rules.removeIf(r->origin(r.endpoint()).equals(target));if(!remove)rules.add(rule);
        String json=HermesExport.JSON.toJson(rules);store.setGlobalSetting(KEY,json);
        if(!json.equals(store.getGlobalSetting(KEY)))throw new IllegalStateException("Identity rule could not be saved");
    }
    static String value(Rule rule,String raw) {
        if(raw==null)return null;int split=raw.indexOf("\r\n\r\n"),skip=4;
        if(split<0){split=raw.indexOf("\n\n");skip=2;}if(split<0)return null;
        String status=raw.substring(0,raw.indexOf('\n')<0?raw.length():raw.indexOf('\n')).trim();
        if(!status.matches("HTTP/[^ ]+ 2[0-9]{2}( .*)?"))return null;
        String body=raw.substring(split+skip);if(body.length()>1024*1024)return null;
        try {
            if(rule.format().equals("JSON")) {
                try(var reader=new com.google.gson.stream.JsonReader(new java.io.StringReader(body))) {
                    uniqueKeys(reader,0);
                    if(reader.peek()!=com.google.gson.stream.JsonToken.END_DOCUMENT)return null;
                }
                JsonElement current=JsonParser.parseString(body);
                String[] path=rule.field().startsWith("/")?rule.field().substring(1).split("/",-1):rule.field().split("\\.");
                for(String part:path){part=part.replace("~1","/").replace("~0","~");if(!current.isJsonObject() || !current.getAsJsonObject().has(part))return null;current=current.getAsJsonObject().get(part);}
                if(!current.isJsonPrimitive() || current.getAsJsonPrimitive().isBoolean())return null;
                String v=current.getAsString();return v.isBlank()?null:v;
            }
            String found=null;
            for(String line:body.split("\\R")) {
                int colon=line.indexOf(':');if(colon<0 || !line.substring(0,colon).trim().equals(rule.field()))continue;
                String v=line.substring(colon+1).trim();if(v.isEmpty())return null;
                if(found!=null)return null;found=v;
            }
            return found;
        }catch(Exception ignored){return null;}
    }
    private static void uniqueKeys(com.google.gson.stream.JsonReader reader,int depth) throws java.io.IOException {
        if(depth>64)throw new java.io.IOException("JSON nesting too deep");
        switch(reader.peek()) {
            case BEGIN_OBJECT -> {reader.beginObject();Set<String> names=new HashSet<>();while(reader.hasNext()){if(!names.add(reader.nextName()))throw new java.io.IOException("Duplicate JSON key");uniqueKeys(reader,depth+1);}reader.endObject();}
            case BEGIN_ARRAY -> {reader.beginArray();while(reader.hasNext())uniqueKeys(reader,depth+1);reader.endArray();}
            default -> reader.skipValue();
        }
    }
    private static boolean authenticated(ActorStore store,ActorProfile actor,String raw) {
        if(raw==null)return false;int split=raw.indexOf("\r\n\r\n");if(split<0)split=raw.indexOf("\n\n");if(split<0)return false;
        Map<String,String> headers=new HashMap<>();
        for(String line:raw.substring(0,split).split("\r?\n")) {
            int colon=line.indexOf(':');if(colon<0)continue;String name=line.substring(0,colon).trim().toLowerCase(Locale.ROOT);
            if(name.equals(com.acas.engine.ReplayEngine.ACAS_INTERNAL_HEADER.toLowerCase(Locale.ROOT)))return false;
            if(headers.put(name,line.substring(colon+1).trim())!=null)return false;
        }
        boolean any=false;
        for(String[] header:actor.getHeaders())if(header!=null && header.length>1 && store.getAllIdentityHeaderNames().contains(header[0].toLowerCase(Locale.ROOT)) && !header[1].isBlank()) {
            any=true;if(!header[1].trim().equals(headers.get(header[0].toLowerCase(Locale.ROOT))))return false;
        }
        return any;
    }
    public static Set<String> fingerprints(ActorStore store,ActorProfile actor) {
        Set<String> result=new HashSet<>();
        for(Rule rule:load(store)) {
            String automatic=actor.getAutomaticIdentityProofs().get(proofKey(store,actor,rule));
            Set<String> values=new HashSet<>();
            for(ActorProfile.HistoryEntry h:new ArrayList<>(actor.getCaptureHistory())) {
                try {
                    if(!"GET".equals(h.method) || h.status<200 || h.status>=300 || !endpoint(h.url).equals(rule.endpoint()) || !authenticated(store,actor,h.request))continue;
                    String value=value(rule,h.response);if(value!=null)values.add(value);
                }catch(Exception ignored){}
            }
            if(values.size()==1){String manual=fingerprint(rule,values.iterator().next());if(automatic==null || automatic.equals(manual))result.add(manual);}
            else if(values.isEmpty() && automatic!=null)result.add(automatic);
        }
        return result;
    }
    static String proofKey(ActorStore store,ActorProfile actor,Rule rule){return HermesExport.hash(HermesExport.JSON.toJson(rule)+"|"+HermesHistoryRegistry.credentials(actor,store.getAllIdentityHeaderNames()));}
    public static String recognisedAccount(ActorStore store,ActorProfile actor){return Objects.toString(recognisedIdentity(store,actor),"—");}
    public static String recognisedIdentity(ActorStore store,ActorProfile actor){
        if(actor.getRecognisedAccount()==null)return null;
        try{for(Rule rule:load(store)){
            String key=proofKey(store,actor,rule);
            if(key.equals(actor.getRecognisedAccountSignature()) && actor.getAutomaticIdentityProofs().containsKey(key)
                && Objects.equals(ActorIdentityLookup.origin(actor),origin(rule.endpoint())))return actor.getRecognisedAccount();
        }}catch(Exception ignored){}
        return null;
    }
    static String fingerprint(Rule rule,String value){return "account:"+HermesExport.hash(HermesExport.JSON.toJson(List.of(rule.endpoint(),rule.format(),rule.field(),value)));}
}
