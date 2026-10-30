package com.acas.export;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.acas.model.ActorProfile;
import com.acas.store.ActorStore;
import java.util.*;
import java.util.concurrent.*;

/** One background GET to the actor's exact configured origin; never follows redirects. */
public final class ActorIdentityLookup implements AutoCloseable {
    interface Transport { Reply get(ActorIdentityRules.Rule rule,ActorProfile snapshot) throws Exception; }
    record Reply(int status,String body) {}
    public record TestResult(boolean success,int httpStatus,String value,String message) {}
    /** Preview an unsaved rule without persisting proof or touching actor status/history. */
    public CompletableFuture<TestResult> test(ActorProfile actor,ActorIdentityRules.Rule proposed) {
        final ActorIdentityRules.Rule rule;
        final ActorProfile snapshot=new ActorProfile();
        try {
            rule=ActorIdentityRules.validate(proposed);
            if(actor==null || store.getActor(actor.getId())!=actor)throw new IllegalArgumentException("Select an existing actor.");
            if(!Objects.equals(origin(actor),ActorIdentityRules.origin(rule.endpoint())))throw new IllegalArgumentException("The endpoint must match the selected actor's known target origin. Update the actor from a request if its target is unknown.");
            if(HermesHistoryRegistry.credentials(actor,store.getAllIdentityHeaderNames())==null)throw new IllegalArgumentException("The selected actor has no authentication headers.");
            snapshot.setId(actor.getId());snapshot.setHeaders(actor.getHeaders().stream().map(h->h.clone()).toList());
        }catch(Exception error){return CompletableFuture.completedFuture(new TestResult(false,0,null,error.getMessage()));}
        String signature=ActorIdentityRules.proofKey(store,snapshot,rule);
        try{return CompletableFuture.supplyAsync(()->{
            try{
                Reply reply=transport.get(rule,snapshot);
                if(store.getActor(actor.getId())!=actor || !signature.equals(ActorIdentityRules.proofKey(store,actor,rule)) || !Objects.equals(origin(actor),ActorIdentityRules.origin(rule.endpoint())))
                    return new TestResult(false,reply.status(),null,"Actor changed during the test. Test again with the current credentials.");
                if(reply.status()<200 || reply.status()>=300)return new TestResult(false,reply.status(),null,"Endpoint did not return a successful response. Redirects are not followed.");
                String value=ActorIdentityRules.value(rule,"HTTP/1.1 "+reply.status()+" OK\r\n\r\n"+reply.body());
                return value==null?new TestResult(false,reply.status(),null,"No unique identity found. Check the field and response format; empty, ambiguous or malformed values are rejected.")
                    :new TestResult(true,reply.status(),value,"Identity extracted. Rule and actor mapping were not changed.");
            }catch(Exception error){return new TestResult(false,0,null,"Identity test failed ("+error.getClass().getSimpleName()+"). Check the connection and actor session.");}
        },executor);}catch(RejectedExecutionException error){return CompletableFuture.completedFuture(new TestResult(false,0,null,"Identity service is stopped. Reload ACAS."));}
    }
    private final ActorStore store;
    private final Transport transport;
    private final ExecutorService executor=Executors.newFixedThreadPool(2,r->{Thread t=new Thread(r,"ACAS identity lookup");t.setDaemon(true);return t;});
    private final Map<String,String> scheduled=new ConcurrentHashMap<>();
    public ActorIdentityLookup(MontoyaApi api,ActorStore store){this(store,(rule,actor)->{
        HttpRequest request=HttpRequest.httpRequestFromUrl(rule.endpoint()).withMethod("GET");
        for(String[] h:actor.getHeaders()) {
            if(h==null || h.length<2 || h[0]==null || h[1]==null)continue;
            if(h[0].contains("\r") || h[0].contains("\n") || h[1].contains("\r") || h[1].contains("\n"))throw new IllegalArgumentException("Invalid actor header");
            if(Set.of("host","content-length","transfer-encoding","connection","accept-encoding", "content-type").contains(h[0].toLowerCase(Locale.ROOT)))continue;
            request=request.withHeader(h[0],h[1]);
        }
        request=request.withHeader("Accept-Encoding","identity").withHeader(com.acas.engine.ReplayEngine.ACAS_INTERNAL_HEADER,"true");
        var rr=com.acas.engine.ReplayGate.send(api,request);
        if(rr.response()==null)return new Reply(0,"");
        return new Reply(rr.response().statusCode(),rr.response().bodyToString());
    });}
    ActorIdentityLookup(ActorStore store,Transport transport){this.store=store;this.transport=transport;}
    static String origin(ActorProfile actor) {
        if(actor.getIdentitySourceUrl()!=null)try{return ActorIdentityRules.origin(actor.getIdentitySourceUrl());}catch(Exception ignored){}
        Set<String> origins=new HashSet<>();for(var h:actor.getCaptureHistory())try{origins.add(ActorIdentityRules.origin(h.url));}catch(Exception ignored){}
        return origins.size()==1?origins.iterator().next():null;
    }
    public void schedule(ActorProfile actor){
        try {
            String origin=origin(actor);
            if(origin==null){actor.setIdentityLookupStatus("Unknown target; update from a request");return;}
            var rule=ActorIdentityRules.load(store).stream().filter(r->ActorIdentityRules.origin(r.endpoint()).equals(origin)).findFirst().orElse(null);
            if(rule==null){actor.setIdentityLookupStatus("No target identity rule");return;}
            if(HermesHistoryRegistry.credentials(actor,store.getAllIdentityHeaderNames())==null){actor.setIdentityLookupStatus("No authentication headers");return;}
            ActorProfile snapshot=new ActorProfile();snapshot.setId(actor.getId());
            snapshot.setHeaders(actor.getHeaders().stream().map(h->h.clone()).toList());
            String signature=ActorIdentityRules.proofKey(store,snapshot,rule);
            if(signature.equals(scheduled.put(actor.getId(),signature)))return;
            actor.getAutomaticIdentityProofs().clear();actor.setIdentityLookupStatus("Checking identity…");store.persistIdentityResult();
            executor.submit(()->{
                try {
                    Reply reply=transport.get(rule,snapshot);
                    String value=reply.status()>=200 && reply.status()<300?ActorIdentityRules.value(rule,"HTTP/1.1 "+reply.status()+" OK\r\n\r\n"+reply.body()):null;
                    if(!current(actor,signature,rule))return;
                    if(value!=null){actor.getAutomaticIdentityProofs().put(signature,ActorIdentityRules.fingerprint(rule,value));actor.setRecognisedAccount(value,signature);actor.setIdentityLookupStatus("Identity recognized");}
                    else{actor.setIdentityLookupStatus("Identity unresolved (HTTP "+reply.status()+")");scheduled.remove(actor.getId(),signature);}
                    store.persistIdentityResult();
                }catch(Exception error){if(current(actor,signature,rule)){actor.setIdentityLookupStatus("Lookup failed; save/update to retry");scheduled.remove(actor.getId(),signature);store.persistIdentityResult();}}
            });
        }catch(Exception error){actor.setIdentityLookupStatus("Identity lookup unavailable");}
    }
    private boolean current(ActorProfile actor,String signature,ActorIdentityRules.Rule rule){
        return store.getActor(actor.getId())==actor && signature.equals(scheduled.get(actor.getId()))
            && signature.equals(ActorIdentityRules.proofKey(store,actor,rule))
            && Objects.equals(origin(actor),ActorIdentityRules.origin(rule.endpoint())) && ActorIdentityRules.load(store).contains(rule);
    }
    public void close(){store.setIdentityLookup(a->{});scheduled.clear();executor.shutdownNow();}
}
