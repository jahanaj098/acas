package com.acas.util;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.acas.model.ActorProfile;
import com.acas.store.ActorStore;
import java.util.*;

/** One policy for ownership, replay and anonymous requests. Raw evidence is never edited. */
public final class CredentialPolicy {
    public enum Kind { SESSION, CSRF, CONTEXT, METADATA }
    private final java.util.function.Function<String,String> settings;
    public CredentialPolicy() { this(key -> ""); }
    public CredentialPolicy(ActorStore store) { this(store::getGlobalSetting); }
    private CredentialPolicy(java.util.function.Function<String,String> settings) { this.settings=settings; }
    private boolean configured(String key,String name) {
        String value=settings.apply("credential_"+key);
        return value!=null && Arrays.stream(value.split("[,\\s]+")) .anyMatch(name::equalsIgnoreCase);
    }
    public static boolean csrf(String name) {
        String n=name.toLowerCase(Locale.ROOT);
        return n.contains("csrf") || n.contains("xsrf") || n.equals("__requestverificationtoken") || n.equals("authenticity_token");
    }
    public Kind header(String name) {
        String n=name.toLowerCase(Locale.ROOT);
        if(csrf(n) || configured("csrf_headers",n))return Kind.CSRF;
        if(configured("session_headers",n))return Kind.SESSION;
        if(configured("context_headers",n))return Kind.CONTEXT;
        if(n.equals("authorization") || n.equals("proxy-authorization") || n.equals("bearer") || n.equals("jwt")
            || n.equals("token") || n.equals("session") || n.contains("auth") || n.contains("token")
            || n.contains("api-key") || n.contains("apikey") || n.contains("session"))return Kind.SESSION;
        if(Set.of("x-tenant-id","x-device-id","x-client-id","x-user-id","x-account-id","x-organization-id").contains(n))return Kind.CONTEXT;
        return Kind.METADATA;
    }
    public Kind cookie(String name) {
        String n=name.toLowerCase(Locale.ROOT);
        if(csrf(n) || configured("csrf_cookies",name))return Kind.CSRF;
        if(configured("session_cookies",name))return Kind.SESSION;
        if(Set.of("login_state","mfa_verified","user_id","tenant_id","device_id","remember_me").contains(n))return Kind.CONTEXT;
        if(n.contains("session") || n.contains("auth") || n.contains("token") || n.equals("sid")
            || n.contains("sessid") || n.matches("(?:.*[_.-])?sess(?:[_.-].*)?") || n.equals("connect.sid") || n.equals("jwt")
            || Set.of("password","passwd","api_key","apikey","access_key","client_secret").contains(n))return Kind.SESSION;
        return Kind.METADATA;
    }
    public boolean managedHeader(String name) {return name.equalsIgnoreCase("cookie") || header(name)!=Kind.METADATA;}
    public static Map<String,String> cookies(String value) {
        Map<String,String> result=new LinkedHashMap<>();
        if(value!=null)for(String pair:value.split(";")) {
            int split=pair.indexOf('=');
            if(split>0) {
                String name=pair.substring(0,split).trim();
                if(result.putIfAbsent(name,pair.substring(split+1).trim())!=null)
                    throw new IllegalArgumentException("Duplicate cookie name; actor identity is ambiguous");
            }
        }
        return result;
    }
    public boolean matches(HttpRequest request,ActorProfile actor) {
        Map<String,String> incoming=new LinkedHashMap<>();
        Map<String,String> saved=new LinkedHashMap<>();
        try {
            for(String[] h:actor.getHeaders()) {
                if(h[0].equalsIgnoreCase("Cookie")) {
                    addSessionCookies(saved,h[1]);
                } else if(header(h[0])==Kind.SESSION)saved.put("header:"+h[0].toLowerCase(Locale.ROOT),h[1]);
            }
            boolean cookieHeaders=false;
            if(request.headers()!=null)for(var h:request.headers())if(h.name().equalsIgnoreCase("Cookie")) {
                cookieHeaders=true;addSessionCookies(incoming,h.value());
            }
            if(!cookieHeaders)addSessionCookies(incoming,request.headerValue("Cookie"));
            for(String key:saved.keySet())if(key.startsWith("header:")) {
                String value=request.headerValue(key.substring(7));
                if(value!=null)incoming.put(key,value);
            }
            if(request.headers()!=null)for(var h:request.headers())if(header(h.name())==Kind.SESSION) {
                String key="header:"+h.name().toLowerCase(Locale.ROOT);
                if(incoming.containsKey(key) && !Objects.equals(incoming.get(key),h.value()))return false;
                incoming.put(key,h.value());
            }
            // Any conflicting supplied credential disqualifies the actor; absent schemes are allowed.
            boolean matched=false;
            for(var item:incoming.entrySet()) {
                if(!saved.containsKey(item.getKey()) || !Objects.equals(saved.get(item.getKey()),item.getValue()))return false;
                if(!item.getValue().isBlank())matched=true;
            }
            return matched;
        } catch(IllegalArgumentException e) {return false;}
    }
    // Ignore unrelated duplicate cookies before checking identity, but never guess
    // which value a server uses when a session cookie occurs more than once.
    private void addSessionCookies(Map<String,String> target,String value) {
        if(value==null)return;
        for(String pair:value.split(";")) {
            int split=pair.indexOf('=');
            if(split<=0)continue;
            String name=pair.substring(0,split).trim();
            if(cookie(name)!=Kind.SESSION)continue;
            if(target.putIfAbsent("cookie:"+name,pair.substring(split+1).trim())!=null)
                throw new IllegalArgumentException("Duplicate session cookie; actor identity is ambiguous");
        }
    }
    private void requireHeaderAuthentication(HttpRequest request) {
        var parameters=request.parameters();
        if(parameters!=null)for(var p:parameters) {
            if(p.type()==burp.api.montoya.http.message.params.HttpParameterType.COOKIE)continue;
            if(cookie(p.name())==Kind.CSRF || cookie(p.name())==Kind.SESSION)
                throw new IllegalArgumentException("Automatic replay skipped: authentication/CSRF parameter '"+p.name()+"' requires a request-specific token rule");
        }
    }
    public HttpRequest anonymous(HttpRequest original,Set<String> extra) {
        requireHeaderAuthentication(original);
        HttpRequest result=original;
        for(var h:original.headers())if(managedHeader(h.name()) || PwnFoxColors.HEADER.equalsIgnoreCase(h.name())
            || extra.contains(h.name().toLowerCase(Locale.ROOT)))result=result.withRemovedHeader(h.name());
        return result;
    }
    public HttpRequest swap(HttpRequest original,ActorProfile actor,Set<String> extra) {
        CanonicalOrigin.requireActorRequest(actor,original);
        HttpRequest result=anonymous(original,extra);
        for(String[] h:actor.getHeaders())if(managedHeader(h[0]))result=result.withHeader(h[0],h[1]);
        String color=PwnFoxColors.headerValue(actor.getPwnfoxColor());
        return color==null?result:result.withHeader(PwnFoxColors.HEADER,color);
    }
}
