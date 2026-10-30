package com.acas.export;
import com.acas.model.ActorProfile;
import com.acas.store.ActorStore;
import com.acas.util.*;
import com.google.gson.*;
import java.util.*;

/** Shared credential replacement contract for normal and session-only exports. */
public final class ActorContract {
 private ActorContract(){}
 public static JsonObject serialize(ActorStore store,ActorProfile actor,String mappedId) {
  if(mappedId==null || mappedId.isBlank())throw new IllegalArgumentException("Actor identity is required");
  String origin=CanonicalOrigin.actor(actor);
  var policy=new CredentialPolicy(store);var headers=new JsonArray();var groups=new JsonObject();
  for(var kind:CredentialPolicy.Kind.values())groups.add(kind.name().toLowerCase(Locale.ROOT),new JsonArray());
  Set<String> names=new HashSet<>();
  if(actor.getHeaders()==null)throw new IllegalArgumentException("Actor credential bundle is missing");
  for(String[] h:actor.getHeaders()) {
   if(h==null || h.length!=2 || h[0]==null || h[1]==null || !h[0].matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+") || h[1].contains("\r") || h[1].contains("\n") || h[1].indexOf(0)>=0)throw new IllegalArgumentException("Malformed actor header");
   if(!policy.managedHeader(h[0]))continue;
   if(!names.add(h[0].toLowerCase(Locale.ROOT)))throw new IllegalArgumentException("Duplicate managed header; update actor with an unambiguous bundle");
   headers.add(HermesExport.JSON.toJsonTree(h));
   if(h[0].equalsIgnoreCase("Cookie")) {
    for(var cookie:CredentialPolicy.cookies(h[1]).entrySet())entry(groups,policy.cookie(cookie.getKey()),"cookie",cookie.getKey(),cookie.getValue());
   } else entry(groups,policy.header(h[0]),"header",h[0],h[1]);
  }
  var result=new JsonObject();result.addProperty("actorId",mappedId);result.addProperty("name",actor.getName());result.addProperty("origin",origin);
  result.addProperty("role",actor.getRole());result.addProperty("roleLevel",actor.getRoleLevel());result.add("currentAuthenticationHeaders",headers);result.add("credentialClassification",groups);
  result.addProperty("identityLookupStatus",actor.getIdentityLookupStatus());result.addProperty("recognisedAccount",ActorIdentityRules.recognisedIdentity(store,actor));
  result.addProperty("sessionStatus",actor.getVerificationStatus()==null?"UNVERIFIED":actor.getVerificationStatus().name());return result;
 }
 private static void entry(JsonObject groups,CredentialPolicy.Kind kind,String location,String name,String value){var item=new JsonObject();item.addProperty("location",location);item.addProperty("name",name);item.addProperty("value",value);groups.getAsJsonArray(kind.name().toLowerCase(Locale.ROOT)).add(item);}
}
