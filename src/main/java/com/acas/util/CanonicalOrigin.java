package com.acas.util;

import java.net.*;
import java.util.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.acas.model.ActorProfile;

/** Exact-origin validation. Errors deliberately omit supplied URLs/credentials. */
public final class CanonicalOrigin {
    private CanonicalOrigin() {}
    public static String of(String value) {
        try {
            if(value==null || value.isBlank() || !value.equals(value.trim()))throw invalid();
            URI uri=new URI(value);
            String scheme=Objects.toString(uri.getScheme(),"").toLowerCase(Locale.ROOT);
            if(!Set.of("http","https").contains(scheme) || uri.isOpaque() || uri.getRawFragment()!=null || uri.getRawUserInfo()!=null)throw invalid();
            String authority=uri.getRawAuthority();
            if(authority==null || authority.isEmpty() || authority.contains("@") || authority.contains("%"))throw invalid();
            String host,portText=null;
            if(authority.startsWith("[")) {
                int end=authority.indexOf(']');if(end<0)throw invalid();
                host=ipv6(authority.substring(1,end));
                String tail=authority.substring(end+1);
                if(!tail.isEmpty()){if(!tail.startsWith(":"))throw invalid();portText=tail.substring(1);}
            } else {
                int colon=authority.indexOf(':');
                if(colon>=0){host=authority.substring(0,colon);portText=authority.substring(colon+1);}else host=authority;
                if(host.isEmpty() || host.endsWith(".") || host.contains(":"))throw invalid();
                host=IDN.toASCII(host,IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
                if(host.length()>253)throw invalid();
                for(String label:host.split("\\.",-1))if(label.isEmpty() || label.length()>63)throw invalid();
                if(host.matches("[0-9.]+")) {
                    String[] octets=host.split("\\.",-1);if(octets.length!=4)throw invalid();
                    for(String octet:octets)if(octet.length()>1 && octet.startsWith("0") || Integer.parseInt(octet)>255)throw invalid();
                }
            }
            int port=scheme.equals("https")?443:80;
            if(portText!=null){if(!portText.matches("[0-9]{1,5}"))throw invalid();port=Integer.parseInt(portText);if(port<1 || port>65535)throw invalid();}
            return scheme+"://"+host+((scheme.equals("https")&&port==443 || scheme.equals("http")&&port==80)?"":":"+port);
        } catch(Exception error){throw invalid();}
    }
    private static String ipv6(String literal)throws Exception {
        if(!literal.contains(":") || !literal.matches("[0-9a-fA-F:.]+"))throw invalid();
        byte[] bytes=InetAddress.getByName(literal).getAddress(); // Numeric IPv6 literal only; no DNS.
        if(bytes.length==4){byte[] mapped=new byte[16];mapped[10]=(byte)255;mapped[11]=(byte)255;System.arraycopy(bytes,0,mapped,12,4);bytes=mapped;}
        int[] words=new int[8];for(int i=0;i<8;i++)words[i]=(bytes[i*2]&255)*256+(bytes[i*2+1]&255);
        int start=-1,length=0;
        for(int i=0;i<8;){if(words[i]!=0){i++;continue;}int j=i;while(j<8 && words[j]==0)j++;if(j-i>length && j-i>=2){start=i;length=j-i;}i=j;}
        StringBuilder out=new StringBuilder("[");
        for(int i=0;i<8;i++) {if(i==start){out.append("::");i+=length-1;continue;}if(out.length()>1 && out.charAt(out.length()-1)!=':')out.append(':');out.append(Integer.toHexString(words[i]));}
        return out.append(']').toString();
    }
    public static String actor(ActorProfile actor){if(actor==null)throw invalid();return of(actor.getIdentitySourceUrl());}
    public static String request(HttpRequest request) {
        if(request==null || request.httpService()==null)throw new IllegalArgumentException("Request HTTP service is required");
        String origin=of(request.url());var service=request.httpService();
        String host=service.host();if(host!=null && host.contains(":") && !host.startsWith("["))host="["+host+"]";
        String serviceOrigin=of((service.secure()?"https":"http")+"://"+host+":"+service.port());
        if(!origin.equals(serviceOrigin))throw new IllegalArgumentException("URL and HTTP service origins disagree");
        Set<String> seen=new HashSet<>();
        for(var h:request.headers())if(h.name().equalsIgnoreCase("Host") || h.name().equalsIgnoreCase(":authority")) {
            if(!seen.add(h.name().toLowerCase(Locale.ROOT)) || !origin.equals(of(origin.substring(0,origin.indexOf(":"))+"://"+h.value())))
                throw new IllegalArgumentException("Host/authority and request origin disagree");
        }
        if(seen.isEmpty())throw new IllegalArgumentException("Request authority is missing");
        return origin;
    }
    public static void requireActorRequest(ActorProfile actor,HttpRequest request){if(!actor(actor).equals(request(request)))throw new IllegalArgumentException("Actor and request origins disagree");}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("A valid exact HTTP(S) origin is required; credentials, fragments and ambiguous authority are forbidden");}
}
