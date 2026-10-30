package com.acas.export;

import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Gzip, authenticated encryption, then bounded attachments. Manifest is sent last. */
public final class HermesArchive {
    public static final int PART_BYTES = 7 * 1024 * 1024;
    public static final int MAX_PARTS = 512;
    public static final long MAX_JSON_BYTES = 1024L * 1024 * 1024;
    public static final long MAX_PART_BYTES = 64L * 1024 * 1024;
    private static final long MAX_TOTAL_BYTES = 1024L * 1024 * 1024;
    private static final long MAX_MANIFEST_BYTES = 4L * 1024 * 1024;
    public record FileData(String name, byte[] bytes) {}
    public static List<FileData> packJson(byte[] json,String batch,int partBytes) {
        if(partBytes<1)throw new IllegalArgumentException("Invalid part size");
        if(json.length>MAX_JSON_BYTES)throw new IllegalArgumentException("Export exceeds the archive size limit");
        if(json.length<=partBytes)return List.of(new FileData("acas-"+batch+".json",json));
        JsonObject manifest=new JsonObject();manifest.addProperty("format","acas-hermes-json-parts-1");manifest.addProperty("batchId",batch);
        manifest.addProperty("sha256",HermesExport.hash(json));
        addSummary(manifest,json);
        return split(json,batch,partBytes,manifest);
    }
    public static List<FileData> pack(byte[] json, String batch, char[] password, int partBytes) throws Exception {
        if (partBytes < 1) throw new IllegalArgumentException("Invalid part size");
        if (json.length > MAX_JSON_BYTES) throw new IllegalArgumentException("Export exceeds the archive size limit");
        if (password.length < 12) throw new IllegalArgumentException("Use a backup password of at least 12 characters");
        ByteArrayOutputStream zipped = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(zipped)) { gzip.write(json); }
        SecureRandom rng = new SecureRandom(); byte[] salt = new byte[16], nonce = new byte[12]; rng.nextBytes(salt); rng.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, derive(password,salt),new GCMParameterSpec(128,nonce));
        cipher.updateAAD(batch.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] encrypted = cipher.doFinal(zipped.toByteArray());
        JsonObject manifest = new JsonObject(); manifest.addProperty("format","acas-hermes-archive-1"); manifest.addProperty("batchId",batch);
        manifest.addProperty("cipher","AES-256-GCM"); manifest.addProperty("kdf","PBKDF2-HMAC-SHA256"); manifest.addProperty("iterations",210000);
        manifest.addProperty("compression","gzip"); manifest.addProperty("salt",Base64.getEncoder().encodeToString(salt));
        manifest.addProperty("nonce",Base64.getEncoder().encodeToString(nonce)); manifest.addProperty("sha256",HermesExport.hash(encrypted));
        addSummary(manifest,json);
        return split(encrypted,batch,partBytes,manifest);
    }
    private static void addSummary(JsonObject manifest, byte[] json) {
        try {
            JsonElement parsed = JsonParser.parseString(new String(json, java.nio.charset.StandardCharsets.UTF_8));
            if (!parsed.isJsonObject()) return;
            var summary = HermesPreflight.of(parsed.getAsJsonObject());
            manifest.addProperty("activeTestingAllowed", summary.activeTestingAllowed());
            manifest.addProperty("captureCount", summary.captures());
            manifest.addProperty("probeCount", summary.probes());
            JsonArray origins = new JsonArray();
            for (String origin : summary.origins()) origins.add(origin);
            manifest.add("exactOrigins", origins);
            JsonObject safety = new JsonObject();
            summary.operationSafety().forEach(safety::addProperty);
            manifest.add("operationSafety", safety);
        } catch (RuntimeException ignored) {
        }
    }

    private static List<FileData> split(byte[] encrypted,String batch,int partBytes,JsonObject manifest) {
        List<FileData> files = new ArrayList<>(); JsonArray parts = new JsonArray();
        for (int offset = 0, number = 1; offset < encrypted.length; offset += partBytes,number++) {
            byte[] data = Arrays.copyOfRange(encrypted,offset,Math.min(encrypted.length,offset+partBytes));
            String name = "acas-" + batch + String.format(Locale.ROOT,".part%04d",number);
            files.add(new FileData(name,data)); JsonObject part = new JsonObject();
            part.addProperty("name",name); part.addProperty("bytes",data.length); part.addProperty("sha256",HermesExport.hash(data)); parts.add(part);
        }
        if(files.size()>MAX_PARTS)throw new IllegalArgumentException("Export exceeds the archive part limit");
        manifest.add("parts",parts); manifest.addProperty("partCount",files.size());
        files.add(new FileData("acas-"+batch+"-manifest.json",HermesExport.JSON.toJson(manifest).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        return files;
    }
    private static SecretKeySpec derive(char[] password,byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password,salt,210000,256);
        try { return new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(),"AES"); }
        finally { spec.clearPassword(); }
    }
    public static byte[] recover(Path manifestPath, char[] password) throws Exception {
        if(Files.isSymbolicLink(manifestPath) || !Files.isRegularFile(manifestPath,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Manifest must be a regular file");
        if(Files.size(manifestPath)>MAX_MANIFEST_BYTES)throw new IOException("Manifest exceeds the size limit");
        JsonObject manifest = JsonParser.parseString(Files.readString(manifestPath)).getAsJsonObject();
        String format=manifest.get("format").getAsString();
        if (!"acas-hermes-archive-1".equals(format) && !"acas-hermes-json-parts-1".equals(format)) throw new IOException("Unsupported archive format");
        if(!manifest.has("partCount") || !manifest.get("partCount").isJsonPrimitive())throw new IOException("Invalid manifest");
        int partCount=manifest.get("partCount").getAsInt();
        JsonArray parts = manifest.getAsJsonArray("parts");
        if(parts==null || partCount<1 || partCount>MAX_PARTS || parts.size()!=partCount) throw new IOException("Incomplete manifest");
        ByteArrayOutputStream all = new ByteArrayOutputStream(); Path root = manifestPath.toAbsolutePath().getParent();
        Set<String> names = new HashSet<>();long total=0;
        for (JsonElement item : parts) {
            if(item==null || !item.isJsonObject())throw new IOException("Invalid manifest part");
            JsonObject part = item.getAsJsonObject();
            if(!part.has("name") || !part.has("bytes") || !part.has("sha256"))throw new IOException("Invalid manifest part");
            String name = part.get("name").getAsString();
            if (!name.matches("acas-[a-zA-Z0-9-]+\\.part[0-9]{4}") || !names.add(name)) throw new IOException("Invalid part name");
            if(!part.get("bytes").isJsonPrimitive() || !part.get("bytes").getAsJsonPrimitive().isNumber())throw new IOException("Invalid part size");
            long declared=part.get("bytes").getAsLong();
            if(declared<1 || declared>MAX_PART_BYTES)throw new IOException("Part size is outside the permitted range");
            Path file = root.resolve(name).normalize();
            if (!file.getParent().equals(root) || Files.isSymbolicLink(file) || !Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)) throw new IOException("Invalid part path");
            if(Files.size(file)!=declared)throw new IOException("Part missing or corrupt: " + name);
            byte[] bytes = Files.readAllBytes(file);
            total+=bytes.length;if(total>MAX_TOTAL_BYTES)throw new IOException("Archive exceeds the total size limit");
            if (bytes.length != declared || !HermesExport.hash(bytes).equals(part.get("sha256").getAsString())) throw new IOException("Part missing or corrupt: " + name);
            all.write(bytes);
        }
        byte[] encrypted = all.toByteArray();
        if (!HermesExport.hash(encrypted).equals(manifest.get("sha256").getAsString())) throw new IOException("Archive checksum mismatch");
        if("acas-hermes-json-parts-1".equals(format)) {
            if(encrypted.length>MAX_JSON_BYTES)throw new IOException("Archive exceeds the JSON size limit");
            return encrypted;
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,derive(password,Base64.getDecoder().decode(manifest.get("salt").getAsString())),new GCMParameterSpec(128,Base64.getDecoder().decode(manifest.get("nonce").getAsString())));
        cipher.updateAAD(manifest.get("batchId").getAsString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(cipher.doFinal(encrypted)))) {
            byte[] json=gzip.readNBytes((int)MAX_JSON_BYTES+1);
            if(json.length>MAX_JSON_BYTES)throw new IOException("Decompressed archive exceeds the JSON size limit");
            return json;
        }
    }
}
