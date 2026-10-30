package com.acas.store;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.acas.model.AcasFinding;
import com.acas.model.ActorProfile;
import com.acas.model.CapturedEndpoint;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * PersistenceManager handles auto-save/load of:
 * - Findings
 * - Actor Profiles
 * - Hunt Queue
 * - Configuration
 *
 * Files stored in ~/.burp/extensions/acas_data/ or {workspace}/.acas/
 */
public class PersistenceManager {
    private static final String ACAS_DATA_DIR = ".acas";
    private static final String FINDINGS_FILE = "findings.json";
    private static final String ACTORS_FILE = "actors.json";
    private static final String QUEUE_FILE = "hunt_queue.json";
    private static final String CONFIG_FILE = "config.json";

    private final Path dataDir;
    private final Gson gson;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ACAS-Persistence");
        t.setDaemon(true);
        return t;
    });

    public PersistenceManager(String workspaceRoot) throws IOException {
        // Use workspace root or user home
        String root = workspaceRoot != null && !workspaceRoot.isEmpty() 
            ? workspaceRoot 
            : System.getProperty("user.home");
        
        this.dataDir = Paths.get(root, ACAS_DATA_DIR);
        Files.createDirectories(dataDir);
        
        this.gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();
    }

    /**
     * Load complete workspace state from disk.
     */
    public WorkspaceState loadWorkspaceState() {
        WorkspaceState state = new WorkspaceState();
        
        try {
            // Load actors
            File actorsFile = dataDir.resolve(ACTORS_FILE).toFile();
            if (actorsFile.exists()) {
                try (FileReader reader = new FileReader(actorsFile)) {
                    ActorProfile[] actorsArray = gson.fromJson(reader, ActorProfile[].class);
                    if (actorsArray != null) {
                        for (ActorProfile actor : actorsArray) {
                            if (actor != null) actor.migrateLegacyRoleLevel();
                            state.actors.add(actor);
                        }
                    }
                }
            }

            // Load findings
            File findingsFile = dataDir.resolve(FINDINGS_FILE).toFile();
            if (findingsFile.exists()) {
                try (FileReader reader = new FileReader(findingsFile)) {
                    AcasFinding[] findingsArray = gson.fromJson(reader, AcasFinding[].class);
                    if (findingsArray != null) {
                        for (AcasFinding finding : findingsArray) {
                            state.findings.add(finding);
                        }
                    }
                }
            }

            // Load hunt queue
            File queueFile = dataDir.resolve(QUEUE_FILE).toFile();
            if (queueFile.exists()) {
                try (FileReader reader = new FileReader(queueFile)) {
                    CapturedEndpoint[] queueArray = gson.fromJson(reader, CapturedEndpoint[].class);
                    if (queueArray != null) {
                        for (CapturedEndpoint ep : queueArray) {
                            state.huntQueue.add(ep);
                        }
                    }
                }
            }

            // Load config
            File configFile = dataDir.resolve(CONFIG_FILE).toFile();
            if (configFile.exists()) {
                try (FileReader reader = new FileReader(configFile)) {
                    WorkspaceState.WorkspaceConfig config = gson.fromJson(reader, WorkspaceState.WorkspaceConfig.class);
                    if (config != null) {
                        state.config = config;
                    }
                }
            }

            state.lastSaved = System.currentTimeMillis();
            return state;
        } catch (JsonSyntaxException | IOException e) {
            System.err.println("ACAS: Error loading workspace state: " + e.getMessage());
            return state; // Return empty state on error
        }
    }

    /**
     * Async save findings to findings.json
     */
    public void saveFindingsAsync(List<AcasFinding> findings) {
        executor.submit(() -> {
            try {
                File file = dataDir.resolve(FINDINGS_FILE).toFile();
                try (FileWriter writer = new FileWriter(file)) {
                    gson.toJson(findings.toArray(), writer);
                }
            } catch (IOException e) {
                System.err.println("ACAS Persistence: Error saving findings: " + e.getMessage());
            }
        });
    }

    /**
     * Sync save actors to actors.json
     */
    public void saveActorsSync(List<ActorProfile> actors) {
        try {
            File file = dataDir.resolve(ACTORS_FILE).toFile();
            try (FileWriter writer = new FileWriter(file)) {
                gson.toJson(actors.toArray(), writer);
            }
        } catch (IOException e) {
            System.err.println("ACAS Persistence: Error saving actors: " + e.getMessage());
        }
    }

    /**
     * Async save hunt queue to hunt_queue.json
     */
    public void saveHuntQueueAsync(List<CapturedEndpoint> queue) {
        executor.submit(() -> {
            try {
                File file = dataDir.resolve(QUEUE_FILE).toFile();
                try (FileWriter writer = new FileWriter(file)) {
                    gson.toJson(queue.toArray(), writer);
                }
            } catch (IOException e) {
                System.err.println("ACAS Persistence: Error saving hunt queue: " + e.getMessage());
            }
        });
    }

    /**
     * Sync save config to config.json
     */
    public void saveConfigSync(WorkspaceState.WorkspaceConfig config) {
        try {
            File file = dataDir.resolve(CONFIG_FILE).toFile();
            try (FileWriter writer = new FileWriter(file)) {
                gson.toJson(config, writer);
            }
        } catch (IOException e) {
            System.err.println("ACAS Persistence: Error saving config: " + e.getMessage());
        }
    }

    /**
     * Export all workspace state to ZIP file.
     */
    public File exportWorkspaceToZip(String outputPath) throws IOException {
        String timestamp = Instant.now().toString().replace(":", "-").substring(0, 16);
        File zipFile = new File(outputPath, "acas_backup_" + timestamp + ".zip");

        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zipFile.toPath()))) {
            File findingsFile = dataDir.resolve(FINDINGS_FILE).toFile();
            if (findingsFile.exists()) {
                zos.putNextEntry(new ZipEntry(FINDINGS_FILE));
                Files.copy(findingsFile.toPath(), zos);
                zos.closeEntry();
            }

            File actorsFile = dataDir.resolve(ACTORS_FILE).toFile();
            if (actorsFile.exists()) {
                zos.putNextEntry(new ZipEntry(ACTORS_FILE));
                Files.copy(actorsFile.toPath(), zos);
                zos.closeEntry();
            }

            File queueFile = dataDir.resolve(QUEUE_FILE).toFile();
            if (queueFile.exists()) {
                zos.putNextEntry(new ZipEntry(QUEUE_FILE));
                Files.copy(queueFile.toPath(), zos);
                zos.closeEntry();
            }

            File configFile = dataDir.resolve(CONFIG_FILE).toFile();
            if (configFile.exists()) {
                zos.putNextEntry(new ZipEntry(CONFIG_FILE));
                Files.copy(configFile.toPath(), zos);
                zos.closeEntry();
            }
        }

        return zipFile;
    }

    /**
     * Import workspace state from ZIP file.
     */
    public void importWorkspaceFromZip(File zipFile) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(zipFile.toPath()))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path filePath = dataDir.resolve(entry.getName());
                Files.createDirectories(filePath.getParent());
                Files.copy(zis, filePath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                zis.closeEntry();
            }
        }
    }

    /**
     * Get data directory path for reference.
     */
    public Path getDataDir() {
        return dataDir;
    }

    /**
     * Shutdown executor
     */
    public void shutdown() {
        executor.shutdown();
    }
}
