package com.acas.export;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;

/** Owner-only, traversal-safe workspace and delivery files. */
public final class SecureFiles {
    private SecureFiles() {}

    private static final Set<PosixFilePermission> DIR_PERMISSIONS = EnumSet.of(
        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> FILE_PERMISSIONS = EnumSet.of(
        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    public static void createDirectories(Path root) throws IOException {
        Path absolute = root.toAbsolutePath().normalize();
        Path current = absolute.getRoot();
        if (current == null) throw new IOException("Invalid workspace root");
        for (Path part : absolute) {
            current = current.resolve(part);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(current)) throw new IOException("Symbolic links are not allowed in the workspace");
                if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Workspace path is not a directory");
            } else {
                Files.createDirectory(current);
                ownerOnly(current, true);
            }
        }
    }

    public static Path write(Path root, String name, byte[] bytes, boolean replace) throws IOException {
        Path target = resolve(root, name);
        createDirectories(root);
        if (Files.isSymbolicLink(target)) throw new IOException("Refusing to write through a symbolic link");
        Path temp = target.resolveSibling("." + target.getFileName() + ".tmp-" + UUID.randomUUID());
        try {
            try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(temp,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            ownerOnly(temp, false);
            if (!replace && Files.exists(target, LinkOption.NOFOLLOW_LINKS))
                throw new FileAlreadyExistsException(target.toString());
            if (replace) Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            else Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE);
            ownerOnly(target, false);
            return target;
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    public static byte[] read(Path root, String name, long maxBytes) throws IOException {
        Path target = resolve(root, name);
        if (Files.isSymbolicLink(target)) throw new IOException("Refusing to read a symbolic link");
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) throw new IOException("File is missing");
        long size = Files.size(target);
        if (size < 0 || size > maxBytes) throw new IOException("File exceeds the permitted size");
        return Files.readAllBytes(target);
    }

    public static Path resolve(Path root, String name) throws IOException {
        if (name == null || name.isBlank() || name.length() > 240) throw new IOException("Invalid file name");
        if (name.contains("/") || name.contains("\\") || name.contains(":") || name.contains("\0")
            || name.equals(".") || name.equals("..") || name.endsWith(".") || name.endsWith(" ")) throw new IOException("Invalid file name");
        if (name.matches("(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(\\..*)?")) throw new IOException("Reserved file name");
        Path base = root.toAbsolutePath().normalize();
        Path target = base.resolve(name).normalize();
        if (!target.getParent().equals(base)) throw new IOException("Path traversal is not allowed");
        return target;
    }

    private static void ownerOnly(Path path, boolean directory) {
        try {
            Files.setPosixFilePermissions(path, directory ? DIR_PERMISSIONS : FILE_PERMISSIONS);
        } catch (UnsupportedOperationException | IOException ignored) {
            java.io.File file = path.toFile();
            file.setReadable(false, false);
            file.setWritable(false, false);
            file.setReadable(true, true);
            file.setWritable(true, true);
            if (directory) file.setExecutable(true, true);
        }
    }
}
