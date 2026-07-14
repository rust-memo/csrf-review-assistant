package com.adminsec.csrf;

import burp.api.montoya.persistence.PersistedObject;
import com.adminsec.csrf.model.ReviewStatus;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class ProjectStore {
    private static final int MAX_NOTE_LENGTH = 50_000;
    private final PersistedObject data;
    public ProjectStore(PersistedObject data) { this.data = data; }

    public ReviewStatus status(String key) {
        if (data == null) return ReviewStatus.NEW;
        String value = data.getString("status." + safe(key));
        return ReviewStatus.from(value);
    }
    public String note(String key) {
        if (data == null) return "";
        String value = data.getString("note." + safe(key)); return value == null ? "" : value;
    }
    public void save(String key, ReviewStatus status, String note) {
        if (data == null) return;
        data.setString("status." + safe(key), status.name());
        String value = note == null ? "" : note;
        data.setString("note." + safe(key), value.length() <= MAX_NOTE_LENGTH ? value : value.substring(0, MAX_NOTE_LENGTH));
    }
    private static String safe(String key) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception error) { throw new IllegalStateException(error); }
    }
}
