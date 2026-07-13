package com.adminsec.csrf;

import burp.api.montoya.persistence.Preferences;

import java.util.*;

public final class CsrfSettings {
    public enum Sensitivity { CONSERVATIVE, BALANCED, AGGRESSIVE }

    private volatile boolean scopeOnly = true;
    private volatile Sensitivity sensitivity = Sensitivity.CONSERVATIVE;
    private volatile int historyLimit = 10_000;
    private volatile int maxBodyBytes = 1_048_576;
    private volatile Set<String> customTokenNames = Set.of();
    private volatile Set<String> customAuthCookies = Set.of();
    private volatile Set<String> customSensitiveWords = Set.of();
    private volatile List<String> ignoredHosts = List.of();
    private volatile List<String> ignoredPaths = List.of();

    public static CsrfSettings load(Preferences preferences) {
        CsrfSettings settings = new CsrfSettings();
        settings.scopeOnly = bool(preferences.getBoolean("csrf.scopeOnly"), true);
        settings.historyLimit = number(preferences.getInteger("csrf.historyLimit"), 10_000, 100, 100_000);
        settings.maxBodyBytes = number(preferences.getInteger("csrf.maxBodyBytes"), 1_048_576, 16_384, 10_485_760);
        settings.sensitivity = enumValue(preferences.getString("csrf.sensitivity"));
        settings.customTokenNames = csvSet(preferences.getString("csrf.tokenNames"));
        settings.customAuthCookies = csvSet(preferences.getString("csrf.authCookies"));
        settings.customSensitiveWords = csvSet(preferences.getString("csrf.sensitiveWords"));
        settings.ignoredHosts = csvList(preferences.getString("csrf.ignoredHosts"));
        settings.ignoredPaths = csvList(preferences.getString("csrf.ignoredPaths"));
        return settings;
    }

    public void save(Preferences preferences) {
        preferences.setBoolean("csrf.scopeOnly", scopeOnly);
        preferences.setInteger("csrf.historyLimit", historyLimit);
        preferences.setInteger("csrf.maxBodyBytes", maxBodyBytes);
        preferences.setString("csrf.sensitivity", sensitivity.name());
        preferences.setString("csrf.tokenNames", String.join(",", customTokenNames));
        preferences.setString("csrf.authCookies", String.join(",", customAuthCookies));
        preferences.setString("csrf.sensitiveWords", String.join(",", customSensitiveWords));
        preferences.setString("csrf.ignoredHosts", String.join(",", ignoredHosts));
        preferences.setString("csrf.ignoredPaths", String.join(",", ignoredPaths));
    }

    public boolean scopeOnly() { return scopeOnly; }
    public Sensitivity sensitivity() { return sensitivity; }
    public int historyLimit() { return historyLimit; }
    public int maxBodyBytes() { return maxBodyBytes; }
    public Set<String> customTokenNames() { return customTokenNames; }
    public Set<String> customAuthCookies() { return customAuthCookies; }
    public Set<String> customSensitiveWords() { return customSensitiveWords; }
    public List<String> ignoredHosts() { return ignoredHosts; }
    public List<String> ignoredPaths() { return ignoredPaths; }

    public void update(boolean scopeOnly, Sensitivity sensitivity, int historyLimit, int maxBodyBytes,
                       String tokenNames, String authCookies, String sensitiveWords, String ignoredHosts, String ignoredPaths) {
        this.scopeOnly = scopeOnly;
        this.sensitivity = sensitivity == null ? Sensitivity.CONSERVATIVE : sensitivity;
        this.historyLimit = number(historyLimit, 10_000, 100, 100_000);
        this.maxBodyBytes = number(maxBodyBytes, 1_048_576, 16_384, 10_485_760);
        this.customTokenNames = csvSet(tokenNames);
        this.customAuthCookies = csvSet(authCookies);
        this.customSensitiveWords = csvSet(sensitiveWords);
        this.ignoredHosts = csvList(ignoredHosts);
        this.ignoredPaths = csvList(ignoredPaths);
    }

    private static boolean bool(Boolean value, boolean fallback) { return value == null ? fallback : value; }
    private static int number(Integer value, int fallback, int min, int max) { return number(value == null ? fallback : value, fallback, min, max); }
    private static int number(int value, int fallback, int min, int max) { return value < min || value > max ? fallback : value; }
    private static Sensitivity enumValue(String value) {
        try { return value == null ? Sensitivity.CONSERVATIVE : Sensitivity.valueOf(value); }
        catch (IllegalArgumentException ignored) { return Sensitivity.CONSERVATIVE; }
    }
    private static Set<String> csvSet(String raw) {
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        for (String value : csvList(raw)) normalized.add(value.replace('-', '_').replace('.', '_').replaceAll("[^a-z0-9_]", ""));
        return Set.copyOf(normalized);
    }
    private static List<String> csvList(String raw) {
        if (raw == null || raw.isBlank()) return List.of();
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (String item : raw.split("[,\\n]")) {
            String normalized = item.trim().toLowerCase(Locale.ROOT);
            if (!normalized.isBlank()) values.add(normalized);
        }
        return List.copyOf(values);
    }
}
