package com.adminsec.csrf.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.Instant;

public final class Candidate {
    private static final int MAX_NOTE_LENGTH = 50_000;
    private final String key;
    private volatile Assessment assessment;
    private volatile HttpRequestResponse message;
    private volatile ReviewStatus status;
    private volatile String note;
    private final Instant firstSeen;
    private volatile Instant lastSeen;
    private volatile long occurrences;

    public Candidate(String key, Assessment assessment, HttpRequestResponse message, ReviewStatus status, String note) {
        this.key = key; this.assessment = assessment; this.message = message;
        this.status = status == null ? ReviewStatus.NEW : status; this.note = safeNote(note);
        this.firstSeen = Instant.now(); this.lastSeen = firstSeen; this.occurrences = 1;
    }
    public String key() { return key; }
    public Assessment assessment() { return assessment; }
    public HttpRequestResponse message() { return message; }
    public ReviewStatus status() { return status; }
    public String note() { return note; }
    public Instant firstSeen() { return firstSeen; }
    public Instant lastSeen() { return lastSeen; }
    public long occurrences() { return occurrences; }
    public void update(Assessment value, HttpRequestResponse latest) {
        assessment = value; message = latest; lastSeen = Instant.now(); occurrences++;
    }
    public void review(ReviewStatus value, String note) { status = value; this.note = safeNote(note); }
    private static String safeNote(String value) {
        if (value == null) return "";
        return value.length() <= MAX_NOTE_LENGTH ? value : value.substring(0, MAX_NOTE_LENGTH);
    }
}
