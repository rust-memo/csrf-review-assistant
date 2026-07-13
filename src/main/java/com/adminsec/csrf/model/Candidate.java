package com.adminsec.csrf.model;

import burp.api.montoya.http.message.HttpRequestResponse;

public final class Candidate {
    private final String key;
    private volatile Assessment assessment;
    private volatile HttpRequestResponse message;
    private volatile ReviewStatus status;
    private volatile String note;

    public Candidate(String key, Assessment assessment, HttpRequestResponse message, ReviewStatus status, String note) {
        this.key = key; this.assessment = assessment; this.message = message;
        this.status = status == null ? ReviewStatus.NEW : status; this.note = note == null ? "" : note;
    }
    public String key() { return key; }
    public Assessment assessment() { return assessment; }
    public HttpRequestResponse message() { return message; }
    public ReviewStatus status() { return status; }
    public String note() { return note; }
    public void update(Assessment value, HttpRequestResponse latest) { assessment = value; message = latest; }
    public void review(ReviewStatus value, String note) { status = value; this.note = note == null ? "" : note; }
}
