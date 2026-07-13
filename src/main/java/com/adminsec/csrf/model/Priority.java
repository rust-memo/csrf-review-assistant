package com.adminsec.csrf.model;

public enum Priority {
    REVIEW_1("P1 - urgent review"),
    REVIEW_2("P2 - review"),
    REVIEW_3("P3 - low confidence"),
    PROTECTED("Protection observed");

    private final String label;
    Priority(String label) { this.label = label; }
    public String label() { return label; }
}
