package com.adminsec.csrf.model;

public enum ReviewStatus {
    NEW("New"), NEEDS_TESTING("Needs Testing"), PROTECTED("Protected"),
    CONFIRMED("Confirmed"), FALSE_POSITIVE("False Positive"), ACCEPTED_RISK("Accepted Risk");

    private final String label;
    ReviewStatus(String label) { this.label = label; }
    public String label() { return label; }
    public static ReviewStatus from(String value) {
        for (ReviewStatus status : values()) if (status.name().equals(value) || status.label.equals(value)) return status;
        return NEW;
    }
}
