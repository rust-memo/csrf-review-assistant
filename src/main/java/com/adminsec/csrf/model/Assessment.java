package com.adminsec.csrf.model;

import java.util.List;

public record Assessment(
        String endpointKey,
        String actionType,
        String authEvidence,
        boolean ambientAuthentication,
        String tokenEvidence,
        String tokenName,
        String originEvidence,
        String fetchMetadataEvidence,
        String corsEvidence,
        String cookieDefense,
        String exploitability,
        Priority priority,
        String confidence,
        List<String> reasons) {

    public Assessment(String endpointKey, String actionType, String authEvidence,
                      boolean ambientAuthentication, String tokenEvidence, String tokenName,
                      String originEvidence, String cookieDefense, String exploitability,
                      Priority priority, String confidence, List<String> reasons) {
        this(endpointKey, actionType, authEvidence, ambientAuthentication, tokenEvidence, tokenName,
                originEvidence, "Fetch Metadata not observed", "CORS evidence not observed",
                cookieDefense, exploitability, priority, confidence, reasons);
    }
}
