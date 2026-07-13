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
        String cookieDefense,
        String exploitability,
        Priority priority,
        String confidence,
        List<String> reasons) {
}
