package com.adminsec.csrf;

import com.adminsec.csrf.model.Candidate;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public final class CandidateRepository {
    private final Map<String, Candidate> values = new ConcurrentHashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public Candidate upsert(Candidate candidate) {
        Candidate result = values.compute(candidate.key(), (key, existing) -> {
            if (existing == null) return candidate;
            existing.update(candidate.assessment(), candidate.message());
            return existing;
        });
        changed(); return result;
    }
    public List<Candidate> snapshot() {
        return values.values().stream().sorted(Comparator.comparingInt((Candidate c) -> rank(c.assessment().priority()))
                .thenComparing(c -> c.assessment().endpointKey())).toList();
    }
    public void clear() { values.clear(); changed(); }
    public void addListener(Runnable listener) { listeners.add(listener); }
    public void changed() { listeners.forEach(listener -> javax.swing.SwingUtilities.invokeLater(listener)); }
    private static int rank(com.adminsec.csrf.model.Priority value) {
        return switch (value) { case REVIEW_1 -> 0; case REVIEW_2 -> 1; case REVIEW_3 -> 2; case PROTECTED -> 3; };
    }
}
