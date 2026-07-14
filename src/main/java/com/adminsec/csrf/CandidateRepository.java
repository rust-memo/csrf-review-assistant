package com.adminsec.csrf;

import com.adminsec.csrf.model.Candidate;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class CandidateRepository {
    private final Map<String, Candidate> values = new ConcurrentHashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean updateScheduled = new AtomicBoolean();
    private final AtomicLong dropped = new AtomicLong();
    private volatile int maximumSize;

    public CandidateRepository() { this(5_000); }
    public CandidateRepository(int maximumSize) { setMaximumSize(maximumSize); }

    public synchronized Candidate upsert(Candidate candidate) {
        return upsert(candidate, true);
    }
    public synchronized Candidate upsert(Candidate candidate, boolean notify) {
        if (!values.containsKey(candidate.key()) && values.size() >= maximumSize) {
            Candidate worst = values.values().stream().max(Comparator
                    .comparingInt((Candidate value) -> rank(value.assessment().priority()))
                    .thenComparing(Candidate::lastSeen, Comparator.reverseOrder())).orElse(null);
            if (worst == null || rank(candidate.assessment().priority()) >= rank(worst.assessment().priority())
                    || !values.remove(worst.key(), worst)) {
                dropped.incrementAndGet();
                if (notify) changed();
                return null;
            }
            dropped.incrementAndGet();
        }
        Candidate result = values.compute(candidate.key(), (key, existing) -> {
            if (existing == null) return candidate;
            existing.update(candidate.assessment(), candidate.message());
            return existing;
        });
        if (notify) changed();
        return result;
    }
    public List<Candidate> snapshot() {
        return values.values().stream().sorted(Comparator.comparingInt((Candidate c) -> rank(c.assessment().priority()))
                .thenComparing(c -> c.assessment().endpointKey())).toList();
    }
    public synchronized void clear() { clear(true); }
    public synchronized void clear(boolean notify) { values.clear(); dropped.set(0); if (notify) changed(); }
    public void addListener(Runnable listener) { listeners.add(listener); }
    public void changed() {
        if (!updateScheduled.compareAndSet(false, true)) return;
        javax.swing.SwingUtilities.invokeLater(() -> {
            updateScheduled.set(false);
            listeners.forEach(Runnable::run);
        });
    }
    public long droppedCount() { return dropped.get(); }
    public int size() { return values.size(); }
    public synchronized void setMaximumSize(int value) { maximumSize = Math.max(100, Math.min(value, 50_000)); }
    private static int rank(com.adminsec.csrf.model.Priority value) {
        return switch (value) { case REVIEW_1 -> 0; case REVIEW_2 -> 1; case REVIEW_3 -> 2; case PROTECTED -> 3; };
    }
}
