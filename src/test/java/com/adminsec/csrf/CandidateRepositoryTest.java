package com.adminsec.csrf;

import com.adminsec.csrf.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CandidateRepositoryTest {
    @Test void capsUniqueCandidatesButStillUpdatesExistingOnes() {
        CandidateRepository repository = new CandidateRepository(100);
        for (int index = 0; index < 100; index++) assertNotNull(repository.upsert(candidate("key-" + index), false));
        assertNull(repository.upsert(candidate("overflow"), false));
        assertEquals(100, repository.size());
        assertEquals(1, repository.droppedCount());
        repository.upsert(candidate("key-0"), false);
        Candidate updated = repository.snapshot().stream().filter(value -> value.key().equals("key-0")).findFirst().orElseThrow();
        assertEquals(2, updated.occurrences());

        Candidate urgent = candidate("urgent", Priority.REVIEW_1);
        assertNotNull(repository.upsert(urgent, false));
        assertTrue(repository.snapshot().stream().anyMatch(value -> value.key().equals("urgent")));
        assertEquals(100, repository.size());
    }

    private static Candidate candidate(String key) {
        return candidate(key, Priority.REVIEW_2);
    }
    private static Candidate candidate(String key, Priority priority) {
        Assessment assessment = new Assessment(key, "State change", "Cookie", true, "No token", "",
                "Origin absent", "SameSite unknown", "Browser-forgeable", priority, "Medium", List.of());
        return new Candidate(key, assessment, null, ReviewStatus.NEW, "");
    }
}
