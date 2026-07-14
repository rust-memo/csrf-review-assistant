package com.adminsec.csrf;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CsrfSettingsTest {
    @Test void preservesUnicodeSensitiveTermsAndDropsEmptyIdentifiers() {
        CsrfSettings settings = new CsrfSettings();
        settings.update(true, CsrfSettings.Sensitivity.CONSERVATIVE, 10_000, 1_048_576,
                "!!!, csrf-token", "---", "حذف, تغيير كلمة المرور", "", "");
        assertEquals(java.util.Set.of("csrf_token"), settings.customTokenNames());
        assertTrue(settings.customAuthCookies().isEmpty());
        assertTrue(settings.customSensitiveWords().contains("حذف"));
        assertTrue(settings.customSensitiveWords().contains("تغيير_كلمة_المرور"));
        assertFalse(settings.customSensitiveWords().contains(""));
    }
}
