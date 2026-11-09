package com.phishguard.security;

/**
 * Utility class for input validation, sanitization, and output encoding.
 */
public class InputSanitizer {

    public static String sanitizeUrl(String rawUrl) {
        if (rawUrl == null) return "";
        String trimmed = rawUrl.trim();
        // Remove leading/trailing control characters or whitespace
        trimmed = trimmed.replaceAll("[\\r\\n\\t]", "");
        
        // Ensure scheme exists, default to http:// if absent for analysis
        if (!trimmed.toLowerCase().startsWith("http://") && !trimmed.toLowerCase().startsWith("https://")) {
            trimmed = "http://" + trimmed;
        }
        return trimmed;
    }

    public static String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;");
    }
}
