package com.phishguard.model;

/**
 * Categorization of Phishing Attack Types.
 */
public enum PhishingType {
    BRAND_TYPOSQUATTING(
        "Brand Typosquatting / Homograph Attack",
        "Uses character substitutions (e.g. paypa1.com, g00gle.com) or Cyrillic homoglyphs to trick users into believing they are visiting a legitimate brand.",
        "High"
    ),
    CREDENTIAL_HARVESTER(
        "Credential Harvester / Fake Login Form",
        "Contains misleading login fields or password inputs designed to steal credentials and submit them to unauthorized external domains.",
        "Critical"
    ),
    SUBDOMAIN_SPOOFING(
        "Subdomain Deception Spoofing",
        "Employs deeply nested subdomains (e.g. paypal.com.login-verify.security-update.xyz) to mask the real malicious root domain.",
        "High"
    ),
    EVIL_TWIN_IP(
        "Evil Twin IP Host Attack",
        "Uses a raw IP address directly instead of a domain name to bypass domain-based blacklists and host rogue phishing infrastructure.",
        "Critical"
    ),
    OBFUSCATED_HTML(
        "Zero-Font / CSS Obfuscated Scam",
        "Uses invisible text, zero-size fonts (font-size: 0px), display:none overlays, or encrypted JavaScript to hide scam content from traditional scanner engines.",
        "High"
    ),
    SUSPICIOUS_TLD_SHORTENER(
        "Malicious TLD / Link Masker",
        "Uses high-risk top-level domains or nested URL shorteners to conceal dangerous destinations.",
        "Medium"
    ),
    BENIGN(
        "Legitimate Site (No Phishing Detected)",
        "URL and page content exhibit normal patterns consistent with safe, legitimate web applications.",
        "None"
    );

    private final String displayName;
    private final String description;
    private final String defaultSeverity;

    PhishingType(String displayName, String description, String defaultSeverity) {
        this.displayName = displayName;
        this.description = description;
        this.defaultSeverity = defaultSeverity;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    public String getDefaultSeverity() {
        return defaultSeverity;
    }
}
