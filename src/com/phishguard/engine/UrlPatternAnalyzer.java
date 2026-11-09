package com.phishguard.engine;

import com.phishguard.model.RiskFactor;
import com.phishguard.model.UrlMetrics;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Advanced Heuristic Analyzer for URL String Patterns.
 */
public class UrlPatternAnalyzer {

    private static final Set<String> HIGH_RISK_TLDS = new HashSet<>(Arrays.asList(
        "xyz", "top", "tk", "zip", "work", "cc", "cf", "ga", "gq", "ml", "click", "link", "skin", "buzz", "country", "fun", "icu", "monster", "site"
    ));

    private static final String[] POPULAR_BRANDS = {
        "paypal", "google", "microsoft", "apple", "amazon", "wellsfargo", "chase",
        "facebook", "netflix", "bankofamerica", "binance", "instagram", "linkedin",
        "twitter", "dropbox", "adobe", "chasebank", "coinbase", "stripe"
    };

    private static final String[] SUSPICIOUS_KEYWORDS = {
        "login", "signin", "verify", "verification", "account", "banking", "secure",
        "security", "update", "credential", "wallet", "support", "auth", "confirm",
        "passcode", "validate", "billing", "service"
    };

    private static final Pattern IP_PATTERN = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    public UrlMetrics analyze(String rawUrl, List<RiskFactor> riskFactors) {
        UrlMetrics metrics = new UrlMetrics();
        metrics.setRawUrl(rawUrl);

        try {
            URI uri = new URI(rawUrl);
            String host = uri.getHost() != null ? uri.getHost().toLowerCase() : "";
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "http";
            int port = uri.getPort();
            String path = uri.getPath() != null ? uri.getPath().toLowerCase() : "";

            metrics.setProtocol(scheme);
            metrics.setHost(host);
            metrics.setPort(port);
            metrics.setPath(path);

            // 1. IP Address Host Check
            if (IP_PATTERN.matcher(host).matches()) {
                metrics.setIpHost(true);
                riskFactors.add(new RiskFactor(
                    "URL Structure",
                    "Evil Twin IP Host",
                    "The website uses a raw IP address (" + host + ") instead of a registered domain name, a tactic commonly used to bypass domain blacklists.",
                    35,
                    "CRITICAL",
                    "Do not enter passwords or sensitive information on IP-based websites."
                ));
            }

            // 2. Homoglyph / Punycode IDN Check
            if (host.startsWith("xn--") || containsHomoglyphs(host)) {
                metrics.setHomoglyphDetected(true);
                riskFactors.add(new RiskFactor(
                    "URL Structure",
                    "Homoglyph / IDN Spoofing",
                    "The domain contains internationalized non-Latin characters (homoglyphs) or Punycode mimicking legitimate Latin characters.",
                    40,
                    "CRITICAL",
                    "Beware: the domain uses look-alike characters (e.g. Cyrillic 'а' replacing Latin 'a')."
                ));
            }

            // 3. Subdomain Depth & Spoofing Analysis
            String[] hostParts = host.split("\\.");
            int subdomainCount = Math.max(0, hostParts.length - 2);
            metrics.setSubdomainCount(subdomainCount);

            if (subdomainCount >= 3) {
                riskFactors.add(new RiskFactor(
                    "URL Structure",
                    "Excessive Subdomain Deception",
                    "The URL features " + subdomainCount + " nested subdomains. Attackers often prefix brand names into subdomains to deceive users.",
                    25,
                    "HIGH",
                    "Inspect the main domain right before the extension (TLD) to verify ownership."
                ));
            }

            // 4. TLD Risk Assessment
            String tld = hostParts.length > 0 ? hostParts[hostParts.length - 1] : "";
            if (HIGH_RISK_TLDS.contains(tld)) {
                metrics.setSuspiciousTld(true);
                riskFactors.add(new RiskFactor(
                    "URL Structure",
                    "High-Risk Top Level Domain (TLD)",
                    "The domain uses the '." + tld + "' extension, which is statistically associated with high rates of malicious spam and phishing campaigns.",
                    15,
                    "MEDIUM",
                    "Exercise extra caution with free or low-cost domain extensions."
                ));
            }

            // 5. Entropy Calculation
            String mainDomainPart = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : host;
            double entropy = calculateShannonEntropy(mainDomainPart);
            metrics.setEntropy(entropy);

            if (entropy > 3.85 && mainDomainPart.length() > 8) {
                riskFactors.add(new RiskFactor(
                    "URL Structure",
                    "High Domain Entropy (Randomness)",
                    "Domain name string '" + mainDomainPart + "' exhibits unusually high randomness (entropy: " + String.format("%.2f", entropy) + "), suggesting algorithmically generated domain (DGA).",
                    15,
                    "MEDIUM",
                    "Verify if the web address looks like a randomly generated string."
                ));
            }

            // 6. Brand Typosquatting / Character Substitution Check
            boolean isLegitDomain = false;
            for (String brand : POPULAR_BRANDS) {
                if (isOfficialBrandDomain(host, brand)) {
                    isLegitDomain = true;
                    break;
                }

                // Check host or path for brand mention on unrelated host
                if (host.contains(brand) && !isOfficialBrandDomain(host, brand)) {
                    metrics.setTyposquatDetected(true);
                    metrics.setSuspectedTargetBrand(brand);
                    riskFactors.add(new RiskFactor(
                        "URL Structure",
                        "Target Brand Deception (" + brand.toUpperCase() + ")",
                        "The brand name '" + brand + "' appears in subdomains or paths of an unrelated host (" + host + ").",
                        35,
                        "CRITICAL",
                        "Ensure the domain name officially belongs to " + brand + "."
                    ));
                    break;
                }

                // Check Levenshtein distance on main domain tokens (e.g. paypa1, g00gle)
                String[] tokens = mainDomainPart.split("[-_]");
                for (String token : tokens) {
                    double sim = Levenshtein.similarity(token, brand);
                    if (sim >= 0.70 && sim < 1.0 && token.length() >= 4) {
                        metrics.setTyposquatDetected(true);
                        metrics.setSuspectedTargetBrand(brand);
                        riskFactors.add(new RiskFactor(
                            "URL Structure",
                            "Brand Typosquatting (" + brand.toUpperCase() + ")",
                            "The domain token '" + token + "' is visually very similar to the known brand '" + brand + "' (Similarity: " + (int)(sim * 100) + "%).",
                            40,
                            "CRITICAL",
                            "Carefully check the spelling of the URL for substituted characters like '1' for 'l' or '0' for 'o'."
                        ));
                        break;
                    }
                }
                if (metrics.isTyposquatDetected()) break;
            }

            // 7. Suspicious Keywords in URL Path/Subdomain (Skip if legitimate official brand site on HTTPS)
            if (!isLegitDomain || "http".equals(scheme)) {
                int suspiciousKeywordCount = 0;
                String fullPath = host + path;
                for (String kw : SUSPICIOUS_KEYWORDS) {
                    if (fullPath.contains(kw)) {
                        suspiciousKeywordCount++;
                    }
                }
                if (suspiciousKeywordCount >= 2 && !metrics.isTyposquatDetected()) {
                    riskFactors.add(new RiskFactor(
                        "URL Structure",
                        "Sensitive Keyword Concentration",
                        "URL path contains multiple authentication keywords (e.g. login, verify, account).",
                        15,
                        "MEDIUM",
                        "Verify the legitimacy of authentication links received via email or message."
                    ));
                }
            }

            // 8. Protocol Check (HTTP vs HTTPS)
            if ("http".equals(scheme)) {
                riskFactors.add(new RiskFactor(
                    "URL Security",
                    "Unencrypted HTTP Protocol",
                    "The website uses unencrypted HTTP instead of secure HTTPS, making transmitted credentials vulnerable to interception.",
                    15,
                    "MEDIUM",
                    "Never enter passwords or personal data on unencrypted HTTP pages."
                ));
            }

        } catch (Exception e) {
            // Invalid URL format fallback
            riskFactors.add(new RiskFactor(
                "URL Structure",
                "Malformed URL Syntax",
                "The target URL has malformed syntax or non-standard structure.",
                10,
                "LOW",
                "Double-check the URL format."
            ));
        }

        return metrics;
    }

    private boolean isOfficialBrandDomain(String host, String brand) {
        if (host == null || brand == null) return false;
        String h = host.toLowerCase();
        String b = brand.toLowerCase();
        return h.equals(b + ".com") || h.endsWith("." + b + ".com")
            || h.equals(b + ".org") || h.endsWith("." + b + ".org")
            || h.equals(b + ".net") || h.endsWith("." + b + ".net");
    }

    private boolean containsHomoglyphs(String input) {
        for (char c : input.toCharArray()) {
            // Cyrillic script characters commonly used in homoglyph attacks
            if ((c >= '\u0400' && c <= '\u04FF') || (c >= '\u0500' && c <= '\u052F')) {
                return true;
            }
        }
        return false;
    }

    private double calculateShannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        Map<Character, Integer> freqMap = new HashMap<>();
        for (char c : s.toCharArray()) {
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        int len = s.length();
        for (int count : freqMap.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }
}
