package com.phishguard.engine;

import com.phishguard.model.*;

import java.util.List;
import java.util.UUID;

/**
 * Weighted Phishing Threat Calculation & Classification Engine.
 */
public class ScoringEngine {

    public ScanResult computeResult(String targetUrl, UrlMetrics urlMetrics, ContentMetrics contentMetrics, List<RiskFactor> riskFactors, long executionTimeMs) {
        ScanResult result = new ScanResult();
        result.setScanId("PG-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase());
        result.setTargetUrl(targetUrl);
        result.setTimestamp(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date()));
        result.setUrlMetrics(urlMetrics);
        result.setContentMetrics(contentMetrics);
        result.setRiskFactors(riskFactors);
        result.setExecutionTimeMs(executionTimeMs);

        // Calculate total score sum from risk factors
        int rawScore = 0;
        for (RiskFactor factor : riskFactors) {
            rawScore += factor.getScoreImpact();
        }

        // Cap score between 0% and 100%
        int finalScore = Math.min(100, Math.max(0, rawScore));
        result.setRiskScore(finalScore);

        // Determine Risk Level Thresholds
        if (finalScore >= 65) {
            result.setRiskLevel("PHISHING");
        } else if (finalScore >= 30) {
            result.setRiskLevel("SUSPICIOUS");
        } else {
            result.setRiskLevel("SAFE");
        }

        // Classify Attack Type
        PhishingType attackType = classifyAttackType(urlMetrics, contentMetrics, riskFactors, finalScore);
        result.setAttackType(attackType);

        // Generate User-Friendly & Technical Summaries
        result.setUserSummary(generateUserSummary(result));
        result.setTechnicalDetails(generateTechnicalDetails(result));

        return result;
    }

    private PhishingType classifyAttackType(UrlMetrics url, ContentMetrics content, List<RiskFactor> factors, int score) {
        if (score < 30) {
            return PhishingType.BENIGN;
        }

        if (url != null && url.isIpHost()) {
            return PhishingType.EVIL_TWIN_IP;
        }

        if (url != null && (url.isHomoglyphDetected() || url.isTyposquatDetected())) {
            return PhishingType.BRAND_TYPOSQUATTING;
        }

        if (content != null && (content.isHasOffsiteFormAction() || content.getPasswordFieldCount() > 0 && (content.isBrandMetaMismatch() || (url != null && url.getSubdomainCount() >= 2)))) {
            return PhishingType.CREDENTIAL_HARVESTER;
        }

        if (content != null && (content.isHasZeroFontObfuscation() || content.isHasCssHiddenOverlay())) {
            return PhishingType.OBFUSCATED_HTML;
        }

        if (url != null && url.getSubdomainCount() >= 3) {
            return PhishingType.SUBDOMAIN_SPOOFING;
        }

        if (url != null && url.isSuspiciousTld()) {
            return PhishingType.SUSPICIOUS_TLD_SHORTENER;
        }

        return PhishingType.CREDENTIAL_HARVESTER;
    }

    private String generateUserSummary(ScanResult result) {
        int score = result.getRiskScore();
        PhishingType type = result.getAttackType();

        if (score >= 65) {
            return "DANGER: High likelihood of phishing (" + score + "% Risk Score). This website appears to be a " 
                   + type.getDisplayName() + ". " + type.getDescription() 
                   + " Do NOT enter passwords, financial details, or personal data on this site.";
        } else if (score >= 30) {
            return "WARNING: Suspicious website detected (" + score + "% Risk Score). Several non-standard URL or layout patterns were found (" 
                   + type.getDisplayName() + "). Proceed with caution and verify the web address before submitting information.";
        } else {
            return "SAFE: Low risk detected (" + score + "% Risk Score). The web address and page structure show normal, legitimate characteristics. Always double-check your browser's address bar when logging in.";
        }
    }

    private String generateTechnicalDetails(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== PhishGuard Threat Analysis Report ===\n");
        sb.append("Scan ID: ").append(result.getScanId()).append("\n");
        sb.append("Target URL: ").append(result.getTargetUrl()).append("\n");
        sb.append("Calculated Risk Score: ").append(result.getRiskScore()).append("% [Level: ").append(result.getRiskLevel()).append("]\n");
        sb.append("Primary Threat Taxonomy: ").append(result.getAttackType().getDisplayName()).append("\n");
        sb.append("Execution Time: ").append(result.getExecutionTimeMs()).append(" ms\n\n");

        sb.append("--- Detected Risk Indicators (").append(result.getRiskFactors().size()).append(") ---\n");
        for (RiskFactor factor : result.getRiskFactors()) {
            sb.append(" • ").append(factor.toString()).append("\n");
        }

        if (result.getUrlMetrics() != null) {
            UrlMetrics u = result.getUrlMetrics();
            sb.append("\n--- URL Metrics ---\n");
            sb.append("Host: ").append(u.getHost()).append("\n");
            sb.append("Subdomain Depth: ").append(u.getSubdomainCount()).append("\n");
            sb.append("Shannon Entropy: ").append(String.format("%.3f", u.getEntropy())).append("\n");
            sb.append("IP Host: ").append(u.isIpHost()).append("\n");
            sb.append("Homoglyph / IDN: ").append(u.isHomoglyphDetected()).append("\n");
            sb.append("Typosquat Brand Match: ").append(u.isTyposquatDetected() ? u.getSuspectedTargetBrand() : "None").append("\n");
        }

        return sb.toString();
    }
}
