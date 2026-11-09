package com.phishguard.server;

import com.phishguard.model.*;

import java.util.List;

/**
 * Lightweight JSON Serializer for PhishGuard API payloads.
 */
public class JsonSerializer {

    public static String toJson(ScanResult result) {
        if (result == null) return "{}";
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"scanId\":\"").append(escape(result.getScanId())).append("\",");
        sb.append("\"targetUrl\":\"").append(escape(result.getTargetUrl())).append("\",");
        sb.append("\"timestamp\":\"").append(escape(result.getTimestamp())).append("\",");
        sb.append("\"riskScore\":").append(result.getRiskScore()).append(",");
        sb.append("\"riskLevel\":\"").append(escape(result.getRiskLevel())).append("\",");
        
        if (result.getAttackType() != null) {
            sb.append("\"attackType\":{");
            sb.append("\"name\":\"").append(escape(result.getAttackType().name())).append("\",");
            sb.append("\"displayName\":\"").append(escape(result.getAttackType().getDisplayName())).append("\",");
            sb.append("\"description\":\"").append(escape(result.getAttackType().getDescription())).append("\",");
            sb.append("\"severity\":\"").append(escape(result.getAttackType().getDefaultSeverity())).append("\"");
            sb.append("},");
        }

        sb.append("\"userSummary\":\"").append(escape(result.getUserSummary())).append("\",");
        sb.append("\"technicalDetails\":\"").append(escape(result.getTechnicalDetails())).append("\",");
        sb.append("\"executionTimeMs\":").append(result.getExecutionTimeMs()).append(",");

        // Risk Factors array
        sb.append("\"riskFactors\":[");
        List<RiskFactor> factors = result.getRiskFactors();
        for (int i = 0; i < factors.size(); i++) {
            RiskFactor rf = factors.get(i);
            sb.append("{");
            sb.append("\"category\":\"").append(escape(rf.getCategory())).append("\",");
            sb.append("\"title\":\"").append(escape(rf.getTitle())).append("\",");
            sb.append("\"description\":\"").append(escape(rf.getDescription())).append("\",");
            sb.append("\"scoreImpact\":").append(rf.getScoreImpact()).append(",");
            sb.append("\"severity\":\"").append(escape(rf.getSeverity())).append("\",");
            sb.append("\"recommendation\":\"").append(escape(rf.getRecommendation())).append("\"");
            sb.append("}");
            if (i < factors.size() - 1) sb.append(",");
        }
        sb.append("],");

        // Url Metrics
        UrlMetrics u = result.getUrlMetrics();
        sb.append("\"urlMetrics\":{");
        if (u != null) {
            sb.append("\"host\":\"").append(escape(u.getHost())).append("\",");
            sb.append("\"protocol\":\"").append(escape(u.getProtocol())).append("\",");
            sb.append("\"entropy\":").append(String.format("%.3f", u.getEntropy())).append(",");
            sb.append("\"subdomainCount\":").append(u.getSubdomainCount()).append(",");
            sb.append("\"isIpHost\":").append(u.isIpHost()).append(",");
            sb.append("\"isHomoglyphDetected\":").append(u.isHomoglyphDetected()).append(",");
            sb.append("\"isTyposquatDetected\":").append(u.isTyposquatDetected()).append(",");
            sb.append("\"suspectedBrand\":\"").append(escape(u.getSuspectedTargetBrand())).append("\",");
            sb.append("\"isSuspiciousTld\":").append(u.isSuspiciousTld());
        }
        sb.append("},");

        // Content Metrics
        ContentMetrics c = result.getContentMetrics();
        sb.append("\"contentMetrics\":{");
        if (c != null) {
            sb.append("\"pageTitle\":\"").append(escape(c.getPageTitle())).append("\",");
            sb.append("\"formCount\":").append(c.getFormCount()).append(",");
            sb.append("\"passwordFieldCount\":").append(c.getPasswordFieldCount()).append(",");
            sb.append("\"hasOffsiteFormAction\":").append(c.isHasOffsiteFormAction()).append(",");
            sb.append("\"hasZeroFontObfuscation\":").append(c.isHasZeroFontObfuscation()).append(",");
            sb.append("\"hasCssHiddenOverlay\":").append(c.isHasCssHiddenOverlay()).append(",");
            sb.append("\"brandMetaMismatch\":").append(c.isBrandMetaMismatch());
        }
        sb.append("}");

        sb.append("}");
        return sb.toString();
    }

    public static String toJsonList(List<ScanResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < results.size(); i++) {
            sb.append(toJson(results.get(i)));
            if (i < results.size() - 1) sb.append(",");
        }
        sb.append("]");
        return sb.toString();
    }

    public static ScanRequest parseScanRequest(String json) {
        ScanRequest request = new ScanRequest();
        if (json == null || json.trim().isEmpty()) return request;

        // Parse "url" field
        String urlKey = "\"url\"";
        int idx = json.indexOf(urlKey);
        if (idx != -1) {
            int startQuote = json.indexOf("\"", idx + urlKey.length());
            if (startQuote != -1) {
                int endQuote = json.indexOf("\"", startQuote + 1);
                if (endQuote != -1) {
                    request.setUrl(json.substring(startQuote + 1, endQuote));
                }
            }
        }

        // Parse optional "htmlContent" field
        String htmlKey = "\"htmlContent\"";
        int htmlIdx = json.indexOf(htmlKey);
        if (htmlIdx != -1) {
            int startQuote = json.indexOf("\"", htmlIdx + htmlKey.length());
            if (startQuote != -1) {
                int endQuote = json.indexOf("\"", startQuote + 1);
                if (endQuote != -1) {
                    request.setHtmlContent(json.substring(startQuote + 1, endQuote));
                }
            }
        }

        return request;
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
