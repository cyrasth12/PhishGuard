package com.phishguard.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Detailed analysis result returned after processing a target URL.
 */
public class ScanResult {
    private String scanId;
    private String targetUrl;
    private String timestamp;
    private int riskScore; // 0 to 100%
    private String riskLevel; // SAFE, SUSPICIOUS, PHISHING
    private PhishingType attackType;
    private String userSummary;
    private String technicalDetails;
    private List<RiskFactor> riskFactors = new ArrayList<>();
    private UrlMetrics urlMetrics;
    private ContentMetrics contentMetrics;
    private long executionTimeMs;

    public ScanResult() {}

    public String getScanId() { return scanId; }
    public void setScanId(String scanId) { this.scanId = scanId; }

    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public PhishingType getAttackType() { return attackType; }
    public void setAttackType(PhishingType attackType) { this.attackType = attackType; }

    public String getUserSummary() { return userSummary; }
    public void setUserSummary(String userSummary) { this.userSummary = userSummary; }

    public String getTechnicalDetails() { return technicalDetails; }
    public void setTechnicalDetails(String technicalDetails) { this.technicalDetails = technicalDetails; }

    public List<RiskFactor> getRiskFactors() { return riskFactors; }
    public void setRiskFactors(List<RiskFactor> riskFactors) { this.riskFactors = riskFactors; }

    public UrlMetrics getUrlMetrics() { return urlMetrics; }
    public void setUrlMetrics(UrlMetrics urlMetrics) { this.urlMetrics = urlMetrics; }

    public ContentMetrics getContentMetrics() { return contentMetrics; }
    public void setContentMetrics(ContentMetrics contentMetrics) { this.contentMetrics = contentMetrics; }

    public long getExecutionTimeMs() { return executionTimeMs; }
    public void setExecutionTimeMs(long executionTimeMs) { this.executionTimeMs = executionTimeMs; }
}
