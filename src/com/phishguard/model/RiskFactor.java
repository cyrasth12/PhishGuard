package com.phishguard.model;

/**
 * Detailed breakdown item for a specific risk factor detected during analysis.
 */
public class RiskFactor {
    private String category;      // e.g. "URL Structure", "Content", "Obfuscation"
    private String title;         // Short title
    private String description;   // Technical explanation
    private int scoreImpact;      // Points added to risk score (e.g. +25)
    private String severity;      // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    private String recommendation;// Actionable advice for users

    public RiskFactor() {}

    public RiskFactor(String category, String title, String description, int scoreImpact, String severity, String recommendation) {
        this.category = category;
        this.title = title;
        this.description = description;
        this.scoreImpact = scoreImpact;
        this.severity = severity;
        this.recommendation = recommendation;
    }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public int getScoreImpact() { return scoreImpact; }
    public void setScoreImpact(int scoreImpact) { this.scoreImpact = scoreImpact; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }

    @Override
    public String toString() {
        return "[" + severity + "] " + title + " (+" + scoreImpact + "%): " + description;
    }
}
