package com.phishguard.service;

import com.phishguard.engine.ContentAnalyzer;
import com.phishguard.engine.ScoringEngine;
import com.phishguard.engine.UrlPatternAnalyzer;
import com.phishguard.model.*;
import com.phishguard.security.InputSanitizer;
import com.phishguard.security.SSRFValidator;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Main Phishing Detection Orchestrator Service.
 */
public class PhishingScannerService {

    private final UrlPatternAnalyzer urlAnalyzer = new UrlPatternAnalyzer();
    private final ContentAnalyzer contentAnalyzer = new ContentAnalyzer();
    private final ScoringEngine scoringEngine = new ScoringEngine();
    private final HistoryService historyService;

    public PhishingScannerService(HistoryService historyService) {
        this.historyService = historyService;
    }

    public ScanResult scan(ScanRequest request) {
        long startTime = System.currentTimeMillis();
        String sanitizedUrl = InputSanitizer.sanitizeUrl(request.getUrl());

        List<RiskFactor> riskFactors = new ArrayList<>();

        // 1. SSRF Safety Check
        if (!SSRFValidator.isSafeUrl(sanitizedUrl)) {
            riskFactors.add(new RiskFactor(
                "Security Policy",
                "Blocked Destination (SSRF Protection)",
                "The requested target URL points to a local, loopback, or private internal IP range which is blocked to prevent Server-Side Request Forgery.",
                50,
                "HIGH",
                "Scanning internal IP addresses is prohibited for security reasons."
            ));
        }

        // 2. Perform URL Pattern Heuristic Analysis
        UrlMetrics urlMetrics = urlAnalyzer.analyze(sanitizedUrl, riskFactors);

        // 3. Fetch Webpage Content or Use Provided Offline Payload
        String htmlContent = request.getHtmlContent();
        if (htmlContent == null || htmlContent.trim().isEmpty()) {
            if (SSRFValidator.isSafeUrl(sanitizedUrl)) {
                htmlContent = fetchRemoteWebpage(sanitizedUrl);
            }
        }

        // 4. Perform Webpage Content & DOM Analysis
        ContentMetrics contentMetrics = contentAnalyzer.analyze(htmlContent, urlMetrics.getHost(), riskFactors);

        long executionTimeMs = System.currentTimeMillis() - startTime;

        // 5. Compute Final Composite Threat Result
        ScanResult result = scoringEngine.computeResult(sanitizedUrl, urlMetrics, contentMetrics, riskFactors, executionTimeMs);

        // 6. Record Scan in History
        if (historyService != null) {
            historyService.addScan(result);
        }

        return result;
    }

    private String fetchRemoteWebpage(String targetUrl) {
        StringBuilder html = new StringBuilder();
        try {
            URL url = new URI(targetUrl).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(4000); // 4 seconds max connect timeout
            conn.setReadTimeout(4000);    // 4 seconds max read timeout
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard-Scanner/1.0");

            int responseCode = conn.getResponseCode();
            if (responseCode >= 200 && responseCode < 400) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    int linesRead = 0;
                    while ((line = reader.readLine()) != null && linesRead < 1000) { // Limit max 1000 lines
                        html.append(line).append("\n");
                        linesRead++;
                    }
                }
            }
        } catch (Exception e) {
            // Fetching remote site failed or timed out (e.g. offline site or network issue)
            // System falls back gracefully to static URL pattern analysis
        }
        return html.toString();
    }
}
