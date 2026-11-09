package com.phishguard.engine;

import com.phishguard.model.ContentMetrics;
import com.phishguard.model.RiskFactor;

import java.net.URI;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HTML Webpage Content and DOM Analyzer.
 * Parses HTML structural markup to detect credential harvesting forms, offsite form actions,
 * zero-font text obfuscation, CSS overlay tricks, and brand title mismatch.
 */
public class ContentAnalyzer {

    private static final Pattern FORM_PATTERN = Pattern.compile("<form[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern FORM_ACTION_PATTERN = Pattern.compile("action=[\"']?([^\"'\\s>]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern PASSWORD_INPUT_PATTERN = Pattern.compile("<input[^>]*type=[\"']?password[\"']?[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern SENSITIVE_INPUT_PATTERN = Pattern.compile("<input[^>]*(ssn|social|creditcard|cardnumber|cvv|pin|passcode)[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern TITLE_PATTERN = Pattern.compile("<title[^>]*>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    
    private static final String[] MAJOR_BRANDS = {
        "paypal", "google", "microsoft", "apple", "amazon", "wellsfargo", "chase",
        "facebook", "netflix", "bankofamerica", "binance", "coinbase"
    };

    public ContentMetrics analyze(String html, String targetHost, List<RiskFactor> riskFactors) {
        ContentMetrics metrics = new ContentMetrics();
        if (html == null || html.trim().isEmpty()) {
            return metrics;
        }

        // 1. Extract Page Title
        Matcher titleMatcher = TITLE_PATTERN.matcher(html);
        if (titleMatcher.find()) {
            String title = titleMatcher.group(1).trim();
            metrics.setPageTitle(title);

            // Check Brand Title Spoofing
            String lowerTitle = title.toLowerCase();
            for (String brand : MAJOR_BRANDS) {
                if (lowerTitle.contains(brand) && (targetHost == null || !targetHost.contains(brand))) {
                    metrics.setBrandMetaMismatch(true);
                    riskFactors.add(new RiskFactor(
                        "Content Analysis",
                        "Brand Meta Title Spoofing",
                        "The webpage title prominently claims to be '" + title + "' (referencing " + brand.toUpperCase() + "), but the actual host domain (" + targetHost + ") has no association with that brand.",
                        30,
                        "HIGH",
                        "Do not trust web pages whose content claims to belong to a known brand when the URL address differs."
                    ));
                    break;
                }
            }
        }

        // 2. Form & Password Field Analysis
        Matcher formMatcher = FORM_PATTERN.matcher(html);
        int formCount = 0;
        while (formMatcher.find()) {
            formCount++;
            String formTag = formMatcher.group(0);
            Matcher actionMatcher = FORM_ACTION_PATTERN.matcher(formTag);
            if (actionMatcher.find()) {
                String actionUrl = actionMatcher.group(1);
                try {
                    URI actionUri = new URI(actionUrl);
                    String actionHost = actionUri.getHost();
                    if (actionHost != null && targetHost != null && !actionHost.equalsIgnoreCase(targetHost)) {
                        metrics.setHasOffsiteFormAction(true);
                        metrics.setDetectedFormActionDomain(actionHost);
                        riskFactors.add(new RiskFactor(
                            "Content Analysis",
                            "Off-Site Form Action Target",
                            "The login/data form submits user credentials to an entirely different host (" + actionHost + ") instead of the page domain (" + targetHost + ").",
                            35,
                            "CRITICAL",
                            "Submitting credentials here will send your data to an unauthorized third-party server."
                        ));
                    }
                } catch (Exception ignored) {}
            }
        }
        metrics.setFormCount(formCount);

        // 3. Password / Financial Input Detection
        Matcher pwdMatcher = PASSWORD_INPUT_PATTERN.matcher(html);
        int pwdCount = 0;
        while (pwdMatcher.find()) {
            pwdCount++;
        }
        metrics.setPasswordFieldCount(pwdCount);

        Matcher sensitiveMatcher = SENSITIVE_INPUT_PATTERN.matcher(html);
        boolean hasSensitiveFields = sensitiveMatcher.find();

        if (pwdCount > 0 || hasSensitiveFields) {
            if (metrics.isBrandMetaMismatch() || metrics.isHasOffsiteFormAction() || (targetHost != null && targetHost.split("\\.").length > 3)) {
                riskFactors.add(new RiskFactor(
                    "Content Analysis",
                    "Credential Harvester Login Form",
                    "The webpage presents password or financial input fields on an unverified or suspicious host domain.",
                    30,
                    "CRITICAL",
                    "Never enter personal passwords or card information on unverified login screens."
                ));
            } else {
                riskFactors.add(new RiskFactor(
                    "Content Analysis",
                    "Authentication / Form Presence",
                    "The webpage contains credential input fields.",
                    5,
                    "LOW",
                    "Verify the browser address bar HTTPS lock icon before logging in."
                ));
            }
        }

        // 4. Zero-Font Size & CSS Obfuscation (Targeting hidden text overlay containing keywords)
        Pattern zeroFontTextPattern = Pattern.compile("<[^>]+style=[\"'][^\"']*font-size\\s*:\\s*0[^\"']*[\"'][^>]*>(.*?)</", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher zfMatcher = zeroFontTextPattern.matcher(html);
        if (zfMatcher.find()) {
            String hiddenText = zfMatcher.group(1).toLowerCase();
            if (hiddenText.contains("verify") || hiddenText.contains("bank") || hiddenText.contains("security") || hiddenText.contains("paypal") || hiddenText.contains("account") || hiddenText.contains("login")) {
                metrics.setHasZeroFontObfuscation(true);
                riskFactors.add(new RiskFactor(
                    "Obfuscation Analysis",
                    "Zero-Font Size Obfuscation",
                    "HTML source uses zero-sized text (font-size: 0px) to inject invisible keyword padding and evade security filter engines.",
                    25,
                    "HIGH",
                    "This webpage uses techniques designed to conceal text from web security filters."
                ));
            }
        }

        Pattern cssOverlayPattern = Pattern.compile("<[^>]+style=[\"'][^\"']*(display\\s*:\\s*none|visibility\\s*:\\s*hidden|opacity\\s*:\\s*0)[^\"']*[\"'][^>]*>(.*?)</", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher cssMatcher = cssOverlayPattern.matcher(html);
        if (cssMatcher.find()) {
            String hiddenContent = cssMatcher.group(1).toLowerCase();
            if (hiddenContent.contains("verify account") || hiddenContent.contains("confirm password") || hiddenContent.contains("billing update") || hiddenContent.contains("security alert")) {
                metrics.setHasCssHiddenOverlay(true);
                riskFactors.add(new RiskFactor(
                    "Obfuscation Analysis",
                    "CSS Hidden Text Overlay",
                    "HTML contains hidden CSS layers (display:none / opacity:0) hiding security keywords or misleading text elements.",
                    20,
                    "MEDIUM",
                    "Be cautious of pages employing hidden content layers."
                ));
            }
        }

        // 5. External Script Ratio
        Pattern scriptPattern = Pattern.compile("<script[^>]*src=[\"']?([^\"'\\s>]+)", Pattern.CASE_INSENSITIVE);
        Matcher scriptMatcher = scriptPattern.matcher(html);
        int totalScripts = 0;
        int externalScripts = 0;
        while (scriptMatcher.find()) {
            totalScripts++;
            String src = scriptMatcher.group(1);
            if (src.startsWith("http://") || src.startsWith("https://") || src.startsWith("//")) {
                if (targetHost != null && !src.contains(targetHost)) {
                    externalScripts++;
                }
            }
        }
        if (totalScripts >= 3 && ((double) externalScripts / totalScripts) >= 0.75) {
            metrics.setHasExternalScriptRatio(true);
            riskFactors.add(new RiskFactor(
                "Content Analysis",
                "High External Script Reliance",
                externalScripts + " out of " + totalScripts + " executable scripts are loaded from third-party remote hosts.",
                10,
                "LOW",
                "Third-party script loading can indicate compromised page templates."
            ));
        }

        return metrics;
    }
}
