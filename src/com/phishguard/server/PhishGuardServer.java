package com.phishguard.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.phishguard.model.ScanRequest;
import com.phishguard.model.ScanResult;
import com.phishguard.security.RateLimiter;

import com.phishguard.service.HistoryService;
import com.phishguard.service.PhishingScannerService;
import com.phishguard.service.UserService;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Embedded HTTP Application Server & REST API Gateway for PhishGuard.
 */
public class PhishGuardServer {

    private static final int PORT = 8080;
    private static final HistoryService historyService = new HistoryService();
    private static final PhishingScannerService scannerService = new PhishingScannerService(historyService);
    private static final UserService userService = new UserService();
    private static final java.util.Map<String, String> sessions = new java.util.concurrent.ConcurrentHashMap<>();
    private static final RateLimiter authLimiter = new RateLimiter(20); // login attempts per minute per IP
    private static final RateLimiter rateLimiter = new RateLimiter(60); // 60 requests/min per IP

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        // API Endpoint Handlers
        server.createContext("/api/v1/scan", new ScanHandler());
        server.createContext("/api/v1/history", new HistoryHandler());
        server.createContext("/api/v1/samples", new SamplesHandler());
        server.createContext("/api/v1/health", new HealthHandler());

        server.createContext("/api/v1/auth/", new AuthHandler());

        // Web Dashboard Static File Handler
        server.createContext("/", new StaticFileHandler());

        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(10));
        System.out.println("=================================================");
        System.out.println(" PhishGuard Detection System Server Starting... ");
        System.out.println(" Server URL : http://localhost:" + PORT);
        System.out.println(" REST API   : http://localhost:" + PORT + "/api/v1/scan");
        System.out.println(" Health     : http://localhost:" + PORT + "/api/v1/health");
        System.out.println("=================================================");
        server.start();
    }

    private static void applySecurityHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
        exchange.getResponseHeaders().set("X-XSS-Protection", "1; mode=block");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }


    // ----- Login / logout -----

    private static final String COOKIE = "pg_session";

    private static String currentUser(HttpExchange exchange) {
        String header = exchange.getRequestHeaders().getFirst("Cookie");
        if (header == null) return null;
        for (String part : header.split(";")) {
            String[] kv = part.trim().split("=", 2);
            if (kv.length == 2 && kv[0].equals(COOKIE)) return sessions.get(kv[1]);
        }
        return null;
    }

    private static boolean requireLogin(HttpExchange exchange) throws IOException {
        if (currentUser(exchange) != null) return true;
        sendJsonResponse(exchange, 401, "{\"error\":\"Please log in first\"}");
        return false;
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    /** Reads a string field from a small JSON body such as {"username":"a","password":"b"}. */
    private static String jsonField(String body, String name) {
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("\"" + name + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(body);
        return m.find() ? m.group(1).replace("\\\"", "\"").replace("\\\\", "\\") : null;
    }

    private static class AuthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            String action = exchange.getRequestURI().getPath().substring("/api/v1/auth/".length());
            String method = exchange.getRequestMethod();

            if (action.equals("me") && "GET".equalsIgnoreCase(method)) {
                String user = currentUser(exchange);
                if (user == null) sendJsonResponse(exchange, 401, "{\"error\":\"Not logged in\"}");
                else sendJsonResponse(exchange, 200, "{\"username\":\"" + user + "\"}");
                return;
            }
            if (!"POST".equalsIgnoreCase(method)) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            if (action.equals("logout")) {
                String header = exchange.getRequestHeaders().getFirst("Cookie");
                if (header != null) {
                    for (String part : header.split(";")) {
                        String[] kv = part.trim().split("=", 2);
                        if (kv.length == 2 && kv[0].equals(COOKIE)) sessions.remove(kv[1]);
                    }
                }
                exchange.getResponseHeaders().add("Set-Cookie", COOKIE + "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
                sendJsonResponse(exchange, 200, "{\"ok\":true}");
                return;
            }

            if (!action.equals("login") && !action.equals("register")) {
                sendJsonResponse(exchange, 404, "{\"error\":\"Not Found\"}");
                return;
            }
            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
            if (!authLimiter.allowRequest(clientIp)) {
                sendJsonResponse(exchange, 429, "{\"error\":\"Too many attempts. Wait a minute and try again.\"}");
                return;
            }

            String body;
            try (InputStream is = exchange.getRequestBody()) {
                body = readStreamToString(is);
            }
            String username = jsonField(body, "username");
            String password = jsonField(body, "password");

            if (action.equals("register")) {
                String error = userService.register(username, password);
                if (error != null) {
                    sendJsonResponse(exchange, 400, "{\"error\":\"" + error + "\"}");
                    return;
                }
            } else if (!userService.authenticate(username, password)) {
                sendJsonResponse(exchange, 401, "{\"error\":\"Wrong username or password.\"}");
                return;
            }

            byte[] raw = new byte[32];
            new java.security.SecureRandom().nextBytes(raw);
            StringBuilder token = new StringBuilder();
            for (byte b : raw) token.append(String.format("%02x", b));
            sessions.put(token.toString(), username);
            exchange.getResponseHeaders().add("Set-Cookie",
                COOKIE + "=" + token + "; Path=/; HttpOnly; SameSite=Lax");
            sendJsonResponse(exchange, 200, "{\"username\":\"" + username + "\"}");
        }
    }

    private static class ScanHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(204, -1);
                return;
            }

            if (!requireLogin(exchange)) return;

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
            if (!rateLimiter.allowRequest(clientIp)) {
                sendJsonResponse(exchange, 429, "{\"error\":\"Rate Limit Exceeded. Max 60 requests per minute.\"}");
                return;
            }

            try (InputStream is = exchange.getRequestBody()) {
                String body = readStreamToString(is);
                ScanRequest request = JsonSerializer.parseScanRequest(body);

                if (request.getUrl() == null || request.getUrl().trim().isEmpty()) {
                    sendJsonResponse(exchange, 400, "{\"error\":\"URL parameter is required\"}");
                    return;
                }

                ScanResult result = scannerService.scan(request);
                String jsonResponse = JsonSerializer.toJson(result);
                sendJsonResponse(exchange, 200, jsonResponse);
            } catch (Exception e) {
                sendJsonResponse(exchange, 500, "{\"error\":\"Internal Server Error: " + e.getMessage() + "\"}");
            }
        }
    }

    private static class HistoryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if (!requireLogin(exchange)) return;
            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                List<ScanResult> history = historyService.getRecentScans();
                String json = JsonSerializer.toJsonList(history);
                sendJsonResponse(exchange, 200, json);
            } else {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
            }
        }
    }

    private static class SamplesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            if (!requireLogin(exchange)) return;
            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                String jsonSamples = "[\n" +
                    "  {\"name\":\"Legitimate Bank\",\"url\":\"https://www.chase.com/personal/banking\"},\n" +
                    "  {\"name\":\"Brand Typosquatting\",\"url\":\"http://paypa1-verify-account.com/login\"},\n" +
                    "  {\"name\":\"Evil Twin IP Host\",\"url\":\"http://192.168.1.100/secure-signin\"},\n" +
                    "  {\"name\":\"Subdomain Deception\",\"url\":\"http://paypal.com.account-update.verify-user.top/auth\"},\n" +
                    "  {\"name\":\"Obfuscated Scam\",\"url\":\"http://g00gle-security-check.xyz/login.php\"}\n" +
                    "]";
                sendJsonResponse(exchange, 200, jsonSamples);
            } else {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
            }
        }
    }

    private static class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            String dbStatus = historyService.getDatabaseStatus().replace("\\", "").replace("\"", "'");
            String healthJson = "{\"status\":\"UP\",\"system\":\"PhishGuard Phishing Detection System\",\"version\":\"1.0.0\","
                + "\"database\":{\"connected\":" + historyService.isDatabaseConnected()
                + ",\"status\":\"" + dbStatus + "\"}}";
            sendJsonResponse(exchange, 200, healthJson);
        }
    }

    private static class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            applySecurityHeaders(exchange);
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/")) {
                path = "/index.html";
            }

            // The dashboard needs a login; the login page itself is public.
            boolean loggedIn = currentUser(exchange) != null;
            if (path.equals("/index.html") && !loggedIn) {
                redirect(exchange, "/login.html");
                return;
            }
            if (path.equals("/login.html") && loggedIn) {
                redirect(exchange, "/");
                return;
            }

            File webDir = new File("web");
            File file = new File(webDir, path);

            if (!file.exists() || file.isDirectory()) {
                sendJsonResponse(exchange, 404, "{\"error\":\"404 Not Found\"}");
                return;
            }

            String contentType = "text/html";
            if (path.endsWith(".css")) contentType = "text/css";
            else if (path.endsWith(".js")) contentType = "application/javascript";
            else if (path.endsWith(".png")) contentType = "image/png";
            else if (path.endsWith(".jpg") || path.endsWith(".jpeg")) contentType = "image/jpeg";
            else if (path.endsWith(".webp")) contentType = "image/webp";
            else if (path.endsWith(".svg")) contentType = "image/svg+xml";

            exchange.getResponseHeaders().set("Content-Type", contentType);
            exchange.sendResponseHeaders(200, file.length());

            try (OutputStream os = exchange.getResponseBody(); FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    private static String readStreamToString(InputStream is) throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int len;
        while ((len = is.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        return baos.toString("UTF-8");
    }

    private static void sendJsonResponse(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
