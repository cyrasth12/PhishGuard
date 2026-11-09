package com.phishguard.service;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * User accounts for login / logout, stored in the MySQL table 'users'.
 * Passwords are never stored in plain text: each one is salted and hashed with PBKDF2.
 * If MySQL is not available the accounts are kept in memory so the login page still works.
 */
public class UserService {

    private static final String CREATE_TABLE =
        "CREATE TABLE IF NOT EXISTS users ("
        + "id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,"
        + "username VARCHAR(30) NOT NULL UNIQUE,"
        + "password_hash VARCHAR(255) NOT NULL,"
        + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    private static final String INSERT_SQL = "INSERT INTO users (username, password_hash) VALUES (?, ?)";
    private static final String SELECT_SQL = "SELECT password_hash FROM users WHERE username = ?";
    private static final int ITERATIONS = 65000;

    private final Map<String, String> memory = new ConcurrentHashMap<>();
    private final String dbUrl, dbUser, dbPassword;
    private volatile boolean databaseReady = false;

    public UserService() {
        Properties p = new Properties();
        try (InputStream in = new FileInputStream("db.properties")) {
            p.load(in);
        } catch (IOException ignored) { }
        dbUrl = p.getProperty("db.url",
            "jdbc:mysql://localhost:3306/phishguard?createDatabaseIfNotExist=true&useSSL=false"
            + "&allowPublicKeyRetrieval=true&serverTimezone=UTC&characterEncoding=UTF-8");
        dbUser = p.getProperty("db.user", "root");
        dbPassword = p.getProperty("db.password", "");
        try (Connection c = connect(); Statement st = c.createStatement()) {
            st.executeUpdate(CREATE_TABLE);
            databaseReady = true;
            System.out.println("[UserService] Accounts are stored in MySQL table 'users'.");
        } catch (SQLException e) {
            System.err.println("[UserService] MySQL unavailable, accounts kept in memory: " + e.getMessage());
        }
        // Demo account so the app can be opened straight away
        if (!exists("admin")) register("admin", "admin123");
    }

    /** Returns null on success, otherwise a message to show the user. */
    public String register(String username, String password) {
        if (username == null || !username.matches("[A-Za-z0-9_]{3,30}"))
            return "Username must be 3-30 letters, numbers or underscores.";
        if (password == null || password.length() < 6 || password.length() > 100)
            return "Password must be 6 to 100 characters.";
        if (exists(username)) return "That username is already taken.";
        String hash = hash(password);
        if (databaseReady) {
            try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(INSERT_SQL)) {
                ps.setString(1, username);
                ps.setString(2, hash);
                ps.executeUpdate();
                return null;
            } catch (SQLException e) {
                System.err.println("[UserService] MySQL write failed, keeping account in memory: " + e.getMessage());
            }
        }
        memory.put(username, hash);
        return null;
    }

    public boolean authenticate(String username, String password) {
        if (username == null || password == null) return false;
        String stored = lookup(username);
        return stored != null && verify(password, stored);
    }

    private boolean exists(String username) {
        return lookup(username) != null;
    }

    private String lookup(String username) {
        if (databaseReady) {
            try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(SELECT_SQL)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) return rs.getString(1);
                }
            } catch (SQLException e) {
                System.err.println("[UserService] MySQL read failed: " + e.getMessage());
            }
        }
        return memory.get(username);
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    // ----- password hashing: iterations:salt:hash (Base64) -----

    private static String hash(String password) {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return ITERATIONS + ":" + Base64.getEncoder().encodeToString(salt) + ":"
            + Base64.getEncoder().encodeToString(pbkdf2(password, salt, ITERATIONS));
    }

    private static boolean verify(String password, String stored) {
        String[] parts = stored.split(":");
        if (parts.length != 3) return false;
        byte[] expected = Base64.getDecoder().decode(parts[2]);
        byte[] actual = pbkdf2(password, Base64.getDecoder().decode(parts[1]), Integer.parseInt(parts[0]));
        return MessageDigest.isEqual(expected, actual);
    }

    private static byte[] pbkdf2(String password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }
}
