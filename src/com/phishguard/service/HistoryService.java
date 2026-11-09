package com.phishguard.service;

import com.phishguard.model.PhishingType;
import com.phishguard.model.RiskFactor;
import com.phishguard.model.ScanResult;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Scan history storage backed by MySQL (XAMPP / phpMyAdmin).
 *
 * Connection settings are read from db.properties in the project folder.
 * If MySQL is not running or the JDBC driver jar is missing, the service logs a
 * clear warning and falls back to an in-memory list so the app keeps working.
 */
public class HistoryService {

    private static final int MAX_HISTORY_SIZE = 50;
    private static final int MAX_URL_LENGTH = 2048;
    private static final String CONFIG_FILE = "db.properties";

    private static final String DEFAULT_URL =
        "jdbc:mysql://localhost:3306/phishguard"
        + "?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true"
        + "&serverTimezone=UTC&characterEncoding=UTF-8";

    private static final String CREATE_TABLE =
        "CREATE TABLE IF NOT EXISTS scans ("
        + "id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,"
        + "scan_id VARCHAR(20) NOT NULL UNIQUE,"
        + "url VARCHAR(2048) NOT NULL,"
        + "risk_score TINYINT UNSIGNED NOT NULL,"
        + "risk_level VARCHAR(12) NOT NULL,"
        + "attack_type VARCHAR(40),"
        + "risk_factor_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,"
        + "execution_ms INT UNSIGNED NOT NULL DEFAULT 0,"
        + "technical_details MEDIUMTEXT,"
        + "scanned_at VARCHAR(19) NOT NULL,"
        + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        + "INDEX idx_created (created_at),"
        + "INDEX idx_level (risk_level)"
        + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

    private static final String INSERT_SQL =
        "INSERT INTO scans (scan_id, url, risk_score, risk_level, attack_type,"
        + " risk_factor_count, execution_ms, technical_details, scanned_at)"
        + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String SELECT_SQL =
        "SELECT scan_id, url, risk_score, risk_level, attack_type, scanned_at"
        + " FROM scans ORDER BY id DESC LIMIT " + MAX_HISTORY_SIZE;

    private final String dbUrl;
    private final String dbUser;
    private final String dbPassword;

    private final List<ScanResult> memory = new CopyOnWriteArrayList<>();
    private volatile boolean databaseReady = false;
    private volatile String databaseStatus = "Not initialised";

    public HistoryService() {
        Properties props = loadProperties();
        this.dbUrl = props.getProperty("db.url", DEFAULT_URL);
        this.dbUser = props.getProperty("db.user", "root");
        this.dbPassword = props.getProperty("db.password", "");
        initDatabase();
    }

    // ----- Public API (unchanged signatures) -----

    public void addScan(ScanResult result) {
        if (result == null) return;

        if (databaseReady) {
            try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(INSERT_SQL)) {
                String url = result.getTargetUrl() == null ? "" : result.getTargetUrl();
                if (url.length() > MAX_URL_LENGTH) url = url.substring(0, MAX_URL_LENGTH);

                ps.setString(1, result.getScanId());
                ps.setString(2, url);
                ps.setInt(3, result.getRiskScore());
                ps.setString(4, result.getRiskLevel());
                ps.setString(5, result.getAttackType() == null ? null : result.getAttackType().name());
                ps.setInt(6, result.getRiskFactors() == null ? 0 : result.getRiskFactors().size());
                ps.setLong(7, result.getExecutionTimeMs());
                ps.setString(8, result.getTechnicalDetails());
                ps.setString(9, result.getTimestamp());
                ps.executeUpdate();
                return;
            } catch (SQLException e) {
                System.err.println("[HistoryService] MySQL write failed, keeping scan in memory: " + e.getMessage());
            }
        }
        addToMemory(result);
    }

    public List<ScanResult> getRecentScans() {
        if (databaseReady) {
            List<ScanResult> list = new ArrayList<>();
            try (Connection c = connect();
                 Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery(SELECT_SQL)) {
                while (rs.next()) {
                    ScanResult r = new ScanResult();
                    r.setScanId(rs.getString("scan_id"));
                    r.setTargetUrl(rs.getString("url"));
                    r.setRiskScore(rs.getInt("risk_score"));
                    r.setRiskLevel(rs.getString("risk_level"));
                    String type = rs.getString("attack_type");
                    if (type != null) {
                        try {
                            r.setAttackType(PhishingType.valueOf(type));
                        } catch (IllegalArgumentException ignored) {
                            // unknown value in the table: leave attack type empty
                        }
                    }
                    r.setTimestamp(rs.getString("scanned_at"));
                    r.setRiskFactors(new ArrayList<RiskFactor>());
                    list.add(r);
                }
                return Collections.unmodifiableList(list);
            } catch (SQLException e) {
                System.err.println("[HistoryService] MySQL read failed, showing in-memory history: " + e.getMessage());
            }
        }
        return Collections.unmodifiableList(new ArrayList<>(memory));
    }

    /** True when scans are being saved to MySQL. */
    public boolean isDatabaseConnected() {
        return databaseReady;
    }

    /** Human-readable storage status, shown by /api/v1/health. */
    public String getDatabaseStatus() {
        return databaseStatus;
    }

    // ----- Internals -----

    private void initDatabase() {
        try (Connection c = connect(); Statement st = c.createStatement()) {
            st.executeUpdate(CREATE_TABLE);
            databaseReady = true;
            databaseStatus = "MySQL connected";
            System.out.println("[HistoryService] Connected to MySQL. Scan history is saved in table 'scans'.");
        } catch (SQLException e) {
            databaseReady = false;
            databaseStatus = "In-memory fallback (MySQL unavailable)";
            System.err.println("[HistoryService] WARNING: could not connect to MySQL: " + e.getMessage());
            System.err.println("[HistoryService] Check that XAMPP MySQL is started, that lib/ contains the MySQL "
                + "Connector/J jar, and that db.properties is correct. Using in-memory history for now.");
        }
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    private void addToMemory(ScanResult result) {
        memory.add(0, result);
        while (memory.size() > MAX_HISTORY_SIZE) {
            memory.remove(memory.size() - 1);
        }
    }

    private static Properties loadProperties() {
        Properties props = new Properties();
        try (InputStream in = new FileInputStream(CONFIG_FILE)) {
            props.load(in);
        } catch (IOException e) {
            System.out.println("[HistoryService] " + CONFIG_FILE + " not found, using XAMPP defaults "
                + "(localhost:3306, user root, empty password).");
        }
        return props;
    }
}
