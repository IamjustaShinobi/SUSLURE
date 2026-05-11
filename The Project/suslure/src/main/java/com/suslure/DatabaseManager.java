package com.suslure;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * DatabaseManager — All SQL operations for SUSLURE.
 * Uses try-with-resources throughout. No string-concatenated SQL.
 */
public class DatabaseManager {

    private static final String DB_URL = "jdbc:sqlite:suslure.db";
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void initialize() {
        String sql = """
            CREATE TABLE IF NOT EXISTS intrusions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address   TEXT    NOT NULL,
                username     TEXT,
                password     TEXT,
                attack_type  TEXT    NOT NULL,
                timestamp    TEXT    NOT NULL,
                user_agent   TEXT,
                session_id   TEXT,
                payload_used TEXT,
                mac_address  TEXT,
                vendor       TEXT,
                hostname     TEXT
            )
        """;
        try (Connection c = conn(); Statement s = c.createStatement()) {
            s.execute(sql);
            System.out.println("[SUSLURE-DB] Database ready → suslure.db");
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] Init: " + e.getMessage());
        }
    }

    public static void logIntrusion(String ip, String username, String password,
                                    String attackType, String payload,
                                    String userAgent, String sessionId,
                                    String mac, String vendor, String hostname) {
        String sql = """
            INSERT INTO intrusions
              (ip_address,username,password,attack_type,timestamp,
               user_agent,session_id,payload_used,mac_address,vendor,hostname)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """;
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1,  ip);
            ps.setString(2,  username);
            ps.setString(3,  password);
            ps.setString(4,  attackType);
            ps.setString(5,  LocalDateTime.now().format(FMT));
            ps.setString(6,  userAgent);
            ps.setString(7,  sessionId);
            ps.setString(8,  payload);
            ps.setString(9,  mac);
            ps.setString(10, vendor);
            ps.setString(11, hostname);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] Insert: " + e.getMessage());
        }
    }

    // Convenience overload — no network data (filled in async)
    public static void logIntrusion(String ip, String username, String password,
                                    String attackType, String payload,
                                    String userAgent, String sessionId) {
        logIntrusion(ip, username, password, attackType, payload,
                     userAgent, sessionId, null, null, null);
    }

    /**
     * Inserts a record and returns the generated row ID (for async enrichment).
     */
    public static int logAndGetId(String ip, String username, String password,
                                  String attackType, String payload,
                                  String userAgent, String sessionId) {
        String sql = """
            INSERT INTO intrusions
              (ip_address,username,password,attack_type,timestamp,
               user_agent,session_id,payload_used)
            VALUES (?,?,?,?,?,?,?,?)
        """;
        try (Connection c = conn();
             PreparedStatement ps = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, ip);
            ps.setString(2, username);
            ps.setString(3, password);
            ps.setString(4, attackType);
            ps.setString(5, LocalDateTime.now().format(FMT));
            ps.setString(6, userAgent);
            ps.setString(7, sessionId);
            ps.setString(8, payload);
            ps.executeUpdate();
            ResultSet keys = ps.getGeneratedKeys();
            if (keys.next()) {
                int id = keys.getInt(1);
                System.out.printf("[TRAP] id=%d | %-15s | type=%-15s | payload=%s%n",
                        id, ip, attackType, payload != null ? payload : "—");
                return id;
            }
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] logAndGetId: " + e.getMessage());
        }
        return -1;
    }

    /**
     * Updates a record with enriched network data from the async scanner.
     */
    public static void updateNetworkData(int id, String mac, String vendor, String hostname) {
        if (id < 0) return;
        String sql = "UPDATE intrusions SET mac_address=?,vendor=?,hostname=? WHERE id=?";
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, mac);
            ps.setString(2, vendor);
            ps.setString(3, hostname);
            ps.setInt(4, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] updateNetworkData: " + e.getMessage());
        }
    }

    public static List<IntrusionRecord> getAllRecords() {
        return query("SELECT * FROM intrusions ORDER BY id DESC", null);
    }

    public static List<IntrusionRecord> getByAttackType(String type) {
        return query("SELECT * FROM intrusions WHERE attack_type=? ORDER BY id DESC", type);
    }

    public static int getTotalCount()              { return count("SELECT COUNT(*) FROM intrusions", null); }
    public static int getCountByType(String type)  { return count("SELECT COUNT(*) FROM intrusions WHERE attack_type=?", type); }
    public static int getUniqueIpCount()           { return count("SELECT COUNT(DISTINCT ip_address) FROM intrusions", null); }

    public static void clearAll() {
        try (Connection c = conn(); Statement s = c.createStatement()) {
            s.execute("DELETE FROM intrusions");
            System.out.println("[DB] Records cleared.");
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] Clear: " + e.getMessage());
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static Connection conn() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    private static List<IntrusionRecord> query(String sql, String param) {
        List<IntrusionRecord> list = new ArrayList<>();
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            if (param != null) ps.setString(1, param);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                list.add(new IntrusionRecord(
                    rs.getInt("id"),
                    rs.getString("ip_address"),
                    rs.getString("username"),
                    rs.getString("password"),
                    rs.getString("attack_type"),
                    rs.getString("timestamp"),
                    rs.getString("user_agent"),
                    rs.getString("session_id"),
                    rs.getString("payload_used"),
                    rs.getString("mac_address"),
                    rs.getString("vendor"),
                    rs.getString("hostname")
                ));
            }
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] Query: " + e.getMessage());
        }
        return list;
    }

    private static int count(String sql, String param) {
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            if (param != null) ps.setString(1, param);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] Count: " + e.getMessage());
        }
        return 0;
    }
}
