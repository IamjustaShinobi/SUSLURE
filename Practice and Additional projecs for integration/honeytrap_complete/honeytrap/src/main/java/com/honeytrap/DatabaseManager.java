package com.honeytrap;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * DatabaseManager — Abstraction layer over SQLite.
 * All SQL is hidden here. Callers just call logIntrusion(), getAllRecords(), etc.
 * Demonstrates OOP Abstraction.
 */
public class DatabaseManager {

    private static final String DB_URL = "jdbc:sqlite:honeypot.db";
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** Creates the table on first run. Called once at startup. */
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
                payload_used TEXT
            )
        """;
        try (Connection c = DriverManager.getConnection(DB_URL);
             Statement  s = c.createStatement()) {
            s.execute(sql);
            System.out.println("[DB] Database initialized → honeypot.db");
        } catch (SQLException e) {
            System.err.println("[DB ERROR] Init failed: " + e.getMessage());
        }
    }

    // ── INSERT ─────────────────────────────────────────────────────────────

    /** Logs an intrusion attempt to the database. */
    public static void logIntrusion(String ip, String username, String password,
                                    String attackType, String payload,
                                    String userAgent, String sessionId) {
        String sql = """
            INSERT INTO intrusions
                (ip_address,username,password,attack_type,timestamp,user_agent,session_id,payload_used)
            VALUES (?,?,?,?,?,?,?,?)
        """;
        try (Connection c = DriverManager.getConnection(DB_URL);
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, ip);
            ps.setString(2, username);
            ps.setString(3, password);
            ps.setString(4, attackType);
            ps.setString(5, LocalDateTime.now().format(FMT));
            ps.setString(6, userAgent);
            ps.setString(7, sessionId);
            ps.setString(8, payload);
            ps.executeUpdate();
            System.out.printf("[TRAP] %s | %-15s | type=%-15s | payload=%s%n",
                    LocalDateTime.now().format(FMT), ip, attackType,
                    payload != null ? payload : "—");
        } catch (SQLException e) {
            System.err.println("[DB ERROR] Insert failed: " + e.getMessage());
        }
    }

    // ── SELECT ─────────────────────────────────────────────────────────────

    /** Returns all intrusion records, newest first. */
    public static List<IntrusionRecord> getAllRecords() {
        return query("SELECT * FROM intrusions ORDER BY id DESC", null);
    }

    /** Returns records filtered by attack type. */
    public static List<IntrusionRecord> getByAttackType(String type) {
        return query("SELECT * FROM intrusions WHERE attack_type=? ORDER BY id DESC", type);
    }

    /** Returns total record count. */
    public static int getTotalCount() {
        return countQuery("SELECT COUNT(*) FROM intrusions", null);
    }

    /** Returns count for a specific attack type. */
    public static int getCountByType(String type) {
        return countQuery("SELECT COUNT(*) FROM intrusions WHERE attack_type=?", type);
    }

    /** Returns count of unique IPs. */
    public static int getUniqueIpCount() {
        return countQuery("SELECT COUNT(DISTINCT ip_address) FROM intrusions", null);
    }

    /** Deletes all records. */
    public static void clearAll() {
        try (Connection c = DriverManager.getConnection(DB_URL);
             Statement  s = c.createStatement()) {
            s.execute("DELETE FROM intrusions");
            System.out.println("[DB] All records cleared.");
        } catch (SQLException e) {
            System.err.println("[DB ERROR] Clear failed: " + e.getMessage());
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────

    private static List<IntrusionRecord> query(String sql, String param) {
        List<IntrusionRecord> list = new ArrayList<>();
        try (Connection c = DriverManager.getConnection(DB_URL)) {
            PreparedStatement ps = c.prepareStatement(sql);
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
                    rs.getString("payload_used")
                ));
            }
        } catch (SQLException e) {
            System.err.println("[DB ERROR] Query failed: " + e.getMessage());
        }
        return list;
    }

    private static int countQuery(String sql, String param) {
        try (Connection c = DriverManager.getConnection(DB_URL);
             PreparedStatement ps = c.prepareStatement(sql)) {
            if (param != null) ps.setString(1, param);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            System.err.println("[DB ERROR] Count failed: " + e.getMessage());
        }
        return 0;
    }
}
