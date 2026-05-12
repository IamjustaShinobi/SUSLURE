package com.suslure;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class DatabaseManager {

    private static final String DB_URL = "jdbc:sqlite:suslure.db";
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void initialize() {
        String create = """
            CREATE TABLE IF NOT EXISTS intrusions (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address       TEXT    NOT NULL,
                username         TEXT,
                password         TEXT,
                attack_type      TEXT    NOT NULL,
                timestamp        TEXT    NOT NULL,
                user_agent       TEXT,
                session_id       TEXT,
                payload_used     TEXT,
                mac_address      TEXT,
                vendor           TEXT,
                hostname         TEXT,
                os_name          TEXT,
                browser_name     TEXT,
                device_type      TEXT,
                attack_tool      TEXT,
                all_headers      TEXT,
                open_ports       TEXT,
                network_snapshot TEXT
            )""";

        // Migration columns for existing databases
        String[] migrations = {
            "ALTER TABLE intrusions ADD COLUMN os_name TEXT",
            "ALTER TABLE intrusions ADD COLUMN browser_name TEXT",
            "ALTER TABLE intrusions ADD COLUMN device_type TEXT",
            "ALTER TABLE intrusions ADD COLUMN attack_tool TEXT",
            "ALTER TABLE intrusions ADD COLUMN all_headers TEXT",
            "ALTER TABLE intrusions ADD COLUMN open_ports TEXT",
            "ALTER TABLE intrusions ADD COLUMN network_snapshot TEXT",
        };

        try (Connection c = conn(); Statement s = c.createStatement()) {
            s.execute(create);
            for (String mig : migrations) {
                try (Statement ms = c.createStatement()) { ms.execute(mig); }
                catch (SQLException ignored) {} // column already exists
            }
            System.out.println("[SUSLURE-DB] Database ready → suslure.db");
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] Init: " + e.getMessage());
        }
    }

    // ── Extended log with UA/header profile data ───────────────────────
    public static int logAndGetId(String ip, String username, String password,
                                  String attackType, String payload,
                                  String userAgent, String sessionId,
                                  String osName, String browserName,
                                  String deviceType, String attackTool,
                                  String allHeaders) {
        String sql = """
            INSERT INTO intrusions
              (ip_address,username,password,attack_type,timestamp,
               user_agent,session_id,payload_used,
               os_name,browser_name,device_type,attack_tool,all_headers)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""";

        try (Connection c = conn();
             PreparedStatement ps = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1,  ip);
            ps.setString(2,  username);
            ps.setString(3,  password);
            ps.setString(4,  attackType);
            ps.setString(5,  LocalDateTime.now().format(FMT));
            ps.setString(6,  userAgent);
            ps.setString(7,  sessionId);
            ps.setString(8,  payload);
            ps.setString(9,  osName);
            ps.setString(10, browserName);
            ps.setString(11, deviceType);
            ps.setString(12, attackTool);
            ps.setString(13, allHeaders);
            ps.executeUpdate();
            ResultSet keys = ps.getGeneratedKeys();
            if (keys.next()) {
                int id = keys.getInt(1);
                System.out.printf("[TRAP] id=%-4d | %-15s | %-15s | %s | %s%n",
                        id, ip, attackType,
                        deviceType != null ? deviceType : "—",
                        payload != null ? payload : "—");
                return id;
            }
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] logAndGetId: " + e.getMessage());
        }
        return -1;
    }

    // ── Legacy overload (no profile) — used by SimulateServlet ─────────
    public static int logAndGetId(String ip, String username, String password,
                                  String attackType, String payload,
                                  String userAgent, String sessionId) {
        return logAndGetId(ip, username, password, attackType, payload,
                userAgent, sessionId, null, null, null, null, null);
    }

    // ── Full enrichment update (async phase) ───────────────────────────
    public static void updateEnrichment(int id, String mac, String vendor, String hostname,
                                        String openPorts, String networkSnapshot) {
        if (id < 0) return;
        String sql = """
            UPDATE intrusions
            SET mac_address=?, vendor=?, hostname=?, open_ports=?, network_snapshot=?
            WHERE id=?""";
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, mac);
            ps.setString(2, vendor);
            ps.setString(3, hostname);
            ps.setString(4, openPorts);
            ps.setString(5, networkSnapshot);
            ps.setInt(6, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] updateEnrichment: " + e.getMessage());
        }
    }

    // ── Legacy overload kept for backward compat ───────────────────────
    public static void updateNetworkData(int id, String mac, String vendor, String hostname) {
        updateEnrichment(id, mac, vendor, hostname, null, null);
    }

    // ── Full record by ID (for detail view) ────────────────────────────
    public static IntrusionRecord getRecordById(int id) {
        String sql = "SELECT * FROM intrusions WHERE id=?";
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, id);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return mapRow(rs);
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] getRecordById: " + e.getMessage());
        }
        return null;
    }

    // ── Simulate bulk insert ───────────────────────────────────────────
    public static void logIntrusion(String ip, String username, String password,
                                    String attackType, String payload,
                                    String userAgent, String sessionId,
                                    String mac, String vendor, String hostname) {
        String sql = """
            INSERT INTO intrusions
              (ip_address,username,password,attack_type,timestamp,
               user_agent,session_id,payload_used,mac_address,vendor,hostname)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""";
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, ip); ps.setString(2, username); ps.setString(3, password);
            ps.setString(4, attackType); ps.setString(5, LocalDateTime.now().format(FMT));
            ps.setString(6, userAgent); ps.setString(7, sessionId); ps.setString(8, payload);
            ps.setString(9, mac); ps.setString(10, vendor); ps.setString(11, hostname);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[DB-ERROR] logIntrusion: " + e.getMessage());
        }
    }

    public static List<IntrusionRecord> getAllRecords() {
        return queryList("SELECT * FROM intrusions ORDER BY id DESC", null);
    }

    public static List<IntrusionRecord> getByAttackType(String type) {
        return queryList("SELECT * FROM intrusions WHERE attack_type=? ORDER BY id DESC", type);
    }

    public static int getTotalCount()             { return count("SELECT COUNT(*) FROM intrusions", null); }
    public static int getCountByType(String type) { return count("SELECT COUNT(*) FROM intrusions WHERE attack_type=?", type); }
    public static int getUniqueIpCount()          { return count("SELECT COUNT(DISTINCT ip_address) FROM intrusions", null); }

    public static void clearAll() {
        try (Connection c = conn(); Statement s = c.createStatement()) {
            s.execute("DELETE FROM intrusions");
            System.out.println("[DB] Records cleared.");
        } catch (SQLException e) { System.err.println("[DB-ERROR] Clear: " + e.getMessage()); }
    }

    // ── Helpers ────────────────────────────────────────────────────────
    private static Connection conn() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    private static IntrusionRecord mapRow(ResultSet rs) throws SQLException {
        return new IntrusionRecord(
            rs.getInt("id"),
            rs.getString("ip_address"),    rs.getString("username"),
            rs.getString("password"),      rs.getString("attack_type"),
            rs.getString("timestamp"),     rs.getString("user_agent"),
            rs.getString("session_id"),    rs.getString("payload_used"),
            rs.getString("mac_address"),   rs.getString("vendor"),
            rs.getString("hostname"),
            rs.getString("os_name"),       rs.getString("browser_name"),
            rs.getString("device_type"),   rs.getString("attack_tool"),
            rs.getString("all_headers"),   rs.getString("open_ports"),
            rs.getString("network_snapshot")
        );
    }

    private static List<IntrusionRecord> queryList(String sql, String param) {
        List<IntrusionRecord> list = new ArrayList<>();
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            if (param != null) ps.setString(1, param);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) list.add(mapRow(rs));
        } catch (SQLException e) { System.err.println("[DB-ERROR] Query: " + e.getMessage()); }
        return list;
    }

    private static int count(String sql, String param) {
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            if (param != null) ps.setString(1, param);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) { System.err.println("[DB-ERROR] Count: " + e.getMessage()); }
        return 0;
    }
}
