package com.honeytrap;

/**
 * Model class representing one row in the intrusions database table.
 * Demonstrates OOP Encapsulation — all fields private, accessed via getters.
 */
public class IntrusionRecord {

    // ── Private fields (Encapsulation) ───────────────────────────────────
    private final int    id;
    private final String ipAddress;
    private final String username;
    private final String password;
    private final String attackType;   // SQLI | BRUTE_FORCE | SESSION_HIJACK | NORMAL
    private final String timestamp;
    private final String userAgent;
    private final String sessionId;
    private final String payloadUsed;  // The exact payload that triggered detection

    /** Attack type constants */
    public static final String TYPE_SQLI     = "SQLI";
    public static final String TYPE_BRUTE    = "BRUTE_FORCE";
    public static final String TYPE_HIJACK   = "SESSION_HIJACK";
    public static final String TYPE_NORMAL   = "NORMAL";

    // ── Constructor ───────────────────────────────────────────────────────
    public IntrusionRecord(int id, String ipAddress, String username, String password,
                           String attackType, String timestamp,
                           String userAgent, String sessionId, String payloadUsed) {
        this.id          = id;
        this.ipAddress   = ipAddress;
        this.username    = username;
        this.password    = password;
        this.attackType  = attackType;
        this.timestamp   = timestamp;
        this.userAgent   = userAgent;
        this.sessionId   = sessionId;
        this.payloadUsed = payloadUsed;
    }

    // ── Getters ────────────────────────────────────────────────────────────
    public int    getId()          { return id; }
    public String getIpAddress()   { return ipAddress; }
    public String getUsername()    { return username  != null ? username  : ""; }
    public String getPassword()    { return password  != null ? password  : ""; }
    public String getAttackType()  { return attackType; }
    public String getTimestamp()   { return timestamp; }
    public String getUserAgent()   { return userAgent  != null ? userAgent  : ""; }
    public String getSessionId()   { return sessionId  != null ? sessionId  : ""; }
    public String getPayloadUsed() { return payloadUsed != null ? payloadUsed : ""; }

    /** Returns CSS class name for dashboard row coloring */
    public String getCssClass() {
        return switch (attackType) {
            case TYPE_SQLI   -> "row-sqli";
            case TYPE_BRUTE  -> "row-brute";
            case TYPE_HIJACK -> "row-hijack";
            default          -> "row-normal";
        };
    }

    /** Returns emoji badge for display */
    public String getBadge() {
        return switch (attackType) {
            case TYPE_SQLI   -> "💉 SQLi";
            case TYPE_BRUTE  -> "🔨 Brute";
            case TYPE_HIJACK -> "👻 Hijack";
            default          -> "🔐 Normal";
        };
    }

    /** Safe HTML-escaped username for display */
    public String getSafeUsername() { return escHtml(getUsername()); }
    public String getSafePassword() { return escHtml(getPassword()); }
    public String getSafePayload()  { return escHtml(getPayloadUsed()); }

    private static String escHtml(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;")
                .replace(">","&gt;").replace("\"","&quot;");
    }

    @Override
    public String toString() {
        return String.format("[%d] %s | %s | %s | %s | payload=%s",
                id, attackType, ipAddress, username, timestamp, payloadUsed);
    }
}
