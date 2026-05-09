package com.suslure;

/**
 * IntrusionRecord — OOP model for one attack event.
 * Includes network scanner data (MAC, vendor, hostname) integrated.
 */
public class IntrusionRecord {

    public static final String TYPE_SQLI    = "SQLI";
    public static final String TYPE_BRUTE   = "BRUTE_FORCE";
    public static final String TYPE_HIJACK  = "SESSION_HIJACK";
    public static final String TYPE_NORMAL  = "NORMAL";

    private final int    id;
    private final String ipAddress;
    private final String username;
    private final String password;
    private final String attackType;
    private final String timestamp;
    private final String userAgent;
    private final String sessionId;
    private final String payloadUsed;
    private final String macAddress;
    private final String vendor;
    private final String hostname;

    public IntrusionRecord(int id, String ipAddress, String username, String password,
                           String attackType, String timestamp, String userAgent,
                           String sessionId, String payloadUsed,
                           String macAddress, String vendor, String hostname) {
        this.id          = id;
        this.ipAddress   = ipAddress;
        this.username    = username;
        this.password    = password;
        this.attackType  = attackType;
        this.timestamp   = timestamp;
        this.userAgent   = userAgent;
        this.sessionId   = sessionId;
        this.payloadUsed = payloadUsed;
        this.macAddress  = macAddress;
        this.vendor      = vendor;
        this.hostname    = hostname;
    }

    public int    getId()          { return id; }
    public String getIpAddress()   { return safe(ipAddress); }
    public String getUsername()    { return safe(username); }
    public String getPassword()    { return safe(password); }
    public String getAttackType()  { return safe(attackType); }
    public String getTimestamp()   { return safe(timestamp); }
    public String getUserAgent()   { return safe(userAgent); }
    public String getSessionId()   { return safe(sessionId); }
    public String getPayloadUsed() { return safe(payloadUsed); }
    public String getMacAddress()  { return safe(macAddress); }
    public String getVendor()      { return safe(vendor); }
    public String getHostname()    { return safe(hostname); }

    public String getBadge() {
        return switch (safe(attackType)) {
            case TYPE_SQLI   -> "💉 SQLi";
            case TYPE_BRUTE  -> "🔨 Brute";
            case TYPE_HIJACK -> "👻 Hijack";
            default          -> "🔐 Normal";
        };
    }

    public String getCssClass() {
        return switch (safe(attackType)) {
            case TYPE_SQLI   -> "row-sqli";
            case TYPE_BRUTE  -> "row-brute";
            case TYPE_HIJACK -> "row-hijack";
            default          -> "row-normal";
        };
    }

    public String getAccentColor() {
        return switch (safe(attackType)) {
            case TYPE_SQLI   -> "#ff3b3b";
            case TYPE_BRUTE  -> "#ff8c00";
            case TYPE_HIJACK -> "#b026ff";
            default          -> "#00ff88";
        };
    }

    private static String safe(String s) { return s == null ? "" : s; }

    public static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;")
                .replace(">","&gt;").replace("\"","&quot;");
    }
}
