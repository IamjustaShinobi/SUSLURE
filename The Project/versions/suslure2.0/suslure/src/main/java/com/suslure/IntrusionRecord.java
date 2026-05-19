package com.suslure;

public class IntrusionRecord {

    public static final String TYPE_SQLI   = "SQLI";
    public static final String TYPE_BRUTE  = "BRUTE_FORCE";
    public static final String TYPE_HIJACK = "SESSION_HIJACK";
    public static final String TYPE_NORMAL = "NORMAL";

    private final int    id;
    private final String ipAddress, username, password;
    private final String attackType, timestamp;
    private final String userAgent, sessionId, payloadUsed;
    private final String macAddress, vendor, hostname;
    private final String osName, browserName, deviceType, attackTool;
    private final String allHeaders, openPorts, networkSnapshot;

    public IntrusionRecord(int id, String ipAddress, String username, String password,
                           String attackType, String timestamp, String userAgent,
                           String sessionId, String payloadUsed,
                           String macAddress, String vendor, String hostname,
                           String osName, String browserName, String deviceType,
                           String attackTool, String allHeaders,
                           String openPorts, String networkSnapshot) {
        this.id = id; this.ipAddress = ipAddress; this.username = username;
        this.password = password; this.attackType = attackType; this.timestamp = timestamp;
        this.userAgent = userAgent; this.sessionId = sessionId; this.payloadUsed = payloadUsed;
        this.macAddress = macAddress; this.vendor = vendor; this.hostname = hostname;
        this.osName = osName; this.browserName = browserName; this.deviceType = deviceType;
        this.attackTool = attackTool; this.allHeaders = allHeaders;
        this.openPorts = openPorts; this.networkSnapshot = networkSnapshot;
    }

    public int    getId()              { return id; }
    public String getIpAddress()       { return s(ipAddress); }
    public String getUsername()        { return s(username); }
    public String getPassword()        { return s(password); }
    public String getAttackType()      { return s(attackType); }
    public String getTimestamp()       { return s(timestamp); }
    public String getUserAgent()       { return s(userAgent); }
    public String getSessionId()       { return s(sessionId); }
    public String getPayloadUsed()     { return s(payloadUsed); }
    public String getMacAddress()      { return s(macAddress); }
    public String getVendor()          { return s(vendor); }
    public String getHostname()        { return s(hostname); }
    public String getOsName()          { return s(osName); }
    public String getBrowserName()     { return s(browserName); }
    public String getDeviceType()      { return s(deviceType); }
    public String getAttackTool()      { return s(attackTool); }
    public String getAllHeaders()      { return s(allHeaders); }
    public String getOpenPorts()       { return s(openPorts); }
    public String getNetworkSnapshot() { return s(networkSnapshot); }

    public String getBadge() {
        return switch (s(attackType)) {
            case TYPE_SQLI   -> "💉 SQLi";
            case TYPE_BRUTE  -> "🔨 Brute";
            case TYPE_HIJACK -> "👻 Hijack";
            default          -> "🔐 Normal";
        };
    }
    public String getCssClass() {
        return switch (s(attackType)) {
            case TYPE_SQLI   -> "row-sqli";
            case TYPE_BRUTE  -> "row-brute";
            case TYPE_HIJACK -> "row-hijack";
            default          -> "row-normal";
        };
    }
    public String getAccentColor() {
        return switch (s(attackType)) {
            case TYPE_SQLI   -> "#ff3b3b";
            case TYPE_BRUTE  -> "#ff8c00";
            case TYPE_HIJACK -> "#b026ff";
            default          -> "#00ff88";
        };
    }
    private static String s(String v) { return v != null ? v : ""; }
    public static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");
    }
}
