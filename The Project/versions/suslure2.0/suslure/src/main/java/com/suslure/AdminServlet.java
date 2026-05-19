package com.suslure;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.*;

public class AdminServlet extends HttpServlet {

    private static final String ADMIN_USER  = "SusLure";
    private static final String ADMIN_PASS  = "thats a secret baby";
    private static final String SESSION_KEY = "suslure_admin_auth";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        res.setContentType("text/html;charset=UTF-8");

        HttpSession session = req.getSession(false);
        boolean authed = session != null && Boolean.TRUE.equals(session.getAttribute(SESSION_KEY));
        if (!authed) { res.getWriter().write(buildLogin(null)); return; }

        // Detail view
        String detailId = req.getParameter("detail");
        if (detailId != null) {
            try {
                IntrusionRecord r = DatabaseManager.getRecordById(Integer.parseInt(detailId));
                if (r != null) { res.getWriter().write(buildDetail(r)); return; }
            } catch (NumberFormatException ignored) {}
        }

        // Trigger manual scan
        if ("scan".equals(req.getParameter("action"))) {
            NetworkMonitor.triggerScan();
            res.sendRedirect("/admin"); return;
        }

        // Main dashboard
        String filter = req.getParameter("type");
        List<IntrusionRecord> records = (filter != null && !filter.isBlank())
                ? DatabaseManager.getByAttackType(filter.toUpperCase())
                : DatabaseManager.getAllRecords();

        res.getWriter().write(buildDashboard(records,
                DatabaseManager.getTotalCount(),
                DatabaseManager.getCountByType(IntrusionRecord.TYPE_SQLI),
                DatabaseManager.getCountByType(IntrusionRecord.TYPE_BRUTE),
                DatabaseManager.getCountByType(IntrusionRecord.TYPE_HIJACK),
                DatabaseManager.getCountByType(IntrusionRecord.TYPE_NORMAL),
                DatabaseManager.getUniqueIpCount(),
                filter));
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        String action = req.getParameter("action");
        if ("auth".equals(action)) {
            if (ADMIN_USER.equals(req.getParameter("username"))
                    && ADMIN_PASS.equals(req.getParameter("password"))) {
                HttpSession s = req.getSession(true);
                s.setAttribute(SESSION_KEY, Boolean.TRUE);
                s.setMaxInactiveInterval(3600);
                res.sendRedirect("/admin");
            } else {
                res.setContentType("text/html;charset=UTF-8");
                res.getWriter().write(buildLogin("Invalid credentials."));
            }
            return;
        }
        HttpSession session = req.getSession(false);
        if (session == null || !Boolean.TRUE.equals(session.getAttribute(SESSION_KEY))) {
            res.sendRedirect("/admin"); return;
        }
        if      ("clear".equals(action))  DatabaseManager.clearAll();
        else if ("logout".equals(action)) session.invalidate();
        else if ("scan".equals(action))   NetworkMonitor.triggerScan();
        res.sendRedirect("/admin");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  DETAIL VIEW
    // ═══════════════════════════════════════════════════════════════════
    private String buildDetail(IntrusionRecord r) {
        String ac = r.getAccentColor();
        String mapRows = buildNetworkMapRows(r.getNetworkSnapshot(), r.getIpAddress());
        String headersHtml = r.getAllHeaders().isEmpty() ? "<em style='color:rgba(0,255,70,0.3)'>No headers captured</em>"
                : "<pre style='white-space:pre-wrap;word-break:break-all;color:rgba(0,255,70,0.75);font-family:Share Tech Mono,monospace;font-size:11px;line-height:1.6'>"
                  + esc(r.getAllHeaders()) + "</pre>";

        String portHtml = r.getOpenPorts().isEmpty() ? "<span style='color:rgba(0,255,70,0.3)'>Not scanned yet...</span>"
                : formatPorts(r.getOpenPorts());

        NetworkMonitor.DeviceInfo dev = NetworkMonitor.getDeviceByIp(r.getIpAddress());

        return "<!DOCTYPE html><html lang='en'><head>"
            + "<meta charset='UTF-8'/><meta name='viewport' content='width=device-width,initial-scale=1'/>"
            + "<title>SUSLURE &mdash; Attack #" + r.getId() + "</title>"
            + "<style>"
            + "@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&family=Rajdhani:wght@400;500;600&display=swap');"
            + "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}"
            + "body{background:#000;font-family:'Rajdhani',sans-serif;color:#8ab89a;min-height:100vh}"
            + "body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,70,0.01) 2px,rgba(0,255,70,0.01) 3px);pointer-events:none;z-index:9999}"
            + ".topbar{background:rgba(0,4,1,0.96);border-bottom:1px solid rgba(0,255,70,0.15);padding:0 28px;height:54px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;backdrop-filter:blur(12px)}"
            + ".brand{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:900;color:#00ff46;letter-spacing:3px}"
            + ".back{font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.5);text-decoration:none;letter-spacing:2px;padding:6px 12px;border:1px solid rgba(0,255,70,0.2);transition:all .2s}"
            + ".back:hover{color:#00ff46;border-color:rgba(0,255,70,0.5)}"
            + ".page{max-width:1400px;margin:0 auto;padding:28px 22px}"
            + ".dh{display:flex;align-items:center;gap:14px;margin-bottom:24px}"
            + ".dh-title{font-family:'Orbitron',sans-serif;font-size:18px;font-weight:900;color:#00ff46;letter-spacing:4px}"
            + ".badge{font-family:'Share Tech Mono',monospace;font-size:10px;padding:4px 10px;border:1px solid;letter-spacing:1px}"
            + ".grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}"
            + "@media(max-width:900px){.grid2{grid-template-columns:1fr}}"
            + ".card{background:rgba(0,5,1,0.85);border:1px solid rgba(0,255,70,0.12);padding:22px 24px;position:relative}"
            + ".card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,70,0.3),transparent)}"
            + ".card-title{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:3px;color:rgba(0,255,70,0.45);margin-bottom:18px;text-transform:uppercase}"
            + ".field{display:flex;align-items:flex-start;padding:7px 0;border-bottom:1px solid rgba(0,255,70,0.05)}"
            + ".field:last-child{border-bottom:none}"
            + ".fl{font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.35);letter-spacing:2px;min-width:120px;padding-top:1px}"
            + ".fv{font-family:'Share Tech Mono',monospace;font-size:12px;color:rgba(0,255,70,0.85);word-break:break-all}"
            + ".fv.hi{font-size:15px;font-weight:bold}"
            + ".fv.dim{color:rgba(100,150,100,0.45)}"
            + ".fv.red{color:#ff5555}"
            + ".section{margin-bottom:14px}"
            + ".section-title{font-family:'Orbitron',sans-serif;font-size:11px;font-weight:700;color:#00ff46;letter-spacing:3px;padding:14px 24px;background:rgba(0,255,70,0.04);border:1px solid rgba(0,255,70,0.12);border-bottom:none;text-transform:uppercase}"
            + ".section-body{background:rgba(0,5,1,0.85);border:1px solid rgba(0,255,70,0.12);padding:20px 24px}"
            + "table{width:100%;border-collapse:collapse;font-size:12px}"
            + "thead th{background:rgba(0,4,1,0.95);color:rgba(0,255,70,0.5);font-family:'Share Tech Mono',monospace;font-size:8px;letter-spacing:2px;text-transform:uppercase;padding:10px 12px;text-align:left;border-bottom:1px solid rgba(0,255,70,0.1);white-space:nowrap}"
            + "tbody td{padding:8px 12px;border-bottom:1px solid rgba(0,255,70,0.04);font-family:'Share Tech Mono',monospace;font-size:11px;vertical-align:middle}"
            + ".tr-attacker td{background:rgba(255,59,59,0.07);border-left:2px solid #ff3b3b;color:#ff8888}"
            + ".tr-us td{background:rgba(0,255,70,0.04);border-left:2px solid #00ff46;color:rgba(0,255,70,0.7)}"
            + ".tr-gw td{background:rgba(255,140,0,0.05);border-left:2px solid #ff8c00;color:rgba(255,140,0,0.8)}"
            + ".port-tag{display:inline-block;font-family:'Share Tech Mono',monospace;font-size:10px;padding:2px 7px;border:1px solid rgba(255,59,59,0.4);color:#ff6b6b;background:rgba(255,59,59,0.07);margin:2px}"
            + ".empty-map{color:rgba(0,255,70,0.25);font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px;padding:20px 0;text-align:center}"
            + "footer{text-align:center;padding:24px;font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.15);letter-spacing:3px;border-top:1px solid rgba(0,255,70,0.08);margin-top:16px}"
            + "</style></head><body>"
            + "<div class='topbar'><span class='brand'>&#9672; SUSLURE</span>"
            + "<a href='/admin' class='back'>&#8592; BACK TO DASHBOARD</a></div>"
            + "<div class='page'>"

            // Header
            + "<div class='dh'>"
            + "<span class='dh-title'>ATTACK RECORD #" + r.getId() + "</span>"
            + "<span class='badge' style='color:" + ac + ";border-color:" + ac + "55;background:" + ac + "11'>" + esc(r.getBadge()) + "</span>"
            + "<span style='font-family:Share Tech Mono,monospace;font-size:9px;color:rgba(0,255,70,0.3);letter-spacing:2px;margin-left:auto'>" + esc(r.getTimestamp()) + "</span>"
            + "</div>"

            // Cards row
            + "<div class='grid2'>"

            // Left: Attacker Identity
            + "<div class='card'><div class='card-title'>&#128373; Attacker Identity</div>"
            + field("Local IP",      "<span class='hi' style='color:#ff5555'>" + esc(r.getIpAddress()) + "</span>")
            + field("MAC Address",   r.getMacAddress().isEmpty() ? "<span class='dim'>Scanning...</span>" : esc(r.getMacAddress()))
            + field("HW Vendor",     r.getVendor().isEmpty()     ? "<span class='dim'>Unknown</span>"    : esc(r.getVendor()))
            + field("Device Type",   r.getDeviceType().isEmpty() ? "<span class='dim'>Unknown</span>"    : esc(r.getDeviceType()))
            + field("Hostname",      r.getHostname().isEmpty()   ? "<span class='dim'>(no hostname)</span>" : esc(r.getHostname()))
            + field("OS",            r.getOsName().isEmpty()     ? "<span class='dim'>Unknown</span>"    : esc(r.getOsName()))
            + field("Browser",       r.getBrowserName().isEmpty()? "<span class='dim'>Unknown</span>"    : esc(r.getBrowserName()))
            + field("Attack Tool",   r.getAttackTool().isEmpty() ? "<span class='dim'>None detected</span>" : "<span class='red'>" + esc(r.getAttackTool()) + "</span>")
            + (dev != null ? field("Live Status", "<span style='color:#00ff88'>&#9679; Device visible on LAN now</span>") : "")
            + "</div>"

            // Right: Attack Details
            + "<div class='card'><div class='card-title'>&#9876; Attack Details</div>"
            + field("Attack Type",  "<span style='color:" + ac + "'>" + esc(r.getBadge()) + "</span>")
            + field("Username",     esc(r.getUsername()))
            + field("Password",     esc(r.getPassword()))
            + field("Payload",      r.getPayloadUsed().isEmpty() ? "<span class='dim'>—</span>" : "<span class='red'>" + esc(r.getPayloadUsed()) + "</span>")
            + field("Session Token",r.getSessionId().isEmpty()   ? "<span class='dim'>—</span>" : esc(r.getSessionId()))
            + field("Timestamp",    esc(r.getTimestamp()))
            + field("Open Ports",   portHtml)
            + "</div></div>"  // end grid2

            // Network Map
            + "<div class='section'>"
            + "<div class='section-title'>&#127760; LAN Network Map at Time of Attack"
            + " <span style='font-size:8px;font-weight:normal;opacity:.5;margin-left:12px'>"
            + (r.getNetworkSnapshot().isEmpty() ? "scan pending" : NetworkMonitor.getDeviceCount() + " live devices") + "</span></div>"
            + "<div class='section-body'>"
            + (mapRows.isEmpty()
                ? "<div class='empty-map'>&#9674; Network snapshot not available &mdash; waiting for background scan</div>"
                : "<table><thead><tr>"
                + "<th>IP ADDRESS</th><th>MAC ADDRESS</th><th>VENDOR</th>"
                + "<th>HOSTNAME</th><th>DEVICE TYPE</th><th>ROLE</th>"
                + "</tr></thead><tbody>" + mapRows + "</tbody></table>")
            + "</div></div>"

            // HTTP Headers
            + "<div class='section'>"
            + "<div class='section-title'>&#128196; Full HTTP Request Headers</div>"
            + "<div class='section-body'>" + headersHtml + "</div></div>"

            + "</div>" // end page
            + "<footer>SUSLURE HONEYPOT &nbsp;&#183;&nbsp; ATTACK #" + r.getId() + " &nbsp;&#183;&nbsp; " + esc(r.getTimestamp()) + "</footer>"
            + "</body></html>";
    }

    private String field(String label, String value) {
        return "<div class='field'><span class='fl'>" + label + "</span>"
             + "<span class='fv'>" + value + "</span></div>";
    }

    private String formatPorts(String ports) {
        if (ports == null || ports.isEmpty() || ports.equals("None detected"))
            return "<span style='color:rgba(0,255,70,0.3)'>None detected</span>";
        StringBuilder sb = new StringBuilder();
        for (String p : ports.split("\\s*\\|\\s*"))
            sb.append("<span class='port-tag'>").append(esc(p.trim())).append("</span>");
        return sb.toString();
    }

    /** Parse the stored JSON snapshot and render as table rows. */
    private String buildNetworkMapRows(String json, String attackerIp) {
        if (json == null || json.isBlank() || json.equals("[]")) return "";
        StringBuilder sb = new StringBuilder();
        Pattern obj = Pattern.compile("\\{([^}]+)\\}");
        Matcher om = obj.matcher(json);
        while (om.find()) {
            String o   = om.group(1);
            String ip  = jsonStr(o, "ip");
            String mac = jsonStr(o, "mac");
            String ven = jsonStr(o, "vendor");
            String hst = jsonStr(o, "host");
            String typ = jsonStr(o, "type");
            boolean gw = "true".equals(jsonBool(o, "gw"));
            boolean us = "true".equals(jsonBool(o, "us"));
            boolean isAttacker = ip.equals(attackerIp);

            String rowClass = isAttacker ? "tr-attacker" : (us ? "tr-us" : (gw ? "tr-gw" : ""));
            String role     = isAttacker ? "&#128680; ATTACKER" : (us ? "&#127959; Honeypot Host" : (gw ? "&#127760; Gateway" : ""));

            sb.append("<tr class='").append(rowClass).append("'>")
              .append("<td>").append(esc(ip)).append("</td>")
              .append("<td>").append(esc(mac)).append("</td>")
              .append("<td>").append(esc(ven)).append("</td>")
              .append("<td>").append(esc(hst)).append("</td>")
              .append("<td>").append(esc(typ)).append("</td>")
              .append("<td>").append(role).append("</td>")
              .append("</tr>");
        }
        return sb.toString();
    }

    private String jsonStr(String obj, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(obj);
        return m.find() ? m.group(1) : "";
    }
    private String jsonBool(String obj, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)").matcher(obj);
        return m.find() ? m.group(1) : "false";
    }

    // ═══════════════════════════════════════════════════════════════════
    //  MAIN DASHBOARD
    // ═══════════════════════════════════════════════════════════════════
    private String buildDashboard(List<IntrusionRecord> records,
                                  int total, int sqli, int brute,
                                  int hijack, int normal, int uniq, String filter) {

        // Build attack table rows
        StringBuilder rows = new StringBuilder();
        if (records.isEmpty()) {
            rows.append("<tr><td colspan='10' class='empty'>&#9674; No intrusion records. Waiting for attackers...</td></tr>");
        } else {
            for (IntrusionRecord r : records) {
                String ac  = r.getAccentColor();
                String pl  = r.getPayloadUsed();
                String plD = pl.isEmpty() ? "&mdash;" : (pl.length() > 28 ? esc(pl.substring(0,28)) + "&hellip;" : esc(pl));
                String mac = r.getMacAddress();
                String macD= mac.isEmpty() ? "<span style='color:rgba(0,255,70,0.2)'>…</span>" : esc(mac);
                String dt  = r.getDeviceType();
                String dtD = dt.isEmpty() ? "&mdash;" : esc(dt);
                String os  = r.getOsName();
                String br  = r.getBrowserName();
                String osbr= (os.isEmpty() && br.isEmpty()) ? "&mdash;" : esc(os + (br.isEmpty() ? "" : " / " + br));
                String tool= r.getAttackTool();
                String toolD = tool.isEmpty() ? "<span style='color:rgba(0,255,70,0.2)'>&mdash;</span>"
                        : "<span style='color:#ff5555'>" + esc(tool) + "</span>";

                rows.append("<tr class='").append(r.getCssClass()).append("' onclick=\"location='/admin?detail=").append(r.getId()).append("'\" style='cursor:pointer'>")
                    .append("<td class='mono dim'>").append(r.getId()).append("</td>")
                    .append("<td><span class='badge' style='color:").append(ac).append(";border-color:").append(ac).append("55;background:").append(ac).append("11'>").append(esc(r.getBadge())).append("</span></td>")
                    .append("<td class='mono' style='color:#ff5555'>").append(esc(r.getIpAddress())).append("</td>")
                    .append("<td class='mono' style='color:rgba(0,200,70,0.6)'>").append(macD).append("</td>")
                    .append("<td>").append(dtD).append("</td>")
                    .append("<td class='dim' style='max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>").append(osbr).append("</td>")
                    .append("<td>").append(toolD).append("</td>")
                    .append("<td class='dim'>").append(esc(r.getUsername())).append("</td>")
                    .append("<td class='payload' style='color:").append(ac).append("'>").append(plD).append("</td>")
                    .append("<td class='mono dim ts'>").append(esc(r.getTimestamp())).append("</td>")
                    .append("</tr>");
            }
        }

        // Live LAN device panel
        StringBuilder lanRows = new StringBuilder();
        List<NetworkMonitor.DeviceInfo> devices = NetworkMonitor.getAllDevices();
        String myIp  = NetworkMonitor.getMyIp();
        String gw    = NetworkMonitor.getGateway();
        String net   = NetworkMonitor.getNetworkBase();
        long   lastScan = NetworkMonitor.getLastScanMs();
        String scanAge  = lastScan == 0 ? "never"
                : ((System.currentTimeMillis() - lastScan) / 1000) + "s ago";

        for (NetworkMonitor.DeviceInfo d : devices) {
            String style = d.isUs ? "color:rgba(0,255,70,0.8)" : (d.isGateway ? "color:#ff8c00" : "color:rgba(0,255,70,0.5)");
            lanRows.append("<tr>")
                .append("<td style='").append(style).append("'>").append(esc(d.ip)).append("</td>")
                .append("<td class='dim'>").append(esc(d.mac)).append("</td>")
                .append("<td class='dim'>").append(esc(d.vendor)).append("</td>")
                .append("<td>").append(esc(d.deviceType)).append("</td>")
                .append("<td class='dim'>").append(esc(d.hostname)).append("</td>")
                .append("</tr>");
        }
        if (devices.isEmpty()) {
            lanRows.append("<tr><td colspan='5' class='empty'>&#9674; Scanning... (first scan starts 3s after startup)</td></tr>");
        }

        String af = filter != null ? filter.toUpperCase() : "ALL";

        return "<!DOCTYPE html><html lang='en'><head>"
            + "<meta charset='UTF-8'/><meta name='viewport' content='width=device-width,initial-scale=1'/>"
            + "<meta http-equiv='refresh' content='15'/>"
            + "<title>SUSLURE &mdash; Dashboard</title><style>"
            + "@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&family=Rajdhani:wght@400;500;600&display=swap');"
            + "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}"
            + "body{background:#000;font-family:'Rajdhani',sans-serif;color:#8ab89a;min-height:100vh;overflow-x:hidden}"
            + "body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,70,0.01) 2px,rgba(0,255,70,0.01) 3px);pointer-events:none;z-index:9999}"
            + ".topbar{background:rgba(0,4,1,0.96);border-bottom:1px solid rgba(0,255,70,0.15);padding:0 28px;height:54px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;backdrop-filter:blur(12px)}"
            + ".brand{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:900;color:#00ff46;letter-spacing:3px;text-shadow:0 0 20px rgba(0,255,70,0.4)}"
            + ".brand-sub{font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.35);letter-spacing:3px;margin-left:12px}"
            + ".topright{display:flex;align-items:center;gap:10px}"
            + ".live{display:flex;align-items:center;gap:6px;font-family:'Share Tech Mono',monospace;font-size:9px;color:#00ff46;letter-spacing:2px}"
            + ".dot{width:6px;height:6px;border-radius:50%;background:#00ff46;animation:blink 1.5s infinite;box-shadow:0 0 8px #00ff46}"
            + "@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}"
            + ".page{max-width:1600px;margin:0 auto;padding:22px 18px}"
            + ".layout{display:grid;grid-template-columns:1fr 340px;gap:16px;align-items:start}"
            + "@media(max-width:1200px){.layout{grid-template-columns:1fr}}"
            + ".stats{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-bottom:16px}"
            + "@media(max-width:900px){.stats{grid-template-columns:repeat(3,1fr)}}"
            + ".sc{background:rgba(0,5,1,0.8);border:1px solid rgba(0,255,70,0.1);padding:16px 14px;position:relative}"
            + ".sc::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,currentColor,transparent);opacity:.3}"
            + ".sn{font-family:'Orbitron',sans-serif;font-size:26px;font-weight:900;display:block;line-height:1;margin-bottom:5px}"
            + ".sl{font-family:'Share Tech Mono',monospace;font-size:8px;letter-spacing:2px;opacity:.45;text-transform:uppercase;display:block}"
            + ".sc-t .sn{color:#00ff46;text-shadow:0 0 20px rgba(0,255,70,0.4)}"
            + ".sc-s .sn{color:#ff3b3b}.sc-b .sn{color:#ff8c00}.sc-h .sn{color:#b026ff}.sc-n .sn{color:#00ff88}.sc-i .sn{color:#facc15}"
            + ".controls{display:flex;align-items:center;gap:6px;margin-bottom:14px;flex-wrap:wrap}"
            + ".fb{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;padding:6px 10px;border:1px solid rgba(0,255,70,0.15);background:transparent;color:rgba(0,255,70,0.4);cursor:pointer;transition:all .2s;text-decoration:none;display:inline-block}"
            + ".fb:hover,.fb.act{color:#00ff46;border-color:rgba(0,255,70,0.5);background:rgba(0,255,70,0.06)}"
            + ".fb-s.act{color:#ff3b3b;border-color:rgba(255,59,59,0.5);background:rgba(255,59,59,0.06)}"
            + ".fb-b.act{color:#ff8c00;border-color:rgba(255,140,0,0.5);background:rgba(255,140,0,0.06)}"
            + ".fb-h.act{color:#b026ff;border-color:rgba(176,38,255,0.5);background:rgba(176,38,255,0.06)}"
            + ".sp{flex:1}"
            + ".ab{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:1px;padding:6px 10px;border:1px solid;background:transparent;cursor:pointer;transition:all .2s;text-decoration:none;display:inline-block}"
            + ".ab-sim{color:rgba(0,255,70,0.7);border-color:rgba(0,255,70,0.25)}.ab-sim:hover{color:#00ff46;border-color:rgba(0,255,70,0.6)}"
            + ".ab-clr{color:rgba(255,59,59,0.7);border-color:rgba(255,59,59,0.25)}.ab-clr:hover{color:#ff3b3b;border-color:rgba(255,59,59,0.6)}"
            + ".ab-scn{color:rgba(0,200,255,0.7);border-color:rgba(0,200,255,0.25)}.ab-scn:hover{color:#00c8ff;border-color:rgba(0,200,255,0.6)}"
            + ".ab-out{color:rgba(0,255,70,0.4);border-color:rgba(0,255,70,0.15)}.ab-out:hover{color:rgba(0,255,70,0.7);border-color:rgba(0,255,70,0.4)}"
            + ".hint{font-family:'Share Tech Mono',monospace;font-size:8px;color:rgba(0,255,70,0.25);letter-spacing:1px;margin-bottom:10px}"
            + ".tw{overflow-x:auto;border:1px solid rgba(0,255,70,0.1)}"
            + "table{width:100%;border-collapse:collapse;font-size:12px}"
            + "thead th{background:rgba(0,4,1,0.95);color:rgba(0,255,70,0.5);font-family:'Share Tech Mono',monospace;font-size:8px;letter-spacing:2px;text-transform:uppercase;padding:10px 10px;text-align:left;border-bottom:1px solid rgba(0,255,70,0.1);white-space:nowrap}"
            + "tbody td{padding:9px 10px;border-bottom:1px solid rgba(0,255,70,0.04);vertical-align:middle;white-space:nowrap}"
            + "tbody tr:hover td{background:rgba(0,255,70,0.03)}"
            + ".row-sqli   td:first-child{border-left:2px solid #ff3b3b}"
            + ".row-brute  td:first-child{border-left:2px solid #ff8c00}"
            + ".row-hijack td:first-child{border-left:2px solid #b026ff}"
            + ".row-normal td:first-child{border-left:2px solid #00ff88}"
            + ".badge{font-family:'Share Tech Mono',monospace;font-size:9px;padding:2px 7px;border:1px solid;white-space:nowrap;letter-spacing:1px}"
            + ".mono{font-family:'Share Tech Mono',monospace;font-size:11px}"
            + ".dim{color:rgba(100,150,100,0.5)}.payload{font-family:'Share Tech Mono',monospace;font-size:11px}"
            + ".ts{font-size:9px;color:rgba(0,255,70,0.3)}.empty{text-align:center;padding:40px;color:rgba(0,255,70,0.2);font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px}"
            // LAN panel
            + ".lan-panel{background:rgba(0,5,1,0.85);border:1px solid rgba(0,255,70,0.12);position:relative}"
            + ".lan-panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,70,0.3),transparent)}"
            + ".lan-title{font-family:'Orbitron',sans-serif;font-size:10px;font-weight:700;color:#00ff46;letter-spacing:3px;padding:14px 16px;border-bottom:1px solid rgba(0,255,70,0.08)}"
            + ".lan-meta{font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.35);padding:10px 16px;border-bottom:1px solid rgba(0,255,70,0.06);letter-spacing:1px;line-height:1.8}"
            + ".lan-table{width:100%;border-collapse:collapse}"
            + ".lan-table thead th{font-family:'Share Tech Mono',monospace;font-size:7px;letter-spacing:2px;color:rgba(0,255,70,0.35);padding:8px 12px;text-align:left;border-bottom:1px solid rgba(0,255,70,0.07);text-transform:uppercase}"
            + ".lan-table tbody td{font-family:'Share Tech Mono',monospace;font-size:10px;padding:7px 12px;border-bottom:1px solid rgba(0,255,70,0.04);color:rgba(0,255,70,0.5);max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
            + ".rn{font-family:'Share Tech Mono',monospace;font-size:8px;color:rgba(0,255,70,0.2);text-align:right;margin-top:6px;letter-spacing:1px}"
            + "footer{text-align:center;padding:20px;font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.15);letter-spacing:3px;border-top:1px solid rgba(0,255,70,0.08);margin-top:14px}"
            + "</style></head><body>"

            + "<div class='topbar'>"
            + "<div><span class='brand'>&#9672; SUSLURE</span><span class='brand-sub'>ATTACK INTELLIGENCE</span></div>"
            + "<div class='topright'><div class='live'><div class='dot'></div>&nbsp;LIVE</div>"
            + "<form method='POST' action='/admin' style='margin:0'><input type='hidden' name='action' value='logout'/>"
            + "<button type='submit' class='ab ab-out'>LOGOUT</button></form>"
            + "</div></div>"

            + "<div class='page'>"
            + "<div class='stats'>"
            + "<div class='sc sc-t'><span class='sn'>" + total  + "</span><span class='sl'>Total Attacks</span></div>"
            + "<div class='sc sc-s'><span class='sn'>" + sqli   + "</span><span class='sl'>SQL Injection</span></div>"
            + "<div class='sc sc-b'><span class='sn'>" + brute  + "</span><span class='sl'>Brute Force</span></div>"
            + "<div class='sc sc-h'><span class='sn'>" + hijack + "</span><span class='sl'>Sess. Hijack</span></div>"
            + "<div class='sc sc-n'><span class='sn'>" + normal + "</span><span class='sl'>Normal</span></div>"
            + "<div class='sc sc-i'><span class='sn'>" + uniq   + "</span><span class='sl'>Unique IPs</span></div>"
            + "</div>"

            + "<div class='layout'><div>"  // left column

            + "<div class='controls'>"
            + "<a href='/admin'                     class='fb " + ("ALL".equals(af)?"act":"") + "'>ALL</a>"
            + "<a href='/admin?type=SQLI'           class='fb fb-s " + ("SQLI".equals(af)?"act":"") + "'>SQLi</a>"
            + "<a href='/admin?type=BRUTE_FORCE'    class='fb fb-b " + ("BRUTE_FORCE".equals(af)?"act":"") + "'>BRUTE</a>"
            + "<a href='/admin?type=SESSION_HIJACK' class='fb fb-h " + ("SESSION_HIJACK".equals(af)?"act":"") + "'>HIJACK</a>"
            + "<a href='/admin?type=NORMAL'         class='fb " + ("NORMAL".equals(af)?"act":"") + "'>NORMAL</a>"
            + "<div class='sp'></div>"
            + "<a href='/simulate' class='ab ab-sim'>&#9889; SIMULATE</a>"
            + "<form method='POST' action='/admin' style='display:inline' onsubmit=\"return confirm('Delete ALL records?')\">"
            + "<input type='hidden' name='action' value='clear'/>"
            + "<button type='submit' class='ab ab-clr'>&#128465; CLEAR</button></form>"
            + "</div>"
            + "<div class='hint'>&#9432; Click any row for full attacker dossier</div>"

            + "<div class='tw'><table><thead><tr>"
            + "<th>#</th><th>TYPE</th><th>LOCAL IP</th><th>MAC</th>"
            + "<th>DEVICE</th><th>OS / BROWSER</th><th>TOOL</th>"
            + "<th>USERNAME</th><th>PAYLOAD</th><th>TIME</th>"
            + "</tr></thead><tbody>" + rows + "</tbody></table></div>"
            + "<div class='rn'>AUTO-REFRESH 15s &nbsp;&#183;&nbsp; " + records.size() + " RECORDS &nbsp;&#183;&nbsp; SUSLURE v1.0</div>"

            + "</div>" // end left column

            // Right: LAN panel
            + "<div class='lan-panel'>"
            + "<div class='lan-title'>&#127760; LAN DEVICES</div>"
            + "<div class='lan-meta'>"
            + "Network: <span style='color:rgba(0,255,70,0.7)'>" + (net != null ? esc(net) : "detecting...") + "</span><br>"
            + "Gateway: <span style='color:#ff8c00'>" + (gw  != null ? esc(gw)  : "unknown") + "</span><br>"
            + "This host: <span style='color:#00ff88'>" + (myIp != null ? esc(myIp) : "unknown") + "</span><br>"
            + "Last scan: <span style='color:rgba(0,255,70,0.5)'>" + scanAge + "</span> &nbsp;"
            + "<a href='/admin?action=scan' style='color:#00c8ff;text-decoration:none;font-size:8px'>&#8635; SCAN NOW</a>"
            + "</div>"
            + "<table class='lan-table'><thead><tr>"
            + "<th>IP</th><th>VENDOR</th><th>TYPE</th><th>HOST</th>"
            + "</tr></thead><tbody>" + lanRows + "</tbody></table>"
            + "</div>"

            + "</div>" // end layout
            + "</div>" // end page
            + "<footer>SUSLURE HONEYPOT &nbsp;&#183;&nbsp; DETECT &nbsp;&#183;&nbsp; TRAP &nbsp;&#183;&nbsp; EXPOSE</footer>"
            + "</body></html>";
    }

    // ═══════════════════════════════════════════════════════════════════
    //  LOGIN PAGE
    // ═══════════════════════════════════════════════════════════════════
    private String buildLogin(String error) {
        String errHtml = error == null ? "" :
                "<div style='background:rgba(255,40,40,0.08);border:1px solid rgba(255,40,40,0.4);border-left:2px solid #ff3b3b;color:#ff6b6b;font-family:Share Tech Mono,monospace;font-size:11px;padding:10px 14px;margin-bottom:16px;display:flex;align-items:center;gap:8px'>"
                + "<span>&#10005;</span>" + esc(error) + "</div>";
        return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'/>"
            + "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
            + "<title>SUSLURE &mdash; Admin</title><style>"
            + "@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap');"
            + "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}"
            + "body{background:#000;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;position:relative}"
            + ".card{width:100%;max-width:380px;background:rgba(0,8,2,0.9);border:1px solid rgba(0,255,70,0.22);padding:44px 40px;position:relative}"
            + ".card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,70,0.5),transparent)}"
            + "h1{font-family:'Orbitron',sans-serif;font-size:18px;font-weight:900;color:#00ff46;letter-spacing:4px;text-align:center;margin-bottom:6px}"
            + ".sub{font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.3);letter-spacing:3px;text-align:center;margin-bottom:30px}"
            + ".lbl{display:block;font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.45);letter-spacing:3px;margin-bottom:7px}"
            + ".fg{margin-bottom:14px}.fw{background:rgba(0,255,70,0.04);border:1px solid rgba(0,255,70,0.18);transition:border-color .2s}"
            + ".fw:focus-within{border-color:rgba(0,255,70,0.6);box-shadow:0 0 0 3px rgba(0,255,70,0.1)}"
            + ".fw input{width:100%;background:transparent;border:none;outline:none;color:#00ff46;font-family:'Share Tech Mono',monospace;font-size:13px;padding:12px 16px}"
            + ".fw input::placeholder{color:rgba(0,255,70,0.2)}"
            + ".btn{width:100%;background:transparent;border:1px solid rgba(0,255,70,0.45);color:#00ff46;font-family:'Orbitron',sans-serif;font-size:11px;font-weight:700;padding:13px;cursor:pointer;letter-spacing:3px;text-transform:uppercase;transition:all .25s;margin-top:6px}"
            + ".btn:hover{border-color:#00ff46;background:rgba(0,255,70,0.07);box-shadow:0 0 25px rgba(0,255,70,0.15)}"
            + "</style></head><body>"
            + "<div class='card'><h1>SUSLURE</h1><p class='sub'>ADMIN ACCESS &middot; AUTHORIZED ONLY</p>"
            + errHtml
            + "<form method='POST' action='/admin'><input type='hidden' name='action' value='auth'/>"
            + "<div class='fg'><label class='lbl'>Username</label><div class='fw'><input type='text' name='username' placeholder='admin username' required/></div></div>"
            + "<div class='fg'><label class='lbl'>Password</label><div class='fw'><input type='password' name='password' placeholder='admin password' required/></div></div>"
            + "<button type='submit' class='btn'>[ ACCESS DASHBOARD ]</button>"
            + "</form></div></body></html>";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");
    }
}
