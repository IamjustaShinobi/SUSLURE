package com.honeytrap;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;

/**
 * TrapController — Serves the 3 "YOU ARE DOOMED" trap pages.
 * Each attack type has its own inner Servlet class for clean separation.
 * Demonstrates OOP Inheritance: each extends HttpServlet.
 */
public class TrapController {

    // ══════════════════════════════════════════════════════════════════════
    //  PAGE 2 — SQL INJECTION TRAP  (/trap/sqli)
    // ══════════════════════════════════════════════════════════════════════
    public static class SqliServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res)
                throws ServletException, IOException {
            String payload = decode(req.getParameter("payload"));
            String user    = decode(req.getParameter("user"));
            String ip      = decode(req.getParameter("ip"));
            String time    = java.time.LocalDateTime.now()
                    .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            res.setContentType("text/html;charset=UTF-8");
            res.getWriter().write(buildSqliPage(ip, user, payload, time));
        }

        private String buildSqliPage(String ip, String user, String payload, String time) {
            return doomedBase(
                "sqli",
                "#ff3b3b",
                "rgba(255,59,59,0.15)",
                "rgba(255,59,59,0.35)",
                "💉",
                "SQL INJECTION DETECTED",
                "YOU ARE DOOMED",
                "Your SQL Injection attempt has been identified, logged, and traced back to your IP address. Every character you typed is now stored in our database.",
                new String[][]{
                    {"Attack Type",    "SQL Injection (SQLi)"},
                    {"Your IP",        ip},
                    {"Username Used",  user},
                    {"Payload Caught", "<code style='color:#ff6b6b;background:rgba(255,59,59,0.1);padding:2px 8px;border-radius:3px;font-family:monospace'>" + esc(payload) + "</code>"},
                    {"Timestamp",      time},
                    {"Status",         "LOGGED · FLAGGED · REPORTED"}
                },
                "HOW WE CAUGHT YOU",
                "Your input was matched against our library of <strong>50+ known SQL injection payloads</strong>. " +
                "The string <em>\"" + esc(payload) + "\"</em> triggered an exact match in our DetectionFilter. " +
                "Your attempt was intercepted before it ever reached the database."
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  PAGE 3 — BRUTE FORCE TRAP  (/trap/bruteforce)
    // ══════════════════════════════════════════════════════════════════════
    public static class BruteServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res)
                throws ServletException, IOException {
            String ip       = decode(req.getParameter("ip"));
            String attempts = decode(req.getParameter("attempts"));
            String since    = decode(req.getParameter("since"));
            String time     = java.time.LocalDateTime.now()
                    .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            res.setContentType("text/html;charset=UTF-8");
            res.getWriter().write(buildBrutePage(ip, attempts, since, time));
        }

        private String buildBrutePage(String ip, String attempts, String since, String time) {
            return doomedBase(
                "brute",
                "#ff8c00",
                "rgba(255,140,0,0.15)",
                "rgba(255,140,0,0.35)",
                "🔨",
                "BRUTE FORCE DETECTED",
                "YOU ARE DOOMED",
                "Your repeated login attempts have triggered our brute-force detection system. Your IP has been flagged and all your attempts have been recorded.",
                new String[][]{
                    {"Attack Type",      "Brute Force Attack"},
                    {"Your IP",          ip},
                    {"Failed Attempts",  attempts + " / " + DetectionFilter.BRUTE_THRESHOLD + " (threshold exceeded)"},
                    {"First Attempt",    since},
                    {"Flagged At",       time},
                    {"Status",           "IP FLAGGED · ATTEMPTS LOGGED · LOCKED OUT"}
                },
                "HOW WE CAUGHT YOU",
                "Our server tracks every failed login attempt per IP address using a <strong>ConcurrentHashMap</strong>. " +
                "Your IP (<em>" + esc(ip) + "</em>) exceeded the threshold of <strong>" +
                DetectionFilter.BRUTE_THRESHOLD + " failed attempts</strong>. " +
                "Your counter has been preserved — even if you try to reconnect, we still remember."
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  PAGE 4 — SESSION HIJACK TRAP  (/trap/hijack)
    // ══════════════════════════════════════════════════════════════════════
    public static class HijackServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res)
                throws ServletException, IOException {
            String ip    = decode(req.getParameter("ip"));
            String token = decode(req.getParameter("token"));
            String time  = java.time.LocalDateTime.now()
                    .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            res.setContentType("text/html;charset=UTF-8");
            res.getWriter().write(buildHijackPage(ip, token, time));
        }

        private String buildHijackPage(String ip, String token, String time) {
            return doomedBase(
                "hijack",
                "#b026ff",
                "rgba(176,38,255,0.15)",
                "rgba(176,38,255,0.35)",
                "👻",
                "SESSION HIJACKING DETECTED",
                "YOU ARE DOOMED",
                "A tampered or forged session token was detected in your request. You attempted to impersonate another user's session. This incident has been fully logged.",
                new String[][]{
                    {"Attack Type",      "Session Hijacking"},
                    {"Your IP",          ip},
                    {"Tampered Token",   "<code style='color:#d06bff;background:rgba(176,38,255,0.1);padding:2px 8px;border-radius:3px;font-family:monospace;word-break:break-all'>" + esc(token) + "</code>"},
                    {"Expected",         "A valid HONEYTRAP_TOKEN issued by this server"},
                    {"Detected At",      time},
                    {"Status",           "TOKEN INVALIDATED · SESSION TERMINATED · LOGGED"}
                },
                "HOW WE CAUGHT YOU",
                "Every visitor to this portal is issued a unique <strong>HONEYTRAP_TOKEN</strong> cookie, " +
                "signed and stored server-side. When you submitted the login form, your cookie value " +
                "<em>\"" + esc(token) + "\"</em> was checked against our <strong>valid token registry</strong>. " +
                "It did not match any token we issued — meaning you forged or tampered with it."
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  SHARED HTML BUILDER — used by all 3 doomed pages
    // ══════════════════════════════════════════════════════════════════════
    private static String doomedBase(
            String type, String accent, String accentBg, String accentBorder,
            String icon, String eyebrow, String heading, String subtitle,
            String[][] details, String explainTitle, String explainText) {

        StringBuilder detailRows = new StringBuilder();
        for (String[] row : details) {
            detailRows.append("<tr>")
                .append("<td class='dl'>").append(esc(row[0])).append("</td>")
                .append("<td class='dv'>").append(row[1]).append("</td>")
                .append("</tr>");
        }

        return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Security Alert — HoneyTrap</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&family=Inter:wght@400;500;600&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{--accent:ACCENT;--accent-bg:ACCENT_BG;--accent-border:ACCENT_BORDER}
  body{background:#02040a;font-family:'Inter',sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:flex-start;padding:40px 20px;overflow-x:hidden;position:relative}
  body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(255,0,0,0.008) 3px,rgba(255,0,0,0.008) 4px);pointer-events:none;z-index:9999}
  .bg-glow{position:fixed;width:700px;height:700px;background:radial-gradient(circle,ACCENT_BG 0%,transparent 60%);top:50%;left:50%;transform:translate(-50%,-50%);pointer-events:none;animation:gp 4s ease-in-out infinite}
  @keyframes gp{0%,100%{transform:translate(-50%,-50%) scale(1);opacity:.5}50%{transform:translate(-50%,-50%) scale(1.1);opacity:.8}}
  .grid{position:fixed;inset:0;background-image:linear-gradient(ACCENT_BG2 1px,transparent 1px),linear-gradient(90deg,ACCENT_BG2 1px,transparent 1px);background-size:40px 40px;pointer-events:none;opacity:.4}
  .wrap{width:100%;max-width:700px;z-index:1;animation:fadeIn .5s ease}
  @keyframes fadeIn{from{opacity:0;transform:translateY(-16px)}to{opacity:1;transform:translateY(0)}}
  .eyebrow{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:5px;color:var(--accent);background:var(--accent-bg);border:1px solid var(--accent-border);padding:7px 18px;display:inline-block;margin-bottom:20px;text-transform:uppercase}
  .icon-wrap{font-size:64px;margin:16px 0;display:block;animation:iconPulse 2s ease-in-out infinite}
  @keyframes iconPulse{0%,100%{transform:scale(1)}50%{transform:scale(1.08)}}
  h1{font-family:'Orbitron',sans-serif;font-size:clamp(32px,6vw,62px);font-weight:900;color:var(--accent);text-shadow:0 0 40px var(--accent),0 0 80px var(--accent-border);letter-spacing:-1px;line-height:1;margin-bottom:16px;animation:glitch 3s infinite}
  @keyframes glitch{0%,90%,100%{text-shadow:0 0 40px var(--accent),0 0 80px var(--accent-border)}91%{text-shadow:-3px 0 #ff0,3px 0 #0ff,0 0 40px var(--accent)}93%{text-shadow:3px 0 #ff0,-3px 0 #0ff,0 0 40px var(--accent)}95%{text-shadow:0 0 40px var(--accent)}}
  .subtitle{font-size:15px;color:rgba(200,210,230,0.65);max-width:520px;line-height:1.7;margin-bottom:36px}
  .detail-card{background:rgba(0,0,0,0.5);border:1px solid var(--accent-border);padding:0;margin-bottom:24px;overflow:hidden}
  .detail-card table{width:100%;border-collapse:collapse}
  .dl{font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:1px;color:var(--accent);padding:12px 20px;width:160px;border-bottom:1px solid rgba(255,255,255,0.05);vertical-align:top;background:rgba(0,0,0,0.3);text-transform:uppercase}
  .dv{font-size:13px;color:rgba(220,230,245,0.85);padding:12px 20px;border-bottom:1px solid rgba(255,255,255,0.05);vertical-align:top;line-height:1.5}
  .explain{background:var(--accent-bg);border:1px solid var(--accent-border);border-left:3px solid var(--accent);padding:20px 24px;margin-bottom:24px}
  .explain-title{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:3px;color:var(--accent);margin-bottom:10px;text-transform:uppercase}
  .explain p{font-size:13.5px;color:rgba(200,215,235,0.75);line-height:1.7}
  .back-btn{display:inline-flex;align-items:center;gap:8px;background:rgba(255,255,255,0.04);border:1px solid var(--accent-border);color:var(--accent);font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px;padding:10px 20px;text-decoration:none;transition:all .2s;cursor:pointer;margin-right:10px;margin-bottom:10px}
  .back-btn:hover{background:var(--accent-bg);color:#fff}
  .admin-btn{display:inline-flex;align-items:center;gap:8px;background:rgba(34,211,238,0.06);border:1px solid rgba(34,211,238,0.3);color:#22d3ee;font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px;padding:10px 20px;text-decoration:none;transition:all .2s;cursor:pointer;margin-bottom:10px}
  .admin-btn:hover{background:rgba(34,211,238,0.12);color:#fff}
  .counter{font-family:'Orbitron',monospace;font-size:11px;color:rgba(var(--accent-rgb),.4);letter-spacing:3px;margin-top:30px;text-align:center;opacity:.5}
</style>
</head>
<body>
<div class="bg-glow"></div>
<div class="grid"></div>
<div class="wrap">
  <div class="eyebrow">⚠ SECURITY ALERT — HONEYTRAP ACTIVATED</div>
  <span class="icon-wrap">ICON</span>
  <div class="eyebrow" style="letter-spacing:3px">EYEBROW</div>
  <h1>HEADING</h1>
  <p class="subtitle">SUBTITLE</p>
  <div class="detail-card">
    <table>DETAIL_ROWS</table>
  </div>
  <div class="explain">
    <div class="explain-title">EXPLAIN_TITLE</div>
    <p>EXPLAIN_TEXT</p>
  </div>
  <a href="/login" class="back-btn">← Return to Login</a>
  <a href="/admin" class="admin-btn">📊 View Attack Dashboard</a>
</div>
</body>
</html>
"""
        .replace("ACCENT",       accent)
        .replace("ACCENT_BG2",   accentBg.replace("0.15","0.03"))
        .replace("ACCENT_BG",    accentBg)
        .replace("ACCENT_BORDER",accentBorder)
        .replace("ICON",         icon)
        .replace("EYEBROW",      eyebrow)
        .replace("HEADING",      heading)
        .replace("SUBTITLE",     subtitle)
        .replace("DETAIL_ROWS",  detailRows.toString())
        .replace("EXPLAIN_TITLE",explainTitle)
        .replace("EXPLAIN_TEXT", explainText);
    }

    private static String decode(String s) {
        if (s == null) return "Unknown";
        try { return java.net.URLDecoder.decode(s, "UTF-8"); }
        catch (Exception e) { return s; }
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;")
                .replace(">","&gt;").replace("\"","&quot;");
    }
}
