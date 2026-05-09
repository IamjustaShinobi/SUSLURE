package com.suslure;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * TrapController — 3 DOOMED pages for SUSLURE.
 * Each is an inner Servlet. All share the buildDoomedPage() engine.
 */
public class TrapController {

    // ══════════════════════════════════════════════════════════════════════
    //  PAGE 2 — SQL INJECTION
    // ══════════════════════════════════════════════════════════════════════
    public static class SqliServlet extends HttpServlet {
        @Override protected void doGet(HttpServletRequest req, HttpServletResponse res)
                throws ServletException, IOException {
            String payload = d(req.getParameter("payload"));
            String user    = d(req.getParameter("user"));
            String ip      = d(req.getParameter("ip"));
            String time    = now();
            res.setContentType("text/html;charset=UTF-8");
            res.getWriter().write(buildDoomedPage(
                "SQLI",
                "#ff3b3b", "rgba(255,59,59,0.12)", "rgba(255,59,59,0.4)",
                "💉",
                "SQL INJECTION DETECTED",
                "YOU USED SQL INJECTION",
                "Your SQL injection payload was intercepted before it reached any database. Every character you typed has been logged, timestamped, and traced to your IP.",
                new String[][]{
                    {"ATTACK TYPE",    "SQL Injection"},
                    {"YOUR IP",        ip},
                    {"USERNAME USED",  e(user)},
                    {"PAYLOAD CAUGHT", "<code style='color:#ff6b6b;background:rgba(255,59,59,0.1);padding:3px 10px;font-family:Share Tech Mono,monospace;border:1px solid rgba(255,59,59,0.3)'>" + e(payload) + "</code>"},
                    {"TIMESTAMP",      time},
                    {"STATUS",         "<span style='color:#ff3b3b;animation:blink 1s infinite'>● LOGGED · FLAGGED · REPORTED</span>"}
                },
                "HOW WE CAUGHT YOU",
                "Your input was matched against a library of <strong style='color:#ff6b6b'>50+ SQL injection signatures</strong> " +
                "including classic auth bypass, UNION attacks, time-based blind, and error-based techniques. " +
                "The payload <em style='color:#ff9999'>\"" + e(payload) + "\"</em> triggered an exact match in our detection engine."
            ));
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  PAGE 3 — BRUTE FORCE
    // ══════════════════════════════════════════════════════════════════════
    public static class BruteServlet extends HttpServlet {
        @Override protected void doGet(HttpServletRequest req, HttpServletResponse res)
                throws ServletException, IOException {
            String ip       = d(req.getParameter("ip"));
            String attempts = d(req.getParameter("attempts"));
            String since    = d(req.getParameter("since"));
            String time     = now();
            res.setContentType("text/html;charset=UTF-8");
            res.getWriter().write(buildDoomedPage(
                "BRUTE",
                "#ff8c00", "rgba(255,140,0,0.12)", "rgba(255,140,0,0.4)",
                "🔨",
                "BRUTE FORCE DETECTED",
                "YOU TRIED BRUTE FORCE",
                "Your repeated login attempts were tracked per IP address. You exceeded the threshold and your IP has been permanently flagged in our database.",
                new String[][]{
                    {"ATTACK TYPE",    "Brute Force"},
                    {"YOUR IP",        ip},
                    {"FAILED ATTEMPTS","<span style='color:#ff8c00'>" + e(attempts) + " / " + DetectionFilter.BRUTE_THRESHOLD + "</span> — Threshold exceeded"},
                    {"FIRST ATTEMPT",  e(since)},
                    {"FLAGGED AT",     time},
                    {"STATUS",         "<span style='color:#ff8c00;animation:blink 1s infinite'>● IP FLAGGED · COUNTER PRESERVED · LOCKED</span>"}
                },
                "HOW WE CAUGHT YOU",
                "Every failed login from every IP address is tracked in a <strong style='color:#ffab40'>ConcurrentHashMap</strong>. " +
                "Your IP <em style='color:#ffab40'>(" + e(ip) + ")</em> exceeded <strong>" +
                DetectionFilter.BRUTE_THRESHOLD + " failed attempts</strong>. " +
                "Your counter persists in memory — reconnecting changes nothing."
            ));
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  PAGE 4 — SESSION HIJACK
    // ══════════════════════════════════════════════════════════════════════
    public static class HijackServlet extends HttpServlet {
        @Override protected void doGet(HttpServletRequest req, HttpServletResponse res)
                throws ServletException, IOException {
            String ip    = d(req.getParameter("ip"));
            String token = d(req.getParameter("token"));
            String time  = now();
            res.setContentType("text/html;charset=UTF-8");
            res.getWriter().write(buildDoomedPage(
                "HIJACK",
                "#b026ff", "rgba(176,38,255,0.12)", "rgba(176,38,255,0.4)",
                "👻",
                "SESSION HIJACKING DETECTED",
                "YOU TRIED SESSION HIJACKING",
                "A tampered or forged SUSLURE_TOKEN cookie was detected in your request. You attempted to impersonate another user's authenticated session.",
                new String[][]{
                    {"ATTACK TYPE",    "Session Hijacking"},
                    {"YOUR IP",        ip},
                    {"FORGED TOKEN",   "<code style='color:#d06bff;background:rgba(176,38,255,0.1);padding:3px 10px;font-family:Share Tech Mono,monospace;border:1px solid rgba(176,38,255,0.3);word-break:break-all'>" + e(token) + "</code>"},
                    {"EXPECTED",       "A valid SUSLURE_TOKEN issued by this server"},
                    {"DETECTED AT",    time},
                    {"STATUS",         "<span style='color:#b026ff;animation:blink 1s infinite'>● TOKEN INVALIDATED · SESSION KILLED · LOGGED</span>"}
                },
                "HOW WE CAUGHT YOU",
                "Every visitor receives a unique <strong style='color:#c77dff'>SUSLURE_TOKEN</strong> cookie, registered server-side. " +
                "When you submitted the form, your cookie <em style='color:#c77dff'>\"" + e(token.length() > 40 ? token.substring(0,40)+"..." : token) + "\"</em> " +
                "was checked against our <strong>valid token registry</strong>. It was not issued by this server."
            ));
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  SHARED DOOMED PAGE BUILDER — Green/Black SUSLURE theme
    // ══════════════════════════════════════════════════════════════════════
    private static String buildDoomedPage(
            String type, String accent, String accentBg, String accentBorder,
            String icon, String eyebrow, String heading, String subtitle,
            String[][] details, String explainTitle, String explainText) {

        StringBuilder rows = new StringBuilder();
        for (String[] row : details) {
            rows.append("<tr>")
                .append("<td class='dl'>").append(row[0]).append("</td>")
                .append("<td class='dv'>").append(row[1]).append("</td>")
                .append("</tr>");
        }

        return "<!DOCTYPE html>\n<html lang='en'>\n<head>\n" +
"<meta charset='UTF-8'/><meta name='viewport' content='width=device-width,initial-scale=1'/>\n" +
"<title>SUSLURE — Security Alert</title>\n" +
"<style>\n" +
"@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&family=Rajdhani:wght@400;600;700&display=swap');\n" +
"*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n" +
"body{background:#000;font-family:'Rajdhani',sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:flex-start;padding:40px 20px 60px;overflow-x:hidden;position:relative}\n" +
"body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,70,0.012) 2px,rgba(0,255,70,0.012) 3px);pointer-events:none;z-index:9999}\n" +
".grid{position:fixed;inset:0;background-image:linear-gradient(rgba(0,255,70,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,70,0.03) 1px,transparent 1px);background-size:44px 44px;pointer-events:none;opacity:.5}\n" +
".bg-glow{position:fixed;width:800px;height:800px;background:radial-gradient(circle," + accentBg + " 0%,transparent 60%);top:50%;left:50%;transform:translate(-50%,-50%);pointer-events:none;animation:gp 5s ease-in-out infinite}\n" +
"@keyframes gp{0%,100%{transform:translate(-50%,-50%) scale(1);opacity:.5}50%{transform:translate(-50%,-50%) scale(1.1);opacity:.9}}\n" +
// green corner glow
".gl{position:fixed;bottom:0;left:0;width:300px;height:300px;background:radial-gradient(circle,rgba(0,255,70,0.06),transparent 70%);pointer-events:none}\n" +
".gr{position:fixed;top:0;right:0;width:300px;height:300px;background:radial-gradient(circle,rgba(0,255,70,0.06),transparent 70%);pointer-events:none}\n" +
".wrap{width:100%;max-width:740px;z-index:1;animation:fadeIn .5s ease}\n" +
"@keyframes fadeIn{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}\n" +
// top suslure brand
".brand{font-family:'Share Tech Mono',monospace;font-size:10px;color:rgba(0,255,70,0.35);letter-spacing:4px;text-align:right;margin-bottom:28px;text-transform:uppercase}\n" +
".brand span{color:rgba(0,255,70,0.6)}\n" +
".eyebrow{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:5px;color:" + accent + ";background:" + accentBg + ";border:1px solid " + accentBorder + ";padding:7px 18px;display:inline-block;margin-bottom:20px;text-transform:uppercase;animation:fadeIn .4s .1s ease both}\n" +
".icon{font-size:70px;display:block;margin:10px 0 16px;animation:iconFloat 3s ease-in-out infinite}\n" +
"@keyframes iconFloat{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-8px) scale(1.05)}}\n" +
"h1{font-family:'Orbitron',sans-serif;font-size:clamp(28px,5.5vw,56px);font-weight:900;color:" + accent + ";text-shadow:0 0 40px " + accent + ",0 0 80px " + accentBg + ";letter-spacing:-1px;line-height:1.05;margin-bottom:14px;animation:glitch 4s infinite}\n" +
"@keyframes glitch{0%,88%,100%{text-shadow:0 0 40px " + accent + ",0 0 80px " + accentBg + "}" +
  "89%{text-shadow:-3px 0 #0f0,3px 0 " + accent + ",0 0 40px " + accent + "}" +
  "91%{text-shadow:3px 0 #0f0,-3px 0 " + accent + ",0 0 40px " + accent + "}" +
  "93%{text-shadow:0 0 40px " + accent + "}}\n" +
".subtitle{font-size:15px;color:rgba(200,220,200,0.6);max-width:560px;line-height:1.75;margin-bottom:36px;font-weight:500}\n" +
// detail card
".dcard{background:rgba(0,5,1,0.7);border:1px solid " + accentBorder + ";margin-bottom:22px;overflow:hidden}\n" +
".dcard table{width:100%;border-collapse:collapse}\n" +
".dl{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:" + accent + ";padding:12px 18px;width:160px;border-bottom:1px solid rgba(255,255,255,0.04);vertical-align:top;background:rgba(0,0,0,0.4);text-transform:uppercase;white-space:nowrap}\n" +
".dv{font-size:13.5px;color:rgba(200,225,200,0.85);padding:12px 18px;border-bottom:1px solid rgba(255,255,255,0.04);vertical-align:middle;line-height:1.5;font-family:'Rajdhani',sans-serif;font-weight:500}\n" +
// explain
".explain{background:" + accentBg + ";border:1px solid " + accentBorder + ";border-left:3px solid " + accent + ";padding:20px 24px;margin-bottom:24px}\n" +
".expl-title{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:3px;color:" + accent + ";margin-bottom:10px;text-transform:uppercase}\n" +
".explain p{font-size:13.5px;color:rgba(200,225,200,0.75);line-height:1.75;font-weight:500}\n" +
// buttons
".btns{display:flex;gap:12px;flex-wrap:wrap;margin-top:4px}\n" +
".btn{display:inline-flex;align-items:center;gap:8px;background:transparent;border:1px solid;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;padding:11px 20px;text-decoration:none;transition:all .2s;cursor:pointer;text-transform:uppercase}\n" +
".btn-back{color:rgba(0,255,70,0.7);border-color:rgba(0,255,70,0.3)}\n" +
".btn-back:hover{color:#00ff46;border-color:rgba(0,255,70,0.7);background:rgba(0,255,70,0.06);box-shadow:0 0 20px rgba(0,255,70,0.15)}\n" +
".btn-admin{color:" + accent + ";border-color:" + accentBorder + "}\n" +
".btn-admin:hover{color:#fff;border-color:" + accent + ";background:" + accentBg + ";box-shadow:0 0 20px " + accentBg + "}\n" +
// blink
"@keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}\n" +
// bottom suslure tag
".tag{font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.15);letter-spacing:3px;text-align:center;margin-top:32px}\n" +
"</style></head><body>\n" +
"<div class='grid'></div>\n" +
"<div class='bg-glow'></div>\n" +
"<div class='gl'></div><div class='gr'></div>\n" +
"<div class='wrap'>\n" +
"  <div class='brand'>◈ <span>SUSLURE</span> SECURITY SYSTEM · THREAT DETECTED</div>\n" +
"  <div class='eyebrow'>⚠ ALERT — INTRUSION DETECTED — HONEYPOT ACTIVATED</div>\n" +
"  <span class='icon'>" + icon + "</span>\n" +
"  <div class='eyebrow' style='letter-spacing:2px;font-size:11px'>" + eyebrow + "</div>\n" +
"  <h1>" + heading + "</h1>\n" +
"  <p class='subtitle'>" + subtitle + "</p>\n" +
"  <div class='dcard'><table>" + rows + "</table></div>\n" +
"  <div class='explain'>\n" +
"    <div class='expl-title'>◈ " + explainTitle + "</div>\n" +
"    <p>" + explainText + "</p>\n" +
"  </div>\n" +
"  <div class='btns'>\n" +
"    <a href='/login' class='btn btn-back'>← RETURN TO PORTAL</a>\n" +
"    <a href='/admin' class='btn btn-admin'>📊 ADMIN DASHBOARD</a>\n" +
"  </div>\n" +
"  <div class='tag'>SUSLURE v1.0 · DETECT · TRAP · EXPOSE · DESTROY</div>\n" +
"</div></body></html>";
    }

    private static String d(String s) {
        if (s == null) return "Unknown";
        try { return URLDecoder.decode(s, StandardCharsets.UTF_8); }
        catch (Exception e) { return s; }
    }

    private static String e(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");
    }

    private static String now() {
        return java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
}
