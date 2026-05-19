package com.suslure;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;

public class LoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        String existing = SessionManager.extractToken(req);
        if (existing == null || !SessionManager.isValidToken(existing))
            SessionManager.issueToken(res);
        res.setContentType("text/html;charset=UTF-8");
        res.getWriter().write(html(null, null));
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        String ip = clientIP(req);
        DetectionFilter.registerFailedAttempt(ip);

        int attempts  = DetectionFilter.getAllAttempts().getOrDefault(ip, 1);
        int remaining = DetectionFilter.BRUTE_THRESHOLD - attempts;

        // Extract UA profile (same as DetectionFilter does for attacks)
        String ua = req.getHeader("User-Agent");
        AttackerProfiler.UAInfo uaInfo = AttackerProfiler.parseUA(ua);
        String headers = AttackerProfiler.dumpHeaders(req);

        int id = DatabaseManager.logAndGetId(ip,
                req.getParameter("username"),
                req.getParameter("password"),
                IntrusionRecord.TYPE_NORMAL, null,
                ua, SessionManager.extractToken(req),
                uaInfo.os, uaInfo.browser, uaInfo.deviceType, uaInfo.attackTool, headers);
        NetworkScanner.enrichAsync(ip, id);

        res.setContentType("text/html;charset=UTF-8");
        res.getWriter().write(html(
            "Invalid credentials. Access denied.",
            remaining > 0
                ? remaining + " attempt(s) remaining before permanent lockout."
                : "⚠ Final warning — next attempt triggers full lockdown."
        ));
    }

    private static String clientIP(HttpServletRequest req) {
        String xf = req.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) return xf.split(",")[0].trim();
        return req.getRemoteAddr();
    }

    private static String html(String error, String warning) {
        String errHtml  = error   == null ? "" : "<div class='msg err'><span class='msg-ic'>&#10005;</span><span>" + esc(error)   + "</span></div>";
        String warnHtml = warning == null ? "" : "<div class='msg warn'><span class='msg-ic'>&#9888;</span><span>" + esc(warning) + "</span></div>";
        return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'/><meta name='viewport' content='width=device-width,initial-scale=1'/><title>SUSLURE &#8212; Secure Access Portal</title><style>"
            + "@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@400;500;600;700&display=swap');"
            + "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}"
            + "body{background:#000;font-family:'Rajdhani',sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;overflow:hidden;position:relative}"
            + "body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,70,0.015) 2px,rgba(0,255,70,0.015) 3px);pointer-events:none;z-index:9999}"
            + ".grid{position:fixed;inset:0;background-image:linear-gradient(rgba(0,255,70,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,70,0.04) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}"
            + ".card{width:100%;max-width:440px;background:rgba(0,10,3,0.82);border:1px solid rgba(0,255,70,0.25);border-radius:4px;padding:48px 42px 40px;backdrop-filter:blur(24px);box-shadow:0 0 60px rgba(0,255,70,0.08),inset 0 1px 0 rgba(0,255,70,0.1);position:relative;z-index:1}"
            + ".logo{display:flex;flex-direction:column;align-items:center;margin-bottom:36px}"
            + ".logo-hex{width:60px;height:60px;background:rgba(0,255,70,0.08);border:1px solid rgba(0,255,70,0.4);border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:26px;margin-bottom:18px}"
            + "h1{font-family:'Orbitron',sans-serif;font-size:26px;font-weight:900;color:#00ff46;letter-spacing:6px;text-shadow:0 0 20px rgba(0,255,70,0.5);text-align:center}"
            + ".sub{font-family:'Share Tech Mono',monospace;font-size:10px;color:rgba(0,255,70,0.4);letter-spacing:3px;text-align:center;margin-top:6px}"
            + ".lbl{display:block;font-family:'Share Tech Mono',monospace;font-size:10px;color:rgba(0,255,70,0.55);letter-spacing:3px;margin-bottom:8px}"
            + ".fg{margin-bottom:18px}.fw{position:relative;display:flex;align-items:center;background:rgba(0,255,70,0.04);border:1px solid rgba(0,255,70,0.18);transition:border-color .25s}"
            + ".fw:focus-within{border-color:rgba(0,255,70,0.65);box-shadow:0 0 0 3px rgba(0,255,70,0.1)}"
            + ".fi{position:absolute;left:14px;font-size:14px;pointer-events:none;opacity:.4;color:#00ff46}"
            + ".fw input{width:100%;background:transparent;border:none;outline:none;color:#00ff46;font-family:'Share Tech Mono',monospace;font-size:14px;padding:14px 14px 14px 44px}"
            + ".fw input::placeholder{color:rgba(0,255,70,0.25)}"
            + ".btn{width:100%;background:transparent;border:1px solid rgba(0,255,70,0.5);color:#00ff46;font-family:'Orbitron',sans-serif;font-size:13px;font-weight:700;padding:15px;cursor:pointer;letter-spacing:3px;text-transform:uppercase;transition:all .3s}"
            + ".btn:hover{border-color:#00ff46;box-shadow:0 0 30px rgba(0,255,70,0.3)}"
            + ".msg{display:flex;align-items:center;gap:10px;padding:11px 14px;border-left:2px solid;font-family:'Share Tech Mono',monospace;font-size:12px;margin-bottom:14px}"
            + ".err{background:rgba(255,40,40,0.07);border-color:rgba(255,40,40,0.5);color:#ff6b6b}"
            + ".warn{background:rgba(255,180,0,0.07);border-color:rgba(255,180,0,0.45);color:#ffd166}"
            + ".corner{position:absolute;width:12px;height:12px;border-color:rgba(0,255,70,0.5);border-style:solid}"
            + ".tl{top:8px;left:8px;border-width:1px 0 0 1px}.tr{top:8px;right:8px;border-width:1px 1px 0 0}"
            + ".bl{bottom:8px;left:8px;border-width:0 0 1px 1px}.br{bottom:8px;right:8px;border-width:0 1px 1px 0}"
            + ".foot{text-align:center;font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.2);letter-spacing:3px;margin-top:20px}"
            + "</style></head><body>"
            + "<div class='grid'></div>"
            + "<div class='card'>"
            + "<div class='corner tl'></div><div class='corner tr'></div>"
            + "<div class='corner bl'></div><div class='corner br'></div>"
            + "<div class='logo'><div class='logo-hex'>&#127855;</div>"
            + "<h1>SUSLURE</h1><p class='sub'>Secure Access Portal &#8212; Authorized Only</p></div>"
            + errHtml + warnHtml
            + "<form method='POST' action='/login' autocomplete='off'>"
            + "<div class='fg'><label class='lbl'>Username</label>"
            + "<div class='fw'><span class='fi'>&#9654;</span>"
            + "<input type='text' name='username' placeholder='Enter username...' required/></div></div>"
            + "<div class='fg'><label class='lbl'>Password</label>"
            + "<div class='fw'><span class='fi'>&#128273;</span>"
            + "<input type='password' name='password' placeholder='Enter password...' required/></div></div>"
            + "<button type='submit' class='btn'>[ AUTHENTICATE ]</button>"
            + "</form>"
            + "<p class='foot'>ALL ACTIVITY MONITORED &#183; UNAUTHORIZED ACCESS PROHIBITED</p>"
            + "</div></body></html>";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;");
    }
}
