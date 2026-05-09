package com.suslure;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;

/**
 * LoginServlet — SUSLURE fake login portal.
 * GET  → serves the beautiful green/black hacker-themed login page + issues token
 * POST → always denies, increments brute counter, logs attempt
 */
public class LoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        // Issue session token on first visit
        String existing = SessionManager.extractToken(req);
        if (existing == null || !SessionManager.isValidToken(existing)) {
            SessionManager.issueToken(res);
        }
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

        // Log normal failed attempt
        int id = DatabaseManager.logAndGetId(ip,
                req.getParameter("username"),
                req.getParameter("password"),
                IntrusionRecord.TYPE_NORMAL, null,
                req.getHeader("User-Agent"),
                SessionManager.extractToken(req));
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
        String errHtml = error == null ? "" :
            "<div class='msg err'><span class='msg-ic'>✕</span><span>" + esc(error) + "</span></div>";
        String warnHtml = warning == null ? "" :
            "<div class='msg warn'><span class='msg-ic'>⚠</span><span>" + esc(warning) + "</span></div>";

        return "<!DOCTYPE html>\n<html lang='en'>\n<head>\n" +
"<meta charset='UTF-8'/>\n" +
"<meta name='viewport' content='width=device-width,initial-scale=1'/>\n" +
"<title>SUSLURE — Secure Access Portal</title>\n" +
"<style>\n" +
"@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@400;500;600;700&display=swap');\n" +
"*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n" +
"body{background:#000;font-family:'Rajdhani',sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;overflow:hidden;position:relative}\n" +

// scanlines
"body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,70,0.015) 2px,rgba(0,255,70,0.015) 3px);pointer-events:none;z-index:9999}\n" +

// grid
".grid{position:fixed;inset:0;background-image:linear-gradient(rgba(0,255,70,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,70,0.04) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;animation:gridPulse 6s ease-in-out infinite}\n" +
"@keyframes gridPulse{0%,100%{opacity:.4}50%{opacity:.8}}\n" +

// orbs
".orb{position:fixed;border-radius:50%;pointer-events:none;filter:blur(90px)}\n" +
".o1{width:500px;height:500px;background:radial-gradient(circle,rgba(0,255,70,0.09),transparent 70%);top:-80px;left:-80px;animation:f1 14s ease-in-out infinite}\n" +
".o2{width:400px;height:400px;background:radial-gradient(circle,rgba(0,200,60,0.07),transparent 70%);bottom:-60px;right:-60px;animation:f2 11s ease-in-out infinite}\n" +
".o3{width:250px;height:250px;background:radial-gradient(circle,rgba(0,255,100,0.05),transparent 70%);top:50%;right:15%;animation:f3 9s ease-in-out infinite}\n" +
"@keyframes f1{0%,100%{transform:translate(0,0)}50%{transform:translate(40px,30px)}}\n" +
"@keyframes f2{0%,100%{transform:translate(0,0)}50%{transform:translate(-30px,-20px)}}\n" +
"@keyframes f3{0%,100%{transform:translate(0,-50%)}50%{transform:translate(15px,-50%)}}\n" +

// card
".card{width:100%;max-width:440px;background:rgba(0,10,3,0.82);border:1px solid rgba(0,255,70,0.25);border-radius:4px;padding:48px 42px 40px;backdrop-filter:blur(24px);box-shadow:0 0 60px rgba(0,255,70,0.08),0 30px 80px rgba(0,0,0,0.7),inset 0 1px 0 rgba(0,255,70,0.1);position:relative;z-index:1;animation:cardIn .7s cubic-bezier(.22,.61,.36,1) both}\n" +
"@keyframes cardIn{from{opacity:0;transform:translateY(32px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}\n" +
".card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,255,70,0.6),transparent)}\n" +

// logo
".logo{display:flex;flex-direction:column;align-items:center;margin-bottom:36px}\n" +
".logo-hex{width:60px;height:60px;background:linear-gradient(135deg,rgba(0,255,70,0.12),rgba(0,200,50,0.06));border:1px solid rgba(0,255,70,0.4);border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:26px;margin-bottom:18px;position:relative;box-shadow:0 0 30px rgba(0,255,70,0.2);animation:logoPulse 3s ease-in-out infinite}\n" +
"@keyframes logoPulse{0%,100%{box-shadow:0 0 30px rgba(0,255,70,0.2)}50%{box-shadow:0 0 50px rgba(0,255,70,0.4),0 0 80px rgba(0,255,70,0.1)}}\n" +
"h1{font-family:'Orbitron',sans-serif;font-size:26px;font-weight:900;color:#00ff46;letter-spacing:6px;text-shadow:0 0 20px rgba(0,255,70,0.5);text-align:center}\n" +
".sub{font-family:'Share Tech Mono',monospace;font-size:10px;color:rgba(0,255,70,0.4);letter-spacing:3px;text-align:center;margin-top:6px;text-transform:uppercase}\n" +

// label
".lbl{display:block;font-family:'Share Tech Mono',monospace;font-size:10px;font-weight:600;color:rgba(0,255,70,0.55);letter-spacing:3px;margin-bottom:8px;text-transform:uppercase}\n" +

// field wrapper
".fg{margin-bottom:18px}\n" +
".fw{position:relative;display:flex;align-items:center;background:rgba(0,255,70,0.04);border:1px solid rgba(0,255,70,0.18);transition:border-color .25s,box-shadow .25s}\n" +
".fw:focus-within{border-color:rgba(0,255,70,0.65);box-shadow:0 0 0 3px rgba(0,255,70,0.1),0 0 20px rgba(0,255,70,0.08)}\n" +
".fi{position:absolute;left:14px;font-size:14px;pointer-events:none;opacity:.4;color:#00ff46}\n" +
".fw input{width:100%;background:transparent;border:none;outline:none;color:#00ff46;font-family:'Share Tech Mono',monospace;font-size:14px;padding:14px 14px 14px 44px;letter-spacing:1px}\n" +
".fw input::placeholder{color:rgba(0,255,70,0.25);font-size:13px}\n" +
".fw input:-webkit-autofill{-webkit-box-shadow:0 0 0 1000px #000a03 inset;-webkit-text-fill-color:#00ff46}\n" +

// options row
".opts{display:flex;align-items:center;justify-content:space-between;margin-bottom:26px}\n" +
".chk{display:flex;align-items:center;gap:8px;font-family:'Share Tech Mono',monospace;font-size:11px;color:rgba(0,255,70,0.5);cursor:pointer;letter-spacing:1px}\n" +
".chk input{accent-color:#00ff46;width:14px;height:14px}\n" +
".fgt{font-family:'Share Tech Mono',monospace;font-size:11px;color:rgba(0,255,70,0.4);text-decoration:none;letter-spacing:1px;transition:color .2s}\n" +
".fgt:hover{color:#00ff46}\n" +

// button
".btn{width:100%;background:transparent;border:1px solid rgba(0,255,70,0.5);color:#00ff46;font-family:'Orbitron',sans-serif;font-size:13px;font-weight:700;padding:15px;cursor:pointer;letter-spacing:3px;text-transform:uppercase;position:relative;overflow:hidden;transition:all .3s}\n" +
".btn::before{content:'';position:absolute;inset:0;background:rgba(0,255,70,0);transition:background .3s}\n" +
".btn:hover{border-color:#00ff46;box-shadow:0 0 30px rgba(0,255,70,0.3),inset 0 0 30px rgba(0,255,70,0.05);color:#fff}\n" +
".btn:hover::before{background:rgba(0,255,70,0.08)}\n" +
".btn:active{transform:scale(.98)}\n" +

// messages
".msg{display:flex;align-items:center;gap:10px;padding:11px 14px;border-left:2px solid;font-family:'Share Tech Mono',monospace;font-size:12px;margin-bottom:14px;letter-spacing:.5px;animation:msgIn .3s ease}\n" +
"@keyframes msgIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}\n" +
".msg-ic{font-size:14px;flex-shrink:0}\n" +
".err{background:rgba(255,40,40,0.07);border-color:rgba(255,40,40,0.5);color:#ff6b6b}\n" +
".warn{background:rgba(255,180,0,0.07);border-color:rgba(255,180,0,0.45);color:#ffd166}\n" +

// divider
".div{display:flex;align-items:center;gap:12px;margin:24px 0}\n" +
".dl{flex:1;height:1px;background:rgba(0,255,70,0.1)}\n" +
".dt{font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.25);letter-spacing:3px}\n" +

// footer
".foot{text-align:center;font-family:'Share Tech Mono',monospace;font-size:9px;color:rgba(0,255,70,0.2);letter-spacing:3px;margin-top:8px}\n" +

// corner decorations
".corner{position:absolute;width:12px;height:12px;border-color:rgba(0,255,70,0.5);border-style:solid}\n" +
".tl{top:8px;left:8px;border-width:1px 0 0 1px}\n" +
".tr{top:8px;right:8px;border-width:1px 1px 0 0}\n" +
".bl{bottom:8px;left:8px;border-width:0 0 1px 1px}\n" +
".br{bottom:8px;right:8px;border-width:0 1px 1px 0}\n" +
"</style>\n" +
"</head>\n<body>\n" +
"<div class='grid'></div>\n" +
"<div class='orb o1'></div>\n" +
"<div class='orb o2'></div>\n" +
"<div class='orb o3'></div>\n" +
"<div class='card'>\n" +
"  <div class='corner tl'></div><div class='corner tr'></div>\n" +
"  <div class='corner bl'></div><div class='corner br'></div>\n" +
"  <div class='logo'>\n" +
"    <div class='logo-hex'>🍯</div>\n" +
"    <h1>SUSLURE</h1>\n" +
"    <p class='sub'>Secure Access Portal — Authorized Only</p>\n" +
"  </div>\n" +
errHtml + warnHtml +
"  <form method='POST' action='/login' autocomplete='off'>\n" +
"    <div class='fg'>\n" +
"      <label class='lbl'>Username</label>\n" +
"      <div class='fw'><span class='fi'>▶</span>\n" +
"        <input type='text' name='username' placeholder='Enter username...' required/>\n" +
"      </div>\n" +
"    </div>\n" +
"    <div class='fg'>\n" +
"      <label class='lbl'>Password</label>\n" +
"      <div class='fw'><span class='fi'>🔑</span>\n" +
"        <input type='password' name='password' placeholder='Enter password...' required/>\n" +
"      </div>\n" +
"    </div>\n" +
"    <div class='opts'>\n" +
"      <label class='chk'><input type='checkbox' name='remember'/> REMEMBER ME</label>\n" +
"      <a href='#' class='fgt'>FORGOT ACCESS?</a>\n" +
"    </div>\n" +
"    <button type='submit' class='btn'>[ AUTHENTICATE ]</button>\n" +
"  </form>\n" +
"  <div class='div'><div class='dl'></div><span class='dt'>SUSLURE v1.0</span><div class='dl'></div></div>\n" +
"  <p class='foot'>ALL ACTIVITY MONITORED · UNAUTHORIZED ACCESS PROHIBITED</p>\n" +
"</div>\n" +
"</body></html>";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;");
    }
}
