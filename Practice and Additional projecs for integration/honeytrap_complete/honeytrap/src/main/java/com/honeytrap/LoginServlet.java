package com.honeytrap;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

/**
 * LoginServlet — Serves the fake login portal.
 * GET  /login → shows the login HTML page, issues a session token
 * POST /login → always denies, increments brute-force counter
 * (The DetectionFilter runs BEFORE this on POST requests)
 */
public class LoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        // Issue a session token cookie on first visit
        String existing = SessionManager.extractToken(req);
        if (existing == null || !SessionManager.isValidToken(existing)) {
            SessionManager.issueToken(res);
        }
        res.setContentType("text/html;charset=UTF-8");
        res.getWriter().write(buildLoginPage());
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {

        String ip = req.getRemoteAddr();
        String xf = req.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) ip = xf.split(",")[0].trim();

        // Always deny — register failed attempt for brute-force tracking
        DetectionFilter.registerFailedAttempt(ip);

        int attempts = DetectionFilter.getAllAttempts().getOrDefault(ip, 1);
        int remaining = DetectionFilter.BRUTE_THRESHOLD - attempts;

        // Log the normal (non-attack) attempt
        DatabaseManager.logIntrusion(ip,
            req.getParameter("username"),
            req.getParameter("password"),
            IntrusionRecord.TYPE_NORMAL, null,
            req.getHeader("User-Agent"),
            SessionManager.extractToken(req));

        res.setContentType("text/html;charset=UTF-8");
        res.getWriter().write(buildLoginPage(
            "Invalid credentials. Access denied.",
            remaining > 0 ? remaining + " attempt(s) remaining before lockout." : null
        ));
    }

    // ── HTML Builder ──────────────────────────────────────────────────────

    private String buildLoginPage() {
        return buildLoginPage(null, null);
    }

    private String buildLoginPage(String error, String warning) {
        String errorHtml = "";
        if (error != null) {
            errorHtml = "<div class='msg msg-error'><span class='msg-icon'>✕</span>" + esc(error) + "</div>";
        }
        String warnHtml = "";
        if (warning != null) {
            warnHtml = "<div class='msg msg-warn'><span class='msg-icon'>⚠</span>" + esc(warning) + "</div>";
        }

        return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Secure Enterprise Portal — Login</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{background:#060912;font-family:'Inter',sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;position:relative;overflow:hidden}
  body::before{content:'';position:fixed;inset:0;background:linear-gradient(135deg,#060912 0%,#080d1a 50%,#060912 100%);z-index:-2}
  .orb{position:fixed;border-radius:50%;pointer-events:none;z-index:-1;filter:blur(80px)}
  .orb1{width:500px;height:500px;background:radial-gradient(circle,rgba(99,102,241,0.15),transparent 70%);top:-100px;left:-100px;animation:float1 12s ease-in-out infinite}
  .orb2{width:400px;height:400px;background:radial-gradient(circle,rgba(168,85,247,0.12),transparent 70%);bottom:-80px;right:-80px;animation:float2 10s ease-in-out infinite}
  @keyframes float1{0%,100%{transform:translate(0,0)}50%{transform:translate(30px,20px)}}
  @keyframes float2{0%,100%{transform:translate(0,0)}50%{transform:translate(-25px,-15px)}}
  .grid-bg{position:fixed;inset:0;background-image:linear-gradient(rgba(99,102,241,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(99,102,241,0.04) 1px,transparent 1px);background-size:44px 44px;z-index:-1}
  .card{width:100%;max-width:420px;background:rgba(12,16,30,0.8);border:1px solid rgba(99,102,241,0.2);border-radius:20px;padding:44px 40px;backdrop-filter:blur(20px);box-shadow:0 25px 80px rgba(0,0,0,0.6),0 0 0 1px rgba(255,255,255,0.04);animation:cardIn .6s ease both}
  @keyframes cardIn{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
  .logo-wrap{display:flex;flex-direction:column;align-items:center;margin-bottom:32px}
  .logo-hex{width:56px;height:56px;background:linear-gradient(135deg,rgba(99,102,241,0.2),rgba(168,85,247,0.15));border:1px solid rgba(139,92,246,0.45);border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:24px;margin-bottom:16px;box-shadow:0 0 30px rgba(124,58,237,0.25)}
  h1{font-size:22px;font-weight:700;color:#f0f4ff;letter-spacing:-0.5px;text-align:center}
  .sub{font-size:13.5px;color:#5c6480;text-align:center;margin-top:5px;font-weight:400}
  .field-group{margin-bottom:16px}
  .field-label{display:block;font-size:12px;font-weight:600;color:#7b85a8;letter-spacing:0.5px;margin-bottom:7px;text-transform:uppercase}
  .field-wrap{position:relative;display:flex;align-items:center;background:rgba(255,255,255,0.04);border:1.5px solid rgba(255,255,255,0.09);border-radius:10px;transition:border-color .2s,box-shadow .2s}
  .field-wrap:focus-within{border-color:rgba(139,92,246,0.7);box-shadow:0 0 0 3px rgba(124,58,237,0.15)}
  .field-icon{position:absolute;left:14px;font-size:15px;pointer-events:none;opacity:0.45}
  .field-wrap input{width:100%;background:transparent;border:none;outline:none;color:#e8ecf8;font-size:14.5px;font-family:inherit;padding:13px 14px 13px 42px}
  .field-wrap input::placeholder{color:rgba(120,130,160,0.5)}
  .options-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;margin-top:4px}
  .remember{display:flex;align-items:center;gap:8px;font-size:13px;color:#7b85a8;cursor:pointer;user-select:none}
  .remember input[type=checkbox]{width:16px;height:16px;accent-color:#7c3aed;cursor:pointer}
  .forgot{font-size:13px;color:#8b5cf6;text-decoration:none;transition:color .2s}
  .forgot:hover{color:#a78bfa}
  .btn{width:100%;background:linear-gradient(135deg,#6366f1,#8b5cf6,#a855f7);border:none;border-radius:10px;color:#fff;font-size:14.5px;font-weight:600;padding:14px;cursor:pointer;letter-spacing:0.3px;transition:all .2s;box-shadow:0 4px 20px rgba(99,102,241,0.4)}
  .btn:hover{transform:translateY(-1px);box-shadow:0 8px 30px rgba(99,102,241,0.55)}
  .btn:active{transform:translateY(0) scale(0.98)}
  .msg{display:flex;align-items:center;gap:10px;padding:11px 15px;border-radius:8px;font-size:13px;margin-bottom:14px}
  .msg-icon{font-size:14px;flex-shrink:0}
  .msg-error{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#fca5a5}
  .msg-warn{background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);color:#fde68a}
  .divider{display:flex;align-items:center;gap:12px;margin:24px 0}
  .divider-line{flex:1;height:1px;background:rgba(255,255,255,0.07)}
  .divider-text{font-size:11px;color:#3a4055;letter-spacing:2px}
  .footer-note{text-align:center;font-size:12px;color:#2a3045}
  .footer-note span{color:#4a5070}
  .security-badge{display:flex;align-items:center;justify-content:center;gap:6px;font-size:11px;color:#2a3045;margin-top:24px;font-family:monospace;letter-spacing:1px}
</style>
</head>
<body>
<div class="orb orb1"></div>
<div class="orb orb2"></div>
<div class="grid-bg"></div>
<div class="card">
  <div class="logo-wrap">
    <div class="logo-hex">🔒</div>
    <h1>Enterprise Portal</h1>
    <p class="sub">Authorized access only — All activity monitored</p>
  </div>
""" + errorHtml + warnHtml + """
  <form method="POST" action="/login" autocomplete="off">
    <div class="field-group">
      <label class="field-label">Username / Email</label>
      <div class="field-wrap">
        <span class="field-icon">✉</span>
        <input type="text" name="username" placeholder="Enter your username" required/>
      </div>
    </div>
    <div class="field-group">
      <label class="field-label">Password</label>
      <div class="field-wrap">
        <span class="field-icon">🔑</span>
        <input type="password" name="password" placeholder="Enter your password" required/>
      </div>
    </div>
    <div class="options-row">
      <label class="remember">
        <input type="checkbox" name="remember"/> Remember me
      </label>
      <a href="#" class="forgot">Forgot password?</a>
    </div>
    <button type="submit" class="btn">Sign In →</button>
  </form>
  <div class="divider">
    <div class="divider-line"></div>
    <span class="divider-text">SECURE</span>
    <div class="divider-line"></div>
  </div>
  <div class="footer-note">Protected by <span>HoneyTrap Security v2.0</span></div>
  <div class="security-badge">🛡 TLS 1.3 &nbsp;·&nbsp; AES-256 &nbsp;·&nbsp; MONITORED</div>
</div>
</body>
</html>
""";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;");
    }
}
