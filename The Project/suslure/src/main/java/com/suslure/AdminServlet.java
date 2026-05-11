package com.suslure;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;
import java.util.List;

/**
 * AdminServlet — SUSLURE Admin Dashboard at /admin.
 * Protected by username: SusLure / password: thats a secret baby
 * GET  /admin → login form OR dashboard (depends on session)
 * POST /admin → handles auth / clear / logout actions
 *
 * FIXES applied vs old broken version:
 *  1. package changed from com.honeytrap → com.suslure
 *  2. removed getSafePayload() call (method does not exist) — use getPayloadUsed() directly
 *  3. removed getSafePayload() on getUserAgent() — use getPayloadUsed() / getUserAgent()
 *  4. admin is now password-protected (was open in old version)
 *  5. all special characters replaced with safe HTML entities (no ? garbage chars)
 *  6. simulate button now requires admin session
 *  7. MAC address column added (from NetworkScanner integration)
 */
public class AdminServlet extends HttpServlet {

    private static final String ADMIN_USER  = "SusLure";
    private static final String ADMIN_PASS  = "thats a secret baby";
    private static final String SESSION_KEY = "suslure_admin_auth";

    // ═══════════════════════════════════════════════════════════════════
    //  GET — show login page OR dashboard
    // ═══════════════════════════════════════════════════════════════════
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {

        res.setContentType("text/html;charset=UTF-8");

        // Check admin session
        HttpSession session = req.getSession(false);
        boolean authed = session != null
                && Boolean.TRUE.equals(session.getAttribute(SESSION_KEY));

        if (!authed) {
            res.getWriter().write(buildAdminLogin(null));
            return;
        }

        // Load data for dashboard
        String filter = req.getParameter("type"); // null = all
        List<IntrusionRecord> records = (filter != null && !filter.isBlank())
                ? DatabaseManager.getByAttackType(filter.toUpperCase())
                : DatabaseManager.getAllRecords();

        int total  = DatabaseManager.getTotalCount();
        int sqli   = DatabaseManager.getCountByType(IntrusionRecord.TYPE_SQLI);
        int brute  = DatabaseManager.getCountByType(IntrusionRecord.TYPE_BRUTE);
        int hijack = DatabaseManager.getCountByType(IntrusionRecord.TYPE_HIJACK);
        int normal = DatabaseManager.getCountByType(IntrusionRecord.TYPE_NORMAL);
        int uniq   = DatabaseManager.getUniqueIpCount();

        res.getWriter().write(
                buildDashboard(records, total, sqli, brute, hijack, normal, uniq, filter));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  POST — handle auth / clear / logout
    // ═══════════════════════════════════════════════════════════════════
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {

        String action = req.getParameter("action");

        // Admin login attempt
        if ("auth".equals(action)) {
            String user = req.getParameter("username");
            String pass = req.getParameter("password");
            if (ADMIN_USER.equals(user) && ADMIN_PASS.equals(pass)) {
                HttpSession session = req.getSession(true);
                session.setAttribute(SESSION_KEY, Boolean.TRUE);
                session.setMaxInactiveInterval(60 * 60); // 1 hour
                res.sendRedirect("/admin");
            } else {
                res.setContentType("text/html;charset=UTF-8");
                res.getWriter().write(buildAdminLogin("Invalid credentials. Try again."));
            }
            return;
        }

        // All other actions require an active admin session
        HttpSession session = req.getSession(false);
        if (session == null || !Boolean.TRUE.equals(session.getAttribute(SESSION_KEY))) {
            res.sendRedirect("/admin");
            return;
        }

        if ("clear".equals(action)) {
            DatabaseManager.clearAll();
        } else if ("logout".equals(action)) {
            session.invalidate();
        }
        res.sendRedirect("/admin");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  ADMIN LOGIN PAGE
    // ═══════════════════════════════════════════════════════════════════
    private String buildAdminLogin(String error) {
        String errHtml = (error == null) ? "" :
                "<div class='msg-err'><span>&#10005;</span> " + esc(error) + "</div>";

        return "<!DOCTYPE html><html lang='en'><head>\n"
                + "<meta charset='UTF-8'/>"
                + "<meta name='viewport' content='width=device-width,initial-scale=1'/>\n"
                + "<title>SUSLURE &mdash; Admin Access</title>\n"
                + "<style>\n"
                + "@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono"
                + "&family=Orbitron:wght@700;900&family=Rajdhani:wght@500;600&display=swap');\n"
                + "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n"
                + "body{background:#000;font-family:'Rajdhani',sans-serif;min-height:100vh;"
                + "display:flex;align-items:center;justify-content:center;"
                + "padding:20px;position:relative;overflow:hidden}\n"
                + "body::before{content:'';position:fixed;inset:0;"
                + "background:repeating-linear-gradient(0deg,transparent,transparent 2px,"
                + "rgba(0,255,70,0.012) 2px,rgba(0,255,70,0.012) 3px);"
                + "pointer-events:none;z-index:9999}\n"
                + ".grid{position:fixed;inset:0;"
                + "background-image:linear-gradient(rgba(0,255,70,0.035) 1px,transparent 1px),"
                + "linear-gradient(90deg,rgba(0,255,70,0.035) 1px,transparent 1px);"
                + "background-size:44px 44px;pointer-events:none}\n"
                + ".glow{position:fixed;width:600px;height:600px;"
                + "background:radial-gradient(circle,rgba(0,255,70,0.06),transparent 60%);"
                + "top:50%;left:50%;transform:translate(-50%,-50%);pointer-events:none}\n"
                + ".card{width:100%;max-width:400px;"
                + "background:rgba(0,8,2,0.88);border:1px solid rgba(0,255,70,0.25);"
                + "padding:44px 40px;position:relative;z-index:1;animation:ci .6s ease;"
                + "box-shadow:0 0 60px rgba(0,255,70,0.06)}\n"
                + "@keyframes ci{from{opacity:0;transform:translateY(20px)}"
                + "to{opacity:1;transform:translateY(0)}}\n"
                + ".card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;"
                + "background:linear-gradient(90deg,transparent,rgba(0,255,70,0.5),transparent)}\n"
                + ".corner{position:absolute;width:10px;height:10px;"
                + "border-color:rgba(0,255,70,0.4);border-style:solid}\n"
                + ".tl{top:6px;left:6px;border-width:1px 0 0 1px}"
                + ".tr{top:6px;right:6px;border-width:1px 1px 0 0}\n"
                + ".bl{bottom:6px;left:6px;border-width:0 0 1px 1px}"
                + ".br{bottom:6px;right:6px;border-width:0 1px 1px 0}\n"
                + "h1{font-family:'Orbitron',sans-serif;font-size:20px;font-weight:900;"
                + "color:#00ff46;letter-spacing:4px;text-align:center;margin-bottom:4px;"
                + "text-shadow:0 0 20px rgba(0,255,70,0.4)}\n"
                + ".sub{font-family:'Share Tech Mono',monospace;font-size:9px;"
                + "color:rgba(0,255,70,0.35);letter-spacing:3px;"
                + "text-align:center;margin-bottom:32px}\n"
                + ".lbl{display:block;font-family:'Share Tech Mono',monospace;font-size:9px;"
                + "color:rgba(0,255,70,0.5);letter-spacing:3px;margin-bottom:7px;"
                + "text-transform:uppercase}\n"
                + ".fg{margin-bottom:16px}\n"
                + ".fw{background:rgba(0,255,70,0.04);border:1px solid rgba(0,255,70,0.18);"
                + "display:flex;align-items:center;transition:border-color .2s,box-shadow .2s}\n"
                + ".fw:focus-within{border-color:rgba(0,255,70,0.6);"
                + "box-shadow:0 0 0 3px rgba(0,255,70,0.1)}\n"
                + ".fw input{width:100%;background:transparent;border:none;outline:none;"
                + "color:#00ff46;font-family:'Share Tech Mono',monospace;"
                + "font-size:13px;padding:13px 16px;letter-spacing:1px}\n"
                + ".fw input::placeholder{color:rgba(0,255,70,0.2)}\n"
                + ".btn{width:100%;background:transparent;"
                + "border:1px solid rgba(0,255,70,0.45);color:#00ff46;"
                + "font-family:'Orbitron',sans-serif;font-size:11px;font-weight:700;"
                + "padding:14px;cursor:pointer;letter-spacing:3px;text-transform:uppercase;"
                + "transition:all .25s;margin-top:8px}\n"
                + ".btn:hover{border-color:#00ff46;background:rgba(0,255,70,0.08);"
                + "box-shadow:0 0 25px rgba(0,255,70,0.2)}\n"
                + ".msg-err{background:rgba(255,40,40,0.08);"
                + "border:1px solid rgba(255,40,40,0.4);border-left:2px solid #ff3b3b;"
                + "color:#ff6b6b;font-family:'Share Tech Mono',monospace;font-size:11px;"
                + "padding:10px 14px;margin-bottom:16px;letter-spacing:.5px;"
                + "display:flex;align-items:center;gap:8px}\n"
                + ".back{display:block;text-align:center;"
                + "font-family:'Share Tech Mono',monospace;font-size:9px;"
                + "color:rgba(0,255,70,0.25);letter-spacing:2px;"
                + "text-decoration:none;margin-top:20px;transition:color .2s}\n"
                + ".back:hover{color:rgba(0,255,70,0.6)}\n"
                + "</style></head><body>\n"
                + "<div class='grid'></div><div class='glow'></div>\n"
                + "<div class='card'>\n"
                + "  <div class='corner tl'></div><div class='corner tr'></div>\n"
                + "  <div class='corner bl'></div><div class='corner br'></div>\n"
                + "  <h1>SUSLURE</h1>\n"
                + "  <p class='sub'>ADMIN ACCESS &middot; AUTHORIZED ONLY</p>\n"
                + errHtml
                + "  <form method='POST' action='/admin'>\n"
                + "    <input type='hidden' name='action' value='auth'/>\n"
                + "    <div class='fg'><label class='lbl'>Admin Username</label>\n"
                + "      <div class='fw'>"
                + "<input type='text' name='username' placeholder='Enter username...' required/>"
                + "</div></div>\n"
                + "    <div class='fg'><label class='lbl'>Admin Password</label>\n"
                + "      <div class='fw'>"
                + "<input type='password' name='password' placeholder='Enter password...' required/>"
                + "</div></div>\n"
                + "    <button type='submit' class='btn'>[ ACCESS DASHBOARD ]</button>\n"
                + "  </form>\n"
                + "  <a href='/login' class='back'>&larr; RETURN TO PORTAL</a>\n"
                + "</div></body></html>";
    }

    // ═══════════════════════════════════════════════════════════════════
    //  MAIN DASHBOARD
    // ═══════════════════════════════════════════════════════════════════
    private String buildDashboard(List<IntrusionRecord> records,
                                  int total, int sqli, int brute,
                                  int hijack, int normal, int uniq,
                                  String filter) {

        StringBuilder rows = new StringBuilder();
        if (records.isEmpty()) {
            rows.append("<tr><td colspan='9' class='empty'>"
                    + "&#9674; No intrusion records yet. Waiting for attackers...</td></tr>");
        } else {
            for (IntrusionRecord r : records) {
                String ac = r.getAccentColor();

                // FIX: safe truncation — no getSafePayload() method exists,
                //      use getPayloadUsed() which already has null safety via safe()
                String pl = r.getPayloadUsed();
                String plDisplay = pl.isEmpty() ? "&mdash;"
                        : (pl.length() > 30 ? esc(pl.substring(0, 30)) + "..." : esc(pl));

                // FIX: safe truncation of user agent — no special method, just string ops
                String ua = r.getUserAgent();
                String uaDisplay = ua.isEmpty() ? "&mdash;"
                        : (ua.length() > 40 ? esc(ua.substring(0, 40)) + "..." : esc(ua));

                // MAC address — may be empty until async enrichment completes
                String mac = r.getMacAddress();
                String macDisplay = mac.isEmpty() ? "<span style='color:rgba(0,255,70,0.2)'>scanning...</span>"
                        : esc(mac);

                rows.append("<tr class='").append(r.getCssClass()).append("'>")
                        .append("<td class='mono dim'>").append(r.getId()).append("</td>")
                        .append("<td><span class='badge' style='color:").append(ac)
                        .append(";border-color:").append(ac).append("55;background:")
                        .append(ac).append("11'>").append(esc(r.getBadge())).append("</span></td>")
                        .append("<td class='mono green'>").append(esc(r.getIpAddress())).append("</td>")
                        .append("<td>").append(esc(r.getUsername())).append("</td>")
                        .append("<td class='dim'>").append(esc(r.getPassword())).append("</td>")
                        .append("<td class='payload' style='color:").append(ac).append("'>")
                        .append(plDisplay).append("</td>")
                        .append("<td class='mono dim ts'>").append(esc(r.getTimestamp())).append("</td>")
                        .append("<td class='mono green2'>").append(macDisplay).append("</td>")
                        .append("<td class='dim ua'>").append(uaDisplay).append("</td>")
                        .append("</tr>");
            }
        }

        String af = (filter != null) ? filter.toUpperCase() : "ALL";

        return "<!DOCTYPE html><html lang='en'><head>\n"
                + "<meta charset='UTF-8'/>"
                + "<meta name='viewport' content='width=device-width,initial-scale=1'/>\n"
                + "<meta http-equiv='refresh' content='15'/>\n"
                + "<title>SUSLURE &mdash; Attack Dashboard</title>\n"
                + "<style>\n"
                + "@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono"
                + "&family=Orbitron:wght@700;900&family=Rajdhani:wght@400;500;600&display=swap');\n"
                + "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n"
                + "body{background:#000;font-family:'Rajdhani',sans-serif;color:#8ab89a;"
                + "min-height:100vh;overflow-x:hidden}\n"
                + "body::before{content:'';position:fixed;inset:0;"
                + "background:repeating-linear-gradient(0deg,transparent,transparent 2px,"
                + "rgba(0,255,70,0.01) 2px,rgba(0,255,70,0.01) 3px);"
                + "pointer-events:none;z-index:9999}\n"
                + ".topbar{background:rgba(0,4,1,0.96);"
                + "border-bottom:1px solid rgba(0,255,70,0.15);padding:0 28px;height:54px;"
                + "display:flex;align-items:center;justify-content:space-between;"
                + "position:sticky;top:0;z-index:100;backdrop-filter:blur(12px)}\n"
                + ".brand{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:900;"
                + "color:#00ff46;letter-spacing:3px;text-shadow:0 0 20px rgba(0,255,70,0.4)}\n"
                + ".brand-sub{font-family:'Share Tech Mono',monospace;font-size:9px;"
                + "color:rgba(0,255,70,0.35);letter-spacing:3px;margin-left:12px}\n"
                + ".topright{display:flex;align-items:center;gap:14px}\n"
                + ".live{display:flex;align-items:center;gap:6px;"
                + "font-family:'Share Tech Mono',monospace;font-size:9px;"
                + "color:#00ff46;letter-spacing:2px}\n"
                + ".dot{width:6px;height:6px;border-radius:50%;background:#00ff46;"
                + "animation:blink 1.5s infinite;box-shadow:0 0 8px #00ff46}\n"
                + "@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}\n"
                + ".page{max-width:1500px;margin:0 auto;padding:28px 22px}\n"
                + ".stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));"
                + "gap:10px;margin-bottom:26px}\n"
                + ".sc{background:rgba(0,5,1,0.8);border:1px solid rgba(0,255,70,0.12);"
                + "padding:18px 16px;transition:border-color .2s,box-shadow .2s;"
                + "position:relative;overflow:hidden}\n"
                + ".sc::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;"
                + "background:linear-gradient(90deg,transparent,currentColor,transparent);opacity:.3}\n"
                + ".sc:hover{border-color:rgba(0,255,70,0.3);box-shadow:0 0 20px rgba(0,255,70,0.05)}\n"
                + ".sn{font-family:'Orbitron',sans-serif;font-size:30px;font-weight:900;"
                + "display:block;line-height:1;margin-bottom:6px}\n"
                + ".sl{font-family:'Share Tech Mono',monospace;font-size:8px;"
                + "letter-spacing:2px;opacity:.5;text-transform:uppercase;display:block}\n"
                + ".sc-t .sn{color:#00ff46;text-shadow:0 0 20px rgba(0,255,70,0.4)}\n"
                + ".sc-s .sn{color:#ff3b3b}.sc-b .sn{color:#ff8c00}\n"
                + ".sc-h .sn{color:#b026ff}.sc-n .sn{color:#00ff88}.sc-i .sn{color:#facc15}\n"
                + ".controls{display:flex;align-items:center;gap:8px;"
                + "margin-bottom:18px;flex-wrap:wrap}\n"
                + ".fb{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;"
                + "padding:7px 12px;border:1px solid rgba(0,255,70,0.15);background:transparent;"
                + "color:rgba(0,255,70,0.4);cursor:pointer;transition:all .2s;"
                + "text-decoration:none;display:inline-block}\n"
                + ".fb:hover,.fb.act{color:#00ff46;border-color:rgba(0,255,70,0.5);"
                + "background:rgba(0,255,70,0.06);box-shadow:0 0 12px rgba(0,255,70,0.08)}\n"
                + ".fb-s.act{color:#ff3b3b;border-color:rgba(255,59,59,0.5);"
                + "background:rgba(255,59,59,0.06)}\n"
                + ".fb-b.act{color:#ff8c00;border-color:rgba(255,140,0,0.5);"
                + "background:rgba(255,140,0,0.06)}\n"
                + ".fb-h.act{color:#b026ff;border-color:rgba(176,38,255,0.5);"
                + "background:rgba(176,38,255,0.06)}\n"
                + ".sp{flex:1}\n"
                + ".ab{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:1px;"
                + "padding:7px 12px;border:1px solid;background:transparent;"
                + "cursor:pointer;transition:all .2s;text-decoration:none;display:inline-block}\n"
                + ".ab-sim{color:rgba(0,255,70,0.7);border-color:rgba(0,255,70,0.25)}\n"
                + ".ab-sim:hover{color:#00ff46;border-color:rgba(0,255,70,0.6);"
                + "box-shadow:0 0 15px rgba(0,255,70,0.12)}\n"
                + ".ab-clr{color:rgba(255,59,59,0.7);border-color:rgba(255,59,59,0.25)}\n"
                + ".ab-clr:hover{color:#ff3b3b;border-color:rgba(255,59,59,0.6);"
                + "box-shadow:0 0 15px rgba(255,59,59,0.1)}\n"
                + ".ab-out{color:rgba(0,255,70,0.4);border-color:rgba(0,255,70,0.15)}\n"
                + ".ab-out:hover{color:rgba(0,255,70,0.7);border-color:rgba(0,255,70,0.4)}\n"
                + ".tw{overflow-x:auto;border:1px solid rgba(0,255,70,0.12)}\n"
                + "table{width:100%;border-collapse:collapse;font-size:13px}\n"
                + "thead th{background:rgba(0,4,1,0.95);color:rgba(0,255,70,0.6);"
                + "font-family:'Share Tech Mono',monospace;font-size:8px;letter-spacing:2px;"
                + "text-transform:uppercase;padding:12px 12px;text-align:left;"
                + "border-bottom:1px solid rgba(0,255,70,0.12);white-space:nowrap}\n"
                + "tbody td{padding:10px 12px;border-bottom:1px solid rgba(0,255,70,0.05);"
                + "vertical-align:middle;max-width:180px;overflow:hidden;"
                + "text-overflow:ellipsis;white-space:nowrap}\n"
                + "tbody tr:hover td{background:rgba(0,255,70,0.025)}\n"
                + ".row-sqli   td:first-child{border-left:2px solid #ff3b3b}\n"
                + ".row-brute  td:first-child{border-left:2px solid #ff8c00}\n"
                + ".row-hijack td:first-child{border-left:2px solid #b026ff}\n"
                + ".row-normal td:first-child{border-left:2px solid #00ff88}\n"
                + ".badge{font-family:'Share Tech Mono',monospace;font-size:9px;"
                + "padding:3px 8px;border:1px solid;white-space:nowrap;letter-spacing:1px}\n"
                + ".mono{font-family:'Share Tech Mono',monospace;font-size:11px}\n"
                + ".green{color:rgba(0,255,70,0.8)}.green2{color:rgba(0,200,70,0.5)}\n"
                + ".dim{color:rgba(100,150,100,0.55)}\n"
                + ".payload{font-family:'Share Tech Mono',monospace;font-size:11px}\n"
                + ".ua{font-size:11px;max-width:200px}\n"
                + ".ts{font-size:10px;color:rgba(0,255,70,0.3)}\n"
                + ".empty{text-align:center;padding:50px;color:rgba(0,255,70,0.2);"
                + "font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:2px}\n"
                + ".rn{font-family:'Share Tech Mono',monospace;font-size:9px;"
                + "color:rgba(0,255,70,0.2);text-align:right;margin-top:8px;letter-spacing:1px}\n"
                + "footer{text-align:center;padding:24px;"
                + "font-family:'Share Tech Mono',monospace;font-size:9px;"
                + "color:rgba(0,255,70,0.15);letter-spacing:3px;"
                + "border-top:1px solid rgba(0,255,70,0.08);margin-top:16px}\n"
                + "</style></head><body>\n"

                + "<div class='topbar'>\n"
                + "  <div><span class='brand'>&#9672; SUSLURE</span>"
                + "<span class='brand-sub'>ATTACK INTELLIGENCE DASHBOARD</span></div>\n"
                + "  <div class='topright'>\n"
                + "    <div class='live'><div class='dot'></div>&nbsp;LIVE</div>\n"
                + "    <form method='POST' action='/admin' style='margin:0'>\n"
                + "      <input type='hidden' name='action' value='logout'/>\n"
                + "      <button type='submit' class='ab ab-out'>LOGOUT</button>\n"
                + "    </form>\n"
                + "  </div>\n"
                + "</div>\n"

                + "<div class='page'>\n"
                + "  <div class='stats'>\n"
                + "    <div class='sc sc-t'><span class='sn'>" + total  + "</span><span class='sl'>Total Attacks</span></div>\n"
                + "    <div class='sc sc-s'><span class='sn'>" + sqli   + "</span><span class='sl'>SQL Injection</span></div>\n"
                + "    <div class='sc sc-b'><span class='sn'>" + brute  + "</span><span class='sl'>Brute Force</span></div>\n"
                + "    <div class='sc sc-h'><span class='sn'>" + hijack + "</span><span class='sl'>Session Hijack</span></div>\n"
                + "    <div class='sc sc-n'><span class='sn'>" + normal + "</span><span class='sl'>Normal</span></div>\n"
                + "    <div class='sc sc-i'><span class='sn'>" + uniq   + "</span><span class='sl'>Unique IPs</span></div>\n"
                + "  </div>\n"

                + "  <div class='controls'>\n"
                + "    <a href='/admin'                     class='fb "
                + ("ALL".equals(af)            ? "act" : "") + "'>ALL</a>\n"
                + "    <a href='/admin?type=SQLI'           class='fb fb-s "
                + ("SQLI".equals(af)           ? "act" : "") + "'>SQLi</a>\n"
                + "    <a href='/admin?type=BRUTE_FORCE'    class='fb fb-b "
                + ("BRUTE_FORCE".equals(af)    ? "act" : "") + "'>BRUTE</a>\n"
                + "    <a href='/admin?type=SESSION_HIJACK' class='fb fb-h "
                + ("SESSION_HIJACK".equals(af) ? "act" : "") + "'>HIJACK</a>\n"
                + "    <a href='/admin?type=NORMAL'         class='fb "
                + ("NORMAL".equals(af)         ? "act" : "") + "'>NORMAL</a>\n"
                + "    <div class='sp'></div>\n"
                + "    <a href='/simulate' class='ab ab-sim'>&#9889; SIMULATE 20 ATTACKS</a>\n"
                + "    <form method='POST' action='/admin' style='display:inline'"
                +          " onsubmit=\"return confirm('Delete ALL records?')\">\n"
                + "      <input type='hidden' name='action' value='clear'/>\n"
                + "      <button type='submit' class='ab ab-clr'>&#128465; CLEAR ALL</button>\n"
                + "    </form>\n"
                + "  </div>\n"

                + "  <div class='tw'><table>\n"
                + "    <thead><tr>"
                + "<th>#</th><th>TYPE</th><th>IP ADDRESS</th>"
                + "<th>USERNAME</th><th>PASSWORD</th><th>PAYLOAD</th>"
                + "<th>TIMESTAMP</th><th>MAC</th><th>USER AGENT</th>"
                + "</tr></thead>\n"
                + "    <tbody>" + rows.toString() + "</tbody>\n"
                + "  </table></div>\n"
                + "  <div class='rn'>AUTO-REFRESH 15s &nbsp;&middot;&nbsp; "
                + records.size() + " RECORDS &nbsp;&middot;&nbsp; SUSLURE v1.0</div>\n"
                + "</div>\n"
                + "<footer>SUSLURE HONEYPOT &nbsp;&middot;&nbsp; "
                + "DETECT &nbsp;&middot;&nbsp; TRAP &nbsp;&middot;&nbsp; "
                + "EXPOSE &nbsp;&middot;&nbsp; DESTROY</footer>\n"
                + "</body></html>";
    }

    // HTML-escape — prevents XSS when displaying attacker-supplied data
    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}