package com.honeytrap;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;
import java.util.List;

/**
 * AdminServlet — Renders the attack dashboard at /admin.
 * Shows all logged intrusions in a color-coded table with stats.
 */
public class AdminServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {

        String filter = req.getParameter("type"); // null = all
        List<IntrusionRecord> records = (filter != null && !filter.isBlank())
                ? DatabaseManager.getByAttackType(filter.toUpperCase())
                : DatabaseManager.getAllRecords();

        int total   = DatabaseManager.getTotalCount();
        int sqli    = DatabaseManager.getCountByType(IntrusionRecord.TYPE_SQLI);
        int brute   = DatabaseManager.getCountByType(IntrusionRecord.TYPE_BRUTE);
        int hijack  = DatabaseManager.getCountByType(IntrusionRecord.TYPE_HIJACK);
        int normal  = DatabaseManager.getCountByType(IntrusionRecord.TYPE_NORMAL);
        int uniqIPs = DatabaseManager.getUniqueIpCount();

        res.setContentType("text/html;charset=UTF-8");
        PrintWriter out = res.getWriter();
        out.write(buildDashboard(records, total, sqli, brute, hijack, normal, uniqIPs, filter));
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        String action = req.getParameter("action");
        if ("clear".equals(action)) {
            DatabaseManager.clearAll();
        }
        res.sendRedirect("/admin");
    }

    private String buildDashboard(List<IntrusionRecord> records,
                                   int total, int sqli, int brute,
                                   int hijack, int normal, int uniqIPs, String filter) {
        StringBuilder rows = new StringBuilder();
        if (records.isEmpty()) {
            rows.append("<tr><td colspan='8' style='text-align:center;padding:40px;color:#2a3a4a;font-family:monospace'>No records found. Waiting for attackers...</td></tr>");
        } else {
            for (IntrusionRecord r : records) {
                rows.append("<tr class='").append(r.getCssClass()).append("'>")
                    .append("<td>").append(r.getId()).append("</td>")
                    .append("<td><span class='badge badge-").append(r.getAttackType().toLowerCase().replace("_","-")).append("'>").append(esc(r.getBadge())).append("</span></td>")
                    .append("<td class='mono'>").append(esc(r.getIpAddress())).append("</td>")
                    .append("<td>").append(esc(r.getUsername())).append("</td>")
                    .append("<td>").append(esc(r.getPassword())).append("</td>")
                    .append("<td class='payload'>").append(esc(r.getSafePayload())).append("</td>")
                    .append("<td class='mono ts'>").append(esc(r.getTimestamp())).append("</td>")
                    .append("<td class='ua'>").append(esc(r.getUserAgent().length() > 40 ? r.getUserAgent().substring(0,40)+"…" : r.getUserAgent())).append("</td>")
                    .append("</tr>");
            }
        }

        String activeFilter = filter != null ? filter.toUpperCase() : "ALL";

        return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta http-equiv="refresh" content="15"/>
<title>HoneyTrap — Attack Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&family=Inter:wght@400;500;600;700&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{background:#02040a;font-family:'Inter',sans-serif;color:#cce6f4;min-height:100vh;overflow-x:hidden}
  body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,180,255,0.008) 3px,rgba(0,180,255,0.008) 4px);pointer-events:none;z-index:9999}
  .topbar{background:rgba(4,8,18,0.95);border-bottom:1px solid #0f1e35;padding:0 28px;height:54px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;backdrop-filter:blur(12px)}
  .brand{font-family:'Orbitron',sans-serif;font-size:13px;font-weight:900;color:#22d3ee;letter-spacing:2px}
  .brand span{color:#4a5070;font-size:10px;letter-spacing:3px;font-family:'Share Tech Mono',monospace;font-weight:400;margin-left:12px}
  .live{display:flex;align-items:center;gap:6px;font-family:'Share Tech Mono',monospace;font-size:10px;color:#22c55e;letter-spacing:2px}
  .live-dot{width:7px;height:7px;border-radius:50%;background:#22c55e;animation:blink 1.5s infinite}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
  .page{max-width:1400px;margin:0 auto;padding:28px 24px}
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:28px}
  .stat-card{background:rgba(8,14,28,0.8);border:1px solid #0f1e35;padding:18px 20px;transition:border-color .2s}
  .stat-card:hover{border-color:#1e3a55}
  .stat-num{font-family:'Orbitron',sans-serif;font-size:28px;font-weight:900;display:block;line-height:1}
  .stat-lbl{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;opacity:.5;text-transform:uppercase;margin-top:6px;display:block}
  .sc-total  .stat-num{color:#22d3ee}
  .sc-sqli   .stat-num{color:#ff3b3b}
  .sc-brute  .stat-num{color:#ff8c00}
  .sc-hijack .stat-num{color:#b026ff}
  .sc-normal .stat-num{color:#22c55e}
  .sc-ips    .stat-num{color:#facc15}
  .controls{display:flex;align-items:center;gap:10px;margin-bottom:20px;flex-wrap:wrap}
  .filter-btn{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;padding:7px 14px;border:1px solid #0f1e35;background:transparent;color:#4a6a7a;cursor:pointer;transition:all .2s;text-decoration:none;display:inline-block}
  .filter-btn:hover,.filter-btn.active{color:#22d3ee;border-color:rgba(34,211,238,0.4);background:rgba(34,211,238,0.06)}
  .filter-btn.f-sqli.active  {color:#ff3b3b;border-color:rgba(255,59,59,0.4);background:rgba(255,59,59,0.06)}
  .filter-btn.f-brute.active {color:#ff8c00;border-color:rgba(255,140,0,0.4);background:rgba(255,140,0,0.06)}
  .filter-btn.f-hijack.active{color:#b026ff;border-color:rgba(176,38,255,0.4);background:rgba(176,38,255,0.06)}
  .spacer{flex:1}
  .action-btn{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;padding:7px 14px;border:1px solid;background:transparent;cursor:pointer;transition:all .2s;text-decoration:none;display:inline-block}
  .btn-sim{color:#22d3ee;border-color:rgba(34,211,238,0.3)}
  .btn-sim:hover{background:rgba(34,211,238,0.08)}
  .btn-clr{color:#ff3b3b;border-color:rgba(255,59,59,0.3)}
  .btn-clr:hover{background:rgba(255,59,59,0.08)}
  .table-wrap{overflow-x:auto;border:1px solid #0f1e35}
  table{width:100%;border-collapse:collapse;font-size:13px}
  thead th{background:rgba(4,8,18,0.95);color:#22d3ee;font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;text-transform:uppercase;padding:12px 14px;text-align:left;border-bottom:1px solid #0f1e35;white-space:nowrap}
  tbody td{padding:10px 14px;border-bottom:1px solid rgba(15,30,53,0.7);vertical-align:middle;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  tbody tr:hover td{background:rgba(34,211,238,0.025)}
  .row-sqli   td{border-left:3px solid #ff3b3b}
  .row-brute  td{border-left:3px solid #ff8c00}
  .row-hijack td{border-left:3px solid #b026ff}
  .row-normal td{border-left:3px solid #22c55e}
  .row-sqli   td:first-child{background:rgba(255,59,59,0.04)}
  .row-brute  td:first-child{background:rgba(255,140,0,0.04)}
  .row-hijack td:first-child{background:rgba(176,38,255,0.04)}
  .badge{font-family:'Share Tech Mono',monospace;font-size:10px;padding:3px 8px;border:1px solid;border-radius:2px;white-space:nowrap}
  .badge-sqli         {color:#ff3b3b;border-color:rgba(255,59,59,0.4);background:rgba(255,59,59,0.08)}
  .badge-brute-force  {color:#ff8c00;border-color:rgba(255,140,0,0.4);background:rgba(255,140,0,0.08)}
  .badge-session-hijack{color:#b026ff;border-color:rgba(176,38,255,0.4);background:rgba(176,38,255,0.08)}
  .badge-normal       {color:#22c55e;border-color:rgba(34,197,94,0.4);background:rgba(34,197,94,0.08)}
  .mono{font-family:'Share Tech Mono',monospace;font-size:12px}
  .ts{color:#4a6a7a;font-size:11px}
  .payload{color:#ff6b6b;font-family:'Share Tech Mono',monospace;font-size:11px;max-width:150px}
  .ua{color:#3a5060;font-size:11px}
  .refresh-note{font-family:'Share Tech Mono',monospace;font-size:10px;color:#1a2a38;text-align:right;margin-top:10px;letter-spacing:1px}
  footer{text-align:center;padding:28px;font-family:'Share Tech Mono',monospace;font-size:10px;color:#1a2a38;letter-spacing:2px;border-top:1px solid #0a1422;margin-top:20px}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">◈ HONEYTRAP <span>ATTACK DASHBOARD v2.0</span></div>
  <div class="live"><div class="live-dot"></div> MONITORING LIVE</div>
</div>
<div class="page">

  <!-- Stats Row -->
  <div class="stats-grid">
    <div class="stat-card sc-total"> <span class="stat-num">""" + total   + """</span><span class="stat-lbl">Total Attacks</span></div>
    <div class="stat-card sc-sqli">  <span class="stat-num">""" + sqli    + """</span><span class="stat-lbl">💉 SQL Injection</span></div>
    <div class="stat-card sc-brute"> <span class="stat-num">""" + brute   + """</span><span class="stat-lbl">🔨 Brute Force</span></div>
    <div class="stat-card sc-hijack"><span class="stat-num">""" + hijack  + """</span><span class="stat-lbl">👻 Session Hijack</span></div>
    <div class="stat-card sc-normal"><span class="stat-num">""" + normal  + """</span><span class="stat-lbl">🔐 Normal Attempts</span></div>
    <div class="stat-card sc-ips">   <span class="stat-num">""" + uniqIPs + """</span><span class="stat-lbl">Unique IPs</span></div>
  </div>

  <!-- Controls -->
  <div class="controls">
    <a href="/admin"                  class="filter-btn """
                + ("ALL".equals(activeFilter)           ? "active" : "") + """ ">ALL</a>
    <a href="/admin?type=SQLI"        class="filter-btn f-sqli """
                + ("SQLI".equals(activeFilter)          ? "active" : "") + """ ">💉 SQLI</a>
    <a href="/admin?type=BRUTE_FORCE" class="filter-btn f-brute """
                + ("BRUTE_FORCE".equals(activeFilter)   ? "active" : "") + """ ">🔨 BRUTE</a>
    <a href="/admin?type=SESSION_HIJACK" class="filter-btn f-hijack """
                + ("SESSION_HIJACK".equals(activeFilter)? "active" : "") + """ ">👻 HIJACK</a>
    <a href="/admin?type=NORMAL"      class="filter-btn """
                + ("NORMAL".equals(activeFilter)          ? "active" : "") + """ ">🔐 NORMAL</a>
    <div class="spacer"></div>
    <a href="/simulate" class="action-btn btn-sim">⚡ SIMULATE 20 ATTACKS</a>
    <form method="POST" action="/admin" style="display:inline" onsubmit="return confirm('Delete ALL records?')">
      <input type="hidden" name="action" value="clear"/>
      <button type="submit" class="action-btn btn-clr">🗑 CLEAR ALL</button>
    </form>
  </div>

  <!-- Table -->
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>#</th><th>Attack Type</th><th>IP Address</th>
          <th>Username</th><th>Password</th><th>Payload</th>
          <th>Timestamp</th><th>User Agent</th>
        </tr>
      </thead>
      <tbody>""" + rows + """
      </tbody>
    </table>
  </div>
  <div class="refresh-note">AUTO-REFRESH EVERY 15s · """ + records.size() + """ RECORDS SHOWN</div>
</div>
<footer>HONEYTRAP v2.0 · DETECT · TRAP · EXPOSE · DESTROY</footer>
</body>
</html>
""";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;")
                .replace(">","&gt;").replace("\"","&quot;");
    }
}
