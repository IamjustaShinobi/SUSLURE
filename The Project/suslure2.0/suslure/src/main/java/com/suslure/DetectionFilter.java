package com.suslure;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * DetectionFilter — SQLi → Brute Force → Session Hijack detection.
 * Now also extracts full UA profile and HTTP headers at intercept time.
 */
public class DetectionFilter implements Filter {

    // ── SQLi payloads ─────────────────────────────────────────────────
    private static final List<String> SQLI_PAYLOADS = Arrays.asList(
        "' or '1'='1","' or 1=1--","' or 1=1#","' or 1=1/*",
        "admin'--","admin' #","admin'/*","' or 'x'='x",
        "') or ('1'='1","' or ''='","1' or '1'='1","or 1=1--",
        "' or 1--","\"or \"1\"=\"1","') or 1=1--","' or true--",
        "union select","union all select","union select null",
        "union select 1,2","union select 1,2,3","' union select",
        "1 union select","' union all select","1 union all select",
        "and 1=1","and 1=2","and '1'='1","1' and '1'='1",
        "1 and 1=1"," and 1=1--","and true","and false",
        "sleep(","sleep (","waitfor delay","pg_sleep(","benchmark(",
        "sleep(5)","sleep(10)","sleep(1)",
        "extractvalue(","updatexml(","and extractvalue",
        "exp(~(","geometrycollection(",
        "--","/*",";--","';--","\";--","' --","\"--",
        "; drop table","; select","; insert",
        "; update","; delete","; exec",
        "information_schema","sys.tables","sysobjects",
        "order by 1--","group by 1--","having 1=1",
        "xp_cmdshell","exec(","execute(","sp_executesql","cast(",
        "%27 or","%27%20or","0x27","char(39)","%22 or"
    );

    private static final List<Pattern> SQLI_PATTERNS = List.of(
        Pattern.compile("('.+--)",                     Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bOR\\b.+[=<>])",           Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bUNION\\b.+\\bSELECT\\b)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bSELECT\\b.+\\bFROM\\b)",  Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bDROP\\b.+\\bTABLE\\b)",   Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bSLEEP\\b\\s*\\()",         Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bEXEC\\b\\s*\\()",          Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bINSERT\\b.+\\bINTO\\b)",   Pattern.CASE_INSENSITIVE)
    );

    // ── Brute force tracker ────────────────────────────────────────────
    private static final Map<String, Integer> failedAttempts   = new ConcurrentHashMap<>();
    private static final Map<String, Long>    firstAttemptTime = new ConcurrentHashMap<>();
    public  static final int                  BRUTE_THRESHOLD  = 5;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest  request  = (HttpServletRequest)  req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        String ip        = getClientIP(request);
        String username  = safe(request.getParameter("username"));
        String password  = safe(request.getParameter("password"));
        String userAgent = safe(request.getHeader("User-Agent"));
        String sessionId = safe(SessionManager.extractToken(request));

        // ── Extract UA profile + headers (fast, synchronous) ───────────
        AttackerProfiler.UAInfo ua   = AttackerProfiler.parseUA(userAgent);
        String allHeaders            = AttackerProfiler.dumpHeaders(request);

        // ── CHECK 1: SQL INJECTION ─────────────────────────────────────
        String sqliPayload = detectSQLi(username, password);
        if (sqliPayload != null) {
            int id = DatabaseManager.logAndGetId(ip, username, password,
                    IntrusionRecord.TYPE_SQLI, sqliPayload, userAgent, sessionId,
                    ua.os, ua.browser, ua.deviceType, ua.attackTool, allHeaders);
            NetworkScanner.enrichAsync(ip, id);
            response.sendRedirect("/trap/sqli?payload="
                    + enc(sqliPayload) + "&user=" + enc(username) + "&ip=" + enc(ip));
            return;
        }

        // ── CHECK 2: BRUTE FORCE ───────────────────────────────────────
        int attempts = failedAttempts.getOrDefault(ip, 0);
        if (attempts >= BRUTE_THRESHOLD) {
            long first = firstAttemptTime.getOrDefault(ip, System.currentTimeMillis());
            int id = DatabaseManager.logAndGetId(ip, username, password,
                    IntrusionRecord.TYPE_BRUTE, null, userAgent, sessionId,
                    ua.os, ua.browser, ua.deviceType, ua.attackTool, allHeaders);
            NetworkScanner.enrichAsync(ip, id);
            response.sendRedirect("/trap/bruteforce?ip=" + enc(ip)
                    + "&attempts=" + attempts
                    + "&since=" + enc(new Date(first).toString()));
            return;
        }

        // ── CHECK 3: SESSION HIJACK ────────────────────────────────────
        String tampered = SessionManager.detectTampering(request);
        if (tampered != null) {
            int id = DatabaseManager.logAndGetId(ip, username, password,
                    IntrusionRecord.TYPE_HIJACK, tampered, userAgent, sessionId,
                    ua.os, ua.browser, ua.deviceType, ua.attackTool, allHeaders);
            NetworkScanner.enrichAsync(ip, id);
            response.sendRedirect("/trap/hijack?ip=" + enc(ip) + "&token=" + enc(tampered));
            return;
        }

        // ── PASS → LoginServlet ────────────────────────────────────────
        request.setAttribute("detectedIp", ip);
        request.setAttribute("uaInfo",     ua);
        request.setAttribute("allHeaders", allHeaders);
        chain.doFilter(request, response);
    }

    // ── Detection helpers ─────────────────────────────────────────────
    public static String detectSQLi(String username, String password) {
        for (String input : new String[]{username, password}) {
            if (input == null || input.isBlank()) continue;
            String lower = input.toLowerCase().trim();
            for (String p : SQLI_PAYLOADS) if (lower.contains(p.toLowerCase())) return p;
            for (Pattern p : SQLI_PATTERNS) if (p.matcher(input).find())
                return input.substring(0, Math.min(input.length(), 80));
        }
        return null;
    }

    public static void registerFailedAttempt(String ip) {
        failedAttempts.merge(ip, 1, Integer::sum);
        firstAttemptTime.putIfAbsent(ip, System.currentTimeMillis());
        System.out.printf("[BRUTE] %s → %d/%d%n", ip, failedAttempts.get(ip), BRUTE_THRESHOLD);
    }

    public static void resetAttempts(String ip) {
        failedAttempts.remove(ip); firstAttemptTime.remove(ip);
    }

    public static Map<String, Integer> getAllAttempts() {
        return Collections.unmodifiableMap(failedAttempts);
    }

    private static String getClientIP(HttpServletRequest req) {
        String xf = req.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) return xf.split(",")[0].trim();
        return req.getRemoteAddr();
    }

    private static String enc(String s) {
        if (s == null) return "";
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String safe(String s) { return s == null ? "" : s; }

    @Override public void init(FilterConfig cfg) {}
    @Override public void destroy() {}
}
