package com.honeytrap;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  DetectionFilter — THE SIEVE                                     ║
 * ║  Intercepts every POST to /login before the servlet sees it.    ║
 * ║  Checks 3 attack vectors in priority order:                     ║
 * ║    1. SQL Injection  → /trap/sqli                               ║
 * ║    2. Brute Force    → /trap/bruteforce                         ║
 * ║    3. Session Hijack → /trap/hijack                             ║
 * ║  Demonstrates: OOP Abstraction + Chain of Responsibility        ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */
public class DetectionFilter implements Filter {

    // ══════════════════════════════════════════════════════════════════════
    //  ① SQL INJECTION PAYLOAD LIBRARY — 50+ known attack strings
    // ══════════════════════════════════════════════════════════════════════
    private static final List<String> SQLI_PAYLOADS = Arrays.asList(

        // ── Classic authentication bypass ────────────────────────────────
        "' or '1'='1",     "' or 1=1--",       "' or 1=1#",
        "' or 1=1/*",      "admin'--",          "admin' #",
        "admin'/*",        "' or 'x'='x",       "') or ('1'='1",
        "' or ''='",       "1' or '1'='1",      "or 1=1--",
        "' or 1--",        "\" or \"1\"=\"1",   "') or 1=1--",

        // ── UNION-based attacks ───────────────────────────────────────────
        "union select",    "union all select",  "union select null",
        "union select 1,2","union select 1,2,3","' union select",
        "1 union select",  "' union all select",

        // ── Boolean-based blind ───────────────────────────────────────────
        "and 1=1",         "and 1=2",           "and '1'='1",
        "1' and '1'='1",   "1 and 1=1",         " and 1=1--",

        // ── Time-based blind ──────────────────────────────────────────────
        "sleep(5)",        "sleep(10)",         "waitfor delay",
        "pg_sleep(",       "benchmark(",        "sleep(0.1)",

        // ── Error-based ───────────────────────────────────────────────────
        "extractvalue(",   "updatexml(",        "and extractvalue",
        "exp(~(",          "geometrycollection(",

        // ── Comment terminators ───────────────────────────────────────────
        "--",              "#",                 "/*",
        ";--",             "';--",              "\";--",

        // ── Stacked / destructive queries ────────────────────────────────
        "; drop table",    "; select",          "; insert",
        "; update",        "; delete",          "; exec",

        // ── Schema discovery ─────────────────────────────────────────────
        "information_schema", "sys.tables",     "sysobjects",
        "order by 1--",    "group by 1--",      "having 1=1",

        // ── Stored procedures ─────────────────────────────────────────────
        "xp_cmdshell",     "exec(",             "execute(",
        "sp_executesql",   "cast(",

        // ── Encoded variants ──────────────────────────────────────────────
        "%27 or",          "%27%20or",          "0x27",
        "&#39; or",        "char(39)",          "%22 or"
    );

    // ── Regex patterns for more sophisticated detection ───────────────────
    private static final List<Pattern> SQLI_PATTERNS = Arrays.asList(
        Pattern.compile("('.+--)",                    Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bOR\\b.+\\b=\\b)",        Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bUNION\\b.+\\bSELECT\\b)",Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bSELECT\\b.+\\bFROM\\b)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bDROP\\b.+\\bTABLE\\b)",  Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bSLEEP\\b\\s*\\()",       Pattern.CASE_INSENSITIVE),
        Pattern.compile("(\\bEXEC\\b\\s*\\()",         Pattern.CASE_INSENSITIVE)
    );

    // ══════════════════════════════════════════════════════════════════════
    //  ② BRUTE FORCE TRACKER — IP address → failed attempt count
    // ══════════════════════════════════════════════════════════════════════
    private static final Map<String, Integer>  failedAttempts  = new ConcurrentHashMap<>();
    private static final Map<String, Long>     firstAttemptTime= new ConcurrentHashMap<>();
    public  static final int                   BRUTE_THRESHOLD = 5;

    // ══════════════════════════════════════════════════════════════════════
    //  FILTER ENTRY POINT — called on every POST /login
    // ══════════════════════════════════════════════════════════════════════
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest  request  = (HttpServletRequest)  req;
        HttpServletResponse response = (HttpServletResponse) res;

        // Only inspect POST requests — GET just serves the login page
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        String ip        = getClientIP(request);
        String username  = nvl(request.getParameter("username"));
        String password  = nvl(request.getParameter("password"));
        String userAgent = nvl(request.getHeader("User-Agent"));
        String sessionId = nvl(SessionManager.extractToken(request));

        // ── CHECK 1: SQL INJECTION (highest priority) ─────────────────────
        String sqliPayload = detectSQLi(username, password);
        if (sqliPayload != null) {
            DatabaseManager.logIntrusion(ip, username, password,
                    IntrusionRecord.TYPE_SQLI, sqliPayload, userAgent, sessionId);
            String encoded = URLEncoder.encode(sqliPayload, StandardCharsets.UTF_8);
            String encodedUser = URLEncoder.encode(username, StandardCharsets.UTF_8);
            response.sendRedirect("/trap/sqli?payload=" + encoded
                    + "&user=" + encodedUser + "&ip=" + ip);
            return; // ← STOP. Do not proceed to servlet.
        }

        // ── CHECK 2: BRUTE FORCE ──────────────────────────────────────────
        int attempts = failedAttempts.getOrDefault(ip, 0);
        if (attempts >= BRUTE_THRESHOLD) {
            DatabaseManager.logIntrusion(ip, username, password,
                    IntrusionRecord.TYPE_BRUTE, null, userAgent, sessionId);
            long firstTime = firstAttemptTime.getOrDefault(ip, System.currentTimeMillis());
            response.sendRedirect("/trap/bruteforce?ip=" + ip
                    + "&attempts=" + attempts
                    + "&since=" + URLEncoder.encode(
                            new java.util.Date(firstTime).toString(), StandardCharsets.UTF_8));
            return;
        }

        // ── CHECK 3: SESSION HIJACKING ─────────────────────────────────────
        String tamperedToken = SessionManager.detectTampering(request);
        if (tamperedToken != null) {
            DatabaseManager.logIntrusion(ip, username, password,
                    IntrusionRecord.TYPE_HIJACK, tamperedToken, userAgent, sessionId);
            String encodedToken = URLEncoder.encode(tamperedToken, StandardCharsets.UTF_8);
            response.sendRedirect("/trap/hijack?ip=" + ip
                    + "&token=" + encodedToken);
            return;
        }

        // ── ALL CHECKS PASSED — let the login servlet handle it ───────────
        // Login servlet will ALWAYS deny and call registerFailedAttempt()
        request.setAttribute("detectedIp", ip);
        chain.doFilter(request, response);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  DETECTION METHODS
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Checks username AND password against all SQLi payloads + regex patterns.
     * Case-insensitive. Returns the matched payload string, or null if clean.
     */
    private static String detectSQLi(String username, String password) {
        String[] inputs = { username, password };
        for (String input : inputs) {
            if (input == null || input.isBlank()) continue;
            String lower = input.toLowerCase().trim();

            // Check hardcoded payload list
            for (String payload : SQLI_PAYLOADS) {
                if (lower.contains(payload.toLowerCase())) {
                    return payload; // Match found — return the payload
                }
            }
            // Check regex patterns
            for (Pattern p : SQLI_PATTERNS) {
                if (p.matcher(input).find()) {
                    return input.substring(0, Math.min(input.length(), 80));
                }
            }
        }
        return null; // Clean
    }

    /** Increments the failed attempt counter for an IP. Called by LoginServlet. */
    public static void registerFailedAttempt(String ip) {
        failedAttempts.merge(ip, 1, Integer::sum);
        firstAttemptTime.putIfAbsent(ip, System.currentTimeMillis());
        int count = failedAttempts.get(ip);
        System.out.printf("[BruteTracker] %s → %d/%d failed attempts%n",
                ip, count, BRUTE_THRESHOLD);
    }

    /** Resets the brute force counter for an IP (e.g. after reset simulation). */
    public static void resetAttempts(String ip) {
        failedAttempts.remove(ip);
        firstAttemptTime.remove(ip);
    }

    public static Map<String, Integer> getAllAttempts() {
        return Collections.unmodifiableMap(failedAttempts);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /** Tries X-Forwarded-For first (for proxies), then getRemoteAddr(). */
    private static String getClientIP(HttpServletRequest request) {
        String xForward = request.getHeader("X-Forwarded-For");
        if (xForward != null && !xForward.isBlank()) {
            return xForward.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static String nvl(String s) {
        return s == null ? "" : s;
    }

    @Override public void init(FilterConfig cfg) {}
    @Override public void destroy() {}
}
