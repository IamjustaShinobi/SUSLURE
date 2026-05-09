package com.suslure;

import javax.servlet.http.*;
import java.util.*;

/**
 * SessionManager — Issues and validates SUSLURE_TOKEN cookies.
 */
public class SessionManager {

    public static final String COOKIE_NAME = "SUSLURE_TOKEN";

    private static final Set<String> validTokens =
            Collections.synchronizedSet(new HashSet<>());

    public static void initialize() {
        System.out.println("[SUSLURE] SessionManager initialized.");
    }

    public static String issueToken(HttpServletResponse response) {
        String token = "SL-" + UUID.randomUUID().toString().replace("-", "").toUpperCase();
        validTokens.add(token);
        Cookie cookie = new Cookie(COOKIE_NAME, token);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60);
        cookie.setHttpOnly(false); // intentionally exposed for hijack detection demo
        response.addCookie(cookie);
        return token;
    }

    public static boolean isValidToken(String token) {
        if (token == null || token.isBlank()) return false;
        return validTokens.contains(token);
    }

    public static String extractToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (COOKIE_NAME.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    /**
     * Returns the tampered token value if detected, null if clean.
     */
    public static String detectTampering(HttpServletRequest request) {
        String token = extractToken(request);
        if (token == null) return null;           // no cookie = first visit
        if (!isValidToken(token)) return token;   // has cookie but we didn't issue it
        return null;
    }

    public static int getCount() { return validTokens.size(); }
}
