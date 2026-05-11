package com.honeytrap;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * SessionManager — Issues and validates HONEYTRAP_TOKEN cookies.
 * Valid tokens are stored in memory. A tampered or forged cookie
 * that wasn't issued by this server will fail validation.
 */
public class SessionManager {

    public static final String COOKIE_NAME = "HONEYTRAP_TOKEN";

    /** Thread-safe set of all tokens this server has legitimately issued */
    private static final Set<String> validTokens =
            Collections.synchronizedSet(new HashSet<>());

    public static void initialize() {
        System.out.println("[Session] SessionManager initialized.");
    }

    /** Generates a new unique token, stores it, and sets it as a cookie. */
    public static String issueToken(HttpServletResponse response) {
        String token = "HT-" + UUID.randomUUID().toString().replace("-", "").toUpperCase();
        validTokens.add(token);

        Cookie cookie = new Cookie(COOKIE_NAME, token);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60); // 1 hour
        cookie.setHttpOnly(false); // intentionally visible so attackers can try to tamper it
        response.addCookie(cookie);
        return token;
    }

    /**
     * Returns true if the token from the cookie is one we actually issued.
     * Returns false if it was forged, modified, or from another session.
     */
    public static boolean isValidToken(String token) {
        if (token == null || token.isBlank()) return false;
        return validTokens.contains(token);
    }

    /** Extracts the HONEYTRAP_TOKEN value from the request cookies. */
    public static String extractToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (COOKIE_NAME.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    /**
     * Checks if the session has been tampered with.
     * Returns the tampered token string if detected, null if clean.
     */
    public static String detectTampering(HttpServletRequest request) {
        String token = extractToken(request);
        if (token == null) return null; // No cookie = first visit, not tampered
        if (!isValidToken(token)) {
            return token; // Cookie exists but wasn't issued by us = TAMPERED
        }
        return null; // Valid token
    }

    public static int getActiveSessionCount() {
        return validTokens.size();
    }
}
