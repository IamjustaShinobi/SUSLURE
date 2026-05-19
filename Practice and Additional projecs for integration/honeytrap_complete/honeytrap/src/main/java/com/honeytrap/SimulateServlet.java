package com.honeytrap;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Random;

/**
 * SimulateServlet — Inserts 20 random attacks into the database for demo purposes.
 * Hit /simulate to populate the dashboard with realistic attack data.
 */
public class SimulateServlet extends HttpServlet {

    private static final Random RNG = new Random();
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String[] FAKE_IPS = {
        "192.168.1.105", "10.0.0.23", "172.16.0.55", "45.33.32.156",
        "198.51.100.42", "203.0.113.77", "104.21.96.1", "23.227.38.32",
        "185.199.108.1", "140.82.121.4"
    };

    private static final String[] USERNAMES = {
        "admin", "root", "administrator", "user", "test",
        "guest", "superuser", "sysadmin", "manager", "support"
    };

    private static final String[] PASSWORDS = {
        "password", "123456", "admin", "letmein", "qwerty",
        "password123", "12345678", "abc123", "monkey", "1234567890"
    };

    private static final List<String> SAMPLE_PAYLOADS = List.of(
        "' OR '1'='1", "' OR 1=1--", "admin'--",
        "UNION SELECT 1,2,3", "'; DROP TABLE users--",
        "' OR 'x'='x", "SLEEP(5)", "1' AND '1'='1",
        "admin' #", "' UNION ALL SELECT NULL--"
    );

    private static final String[] USER_AGENTS = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "sqlmap/1.7.8#stable (https://sqlmap.org)",
        "python-requests/2.28.0",
        "curl/7.88.1",
        "Hydra v9.4 (https://github.com/vanhauser-thc/thc-hydra)",
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "Nikto/2.1.6"
    };

    private static final String[] FAKE_TOKENS = {
        "HACKED_TOKEN_123", "admin_bypass", "../../../../etc/passwd",
        "eyJhbGciOiJub25lIn0.fake.sig", "'; DROP TABLE sessions--",
        "FAKE-SESSION-XYZ", "0x41414141"
    };

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {

        int count = 0;
        for (int i = 0; i < 20; i++) {
            int roll = RNG.nextInt(4);
            String ip        = FAKE_IPS[RNG.nextInt(FAKE_IPS.length)];
            String username  = USERNAMES[RNG.nextInt(USERNAMES.length)];
            String password  = PASSWORDS[RNG.nextInt(PASSWORDS.length)];
            String ua        = USER_AGENTS[RNG.nextInt(USER_AGENTS.length)];
            String ts        = LocalDateTime.now()
                    .minusMinutes(RNG.nextInt(120))
                    .format(FMT);

            switch (roll) {
                case 0 -> {
                    // SQLi
                    String payload = SAMPLE_PAYLOADS.get(RNG.nextInt(SAMPLE_PAYLOADS.size()));
                    DatabaseManager.logIntrusion(ip,
                            username + payload.substring(0, Math.min(payload.length(), 8)),
                            password, IntrusionRecord.TYPE_SQLI,
                            payload, ua, "HT-SIM-" + i);
                }
                case 1 -> {
                    // Brute force
                    DatabaseManager.logIntrusion(ip, username, password,
                            IntrusionRecord.TYPE_BRUTE, null, ua, "HT-SIM-" + i);
                }
                case 2 -> {
                    // Session hijack
                    String fakeToken = FAKE_TOKENS[RNG.nextInt(FAKE_TOKENS.length)];
                    DatabaseManager.logIntrusion(ip, username, password,
                            IntrusionRecord.TYPE_HIJACK, fakeToken, ua, fakeToken);
                }
                default -> {
                    // Normal failed attempt
                    DatabaseManager.logIntrusion(ip, username, password,
                            IntrusionRecord.TYPE_NORMAL, null, ua, "HT-SIM-" + i);
                }
            }
            count++;
        }

        res.sendRedirect("/admin");
    }
}
