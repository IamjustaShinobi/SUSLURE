package com.suslure;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Random;

/**
 * SimulateServlet — Injects 20 realistic demo attacks for presentation.
 * Hit GET /simulate to populate the dashboard instantly.
 */
public class SimulateServlet extends HttpServlet {

    private static final Random RNG = new Random();
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String[] FAKE_IPS = {
        "192.168.1.105","10.0.0.23","172.16.0.55","45.33.32.156",
        "198.51.100.42","203.0.113.77","104.21.96.1","23.227.38.32",
        "185.199.108.1","140.82.121.4","91.108.4.1","95.161.76.100",
        "194.165.16.11","5.188.206.14","103.251.167.20"
    };
    private static final String[] USERNAMES = {
        "admin","root","administrator","user","test",
        "guest","superuser","sysadmin","manager","support",
        "sa","oracle","postgres","ubuntu","pi"
    };
    private static final String[] PASSWORDS = {
        "password","123456","admin","letmein","qwerty",
        "password123","12345678","abc123","monkey","1234567890",
        "iloveyou","dragon","master","sunshine","princess"
    };
    private static final List<String> SQLI_SAMPLES = List.of(
        "' OR '1'='1",   "' OR 1=1--",       "admin'--",
        "UNION SELECT 1,2,3", "'; DROP TABLE users--",
        "' OR 'x'='x",  "SLEEP(5)",          "1' AND '1'='1",
        "admin' #",      "' UNION ALL SELECT NULL--",
        "1 OR 1=1",      "'; EXEC xp_cmdshell('whoami')--",
        "' AND extractvalue(1,concat(0x7e,version()))--"
    );
    private static final String[] FAKE_TOKENS = {
        "HACKED_TOKEN_XYZ","admin_bypass_123","../../../../etc/passwd",
        "eyJhbGciOiJub25lIn0.fake.payload","'; DROP TABLE sessions--",
        "FAKE-SL-SESSION","0x41414141","<script>alert(1)</script>",
        "SL-000000000000000000000000000000"
    };
    private static final String[] FAKE_MACS = {
        "AA:BB:CC:DD:EE:FF","11:22:33:44:55:66","DE:AD:BE:EF:CA:FE",
        "00:11:22:33:44:55","FF:EE:DD:CC:BB:AA","12:34:56:78:9A:BC"
    };
    private static final String[] VENDORS = {
        "Huawei","TP-Link","Apple","Samsung","Xiaomi","Intel","Unknown"
    };
    private static final String[] USER_AGENTS = {
        "sqlmap/1.7.8#stable (https://sqlmap.org)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "python-requests/2.28.0",
        "curl/7.88.1",
        "Hydra v9.4 (https://github.com/vanhauser-thc/thc-hydra)",
        "Nikto/2.1.6",
        "masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)",
        "Go-http-client/1.1"
    };

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {

        // Check admin auth
        HttpSession session = req.getSession(false);
        if (session == null || !Boolean.TRUE.equals(session.getAttribute("suslure_admin_auth"))) {
            res.sendRedirect("/admin");
            return;
        }

        for (int i = 0; i < 20; i++) {
            String ip      = FAKE_IPS[RNG.nextInt(FAKE_IPS.length)];
            String user    = USERNAMES[RNG.nextInt(USERNAMES.length)];
            String pass    = PASSWORDS[RNG.nextInt(PASSWORDS.length)];
            String ua      = USER_AGENTS[RNG.nextInt(USER_AGENTS.length)];
            String mac     = FAKE_MACS[RNG.nextInt(FAKE_MACS.length)];
            String vendor  = VENDORS[RNG.nextInt(VENDORS.length)];
            String host    = "host-" + ip.replace(".", "-") + ".local";

            int roll = RNG.nextInt(4);
            switch (roll) {
                case 0 -> {
                    String payload = SQLI_SAMPLES.get(RNG.nextInt(SQLI_SAMPLES.size()));
                    DatabaseManager.logIntrusion(ip, user + payload.substring(0, Math.min(4, payload.length())),
                            pass, IntrusionRecord.TYPE_SQLI, payload, ua, "SL-SIM-" + i, mac, vendor, host);
                }
                case 1 -> DatabaseManager.logIntrusion(ip, user, pass,
                        IntrusionRecord.TYPE_BRUTE, null, ua, "SL-SIM-" + i, mac, vendor, host);
                case 2 -> {
                    String tok = FAKE_TOKENS[RNG.nextInt(FAKE_TOKENS.length)];
                    DatabaseManager.logIntrusion(ip, user, pass,
                            IntrusionRecord.TYPE_HIJACK, tok, ua, tok, mac, vendor, host);
                }
                default -> DatabaseManager.logIntrusion(ip, user, pass,
                        IntrusionRecord.TYPE_NORMAL, null, ua, "SL-SIM-" + i, mac, vendor, host);
            }
        }
        res.sendRedirect("/admin");
    }
}
