package com.suslure;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * AttackerProfiler — Synchronous UA/header fingerprinting + async port scan.
 * Called from DetectionFilter at the moment of attack detection.
 */
public class AttackerProfiler {

    // ══════════════════════════════════════════════════════════════════
    // UA Fingerprinting
    // ══════════════════════════════════════════════════════════════════

    public static class UAInfo {
        public String os         = "Unknown";
        public String browser    = "Unknown";
        public String deviceType = "Unknown";
        public String attackTool = null;   // null = not a known tool
    }

    private static final String[][] ATTACK_TOOLS = {
        {"sqlmap",          "SQLMap"},
        {"hydra",           "Hydra"},
        {"nikto",           "Nikto"},
        {"masscan",         "Masscan"},
        {"nmap",            "Nmap"},
        {"zgrab",           "ZGrab"},
        {"dirbuster",       "DirBuster"},
        {"gobuster",        "GoBuster"},
        {"wfuzz",           "WFuzz"},
        {"metasploit",      "Metasploit"},
        {"burp",            "Burp Suite"},
        {"nessus",          "Nessus"},
        {"openvas",         "OpenVAS"},
        {"nuclei",          "Nuclei"},
        {"acunetix",        "Acunetix"},
        {"w3af",            "W3AF"},
        {"python-requests", "Python Requests"},
        {"python-urllib",   "Python urllib"},
        {"go-http-client",  "Go HTTP Client"},
        {"libwww-perl",     "Perl LWP"},
        {"wget/",           "Wget"},
        {"curl/",           "cURL"},
        {"httpclient",      "Apache HttpClient"},
        {"scrapy",          "Scrapy"},
        {"mechanize",       "Mechanize"},
        {"phantomjs",       "PhantomJS"},
        {"java/",           "Java HttpClient"},
        {"okhttp",          "OkHttp"},
        {"axios",           "Axios"},
        {"postman",         "Postman"},
    };

    public static UAInfo parseUA(String ua) {
        UAInfo info = new UAInfo();
        if (ua == null || ua.isBlank()) {
            info.os         = "No User-Agent (Raw Script)";
            info.browser    = "None";
            info.deviceType = "⚙ Script";
            return info;
        }
        String l = ua.toLowerCase();

        // 1. Attack tool check — highest priority, return immediately
        for (String[] tool : ATTACK_TOOLS) {
            if (l.contains(tool[0])) {
                info.attackTool = tool[1];
                info.os         = "Script / Tool Environment";
                info.browser    = tool[1];
                info.deviceType = "🔴 Attack Tool";
                return info;
            }
        }

        // 2. OS
        if      (l.contains("windows nt 10") || l.contains("windows nt 11")) info.os = "Windows 10/11";
        else if (l.contains("windows nt 6.3")) info.os = "Windows 8.1";
        else if (l.contains("windows nt 6.2")) info.os = "Windows 8";
        else if (l.contains("windows nt 6.1")) info.os = "Windows 7";
        else if (l.contains("windows nt 5"))   info.os = "Windows XP";
        else if (l.contains("windows"))        info.os = "Windows";
        else if (l.contains("android")) {
            Matcher m = Pattern.compile("android ([\\d.]+)").matcher(l);
            info.os = m.find() ? "Android " + m.group(1) : "Android";
        }
        else if (l.contains("iphone") || l.contains("cpu iphone")) {
            Matcher m = Pattern.compile("os ([\\d_]+) like").matcher(l);
            info.os = m.find() ? "iOS " + m.group(1).replace('_', '.') : "iOS";
        }
        else if (l.contains("ipad"))    info.os = "iPadOS";
        else if (l.contains("mac os x")) {
            Matcher m = Pattern.compile("mac os x ([\\d_]+)").matcher(l);
            info.os = m.find() ? "macOS " + m.group(1).replace('_', '.') : "macOS";
        }
        else if (l.contains("ubuntu"))  info.os = "Ubuntu Linux";
        else if (l.contains("kali"))    info.os = "Kali Linux";
        else if (l.contains("fedora"))  info.os = "Fedora Linux";
        else if (l.contains("debian"))  info.os = "Debian Linux";
        else if (l.contains("centos"))  info.os = "CentOS Linux";
        else if (l.contains("arch"))    info.os = "Arch Linux";
        else if (l.contains("linux"))   info.os = "Linux";
        else if (l.contains("freebsd")) info.os = "FreeBSD";
        else if (l.contains("openbsd")) info.os = "OpenBSD";

        // 3. Browser (order matters: Edge > Opera > Firefox > Chrome > Safari)
        Matcher m;
        if      (l.contains("edg/") || l.contains("edge/")) {
            m = Pattern.compile("edg(?:e)?/([\\d]+)").matcher(l);
            info.browser = m.find() ? "Edge " + m.group(1) : "Edge";
        }
        else if (l.contains("opr/")) {
            m = Pattern.compile("opr/([\\d]+)").matcher(l);
            info.browser = m.find() ? "Opera " + m.group(1) : "Opera";
        }
        else if (l.contains("firefox/")) {
            m = Pattern.compile("firefox/([\\d]+)").matcher(l);
            info.browser = m.find() ? "Firefox " + m.group(1) : "Firefox";
        }
        else if (l.contains("chrome/")) {
            m = Pattern.compile("chrome/([\\d]+)").matcher(l);
            info.browser = m.find() ? "Chrome " + m.group(1) : "Chrome";
        }
        else if (l.contains("safari/") && !l.contains("chrome")) {
            m = Pattern.compile("version/([\\d]+)").matcher(l);
            info.browser = m.find() ? "Safari " + m.group(1) : "Safari";
        }

        // 4. Device type
        if      (l.contains("mobile") || l.contains("iphone") || l.contains("android"))
            info.deviceType = "📱 Mobile";
        else if (l.contains("tablet") || l.contains("ipad"))
            info.deviceType = "📱 Tablet";
        else if (l.contains("bot") || l.contains("spider") || l.contains("crawler"))
            info.deviceType = "🤖 Bot";
        else
            info.deviceType = "💻 Desktop";

        return info;
    }

    // ══════════════════════════════════════════════════════════════════
    // HTTP Header Dump
    // ══════════════════════════════════════════════════════════════════

    public static String dumpHeaders(HttpServletRequest req) {
        StringBuilder sb = new StringBuilder();
        // First line: method + path
        sb.append(req.getMethod()).append(" ").append(req.getRequestURI())
          .append(req.getQueryString() != null ? "?" + req.getQueryString() : "")
          .append(" ").append(req.getProtocol()).append("\n");

        Enumeration<String> names = req.getHeaderNames();
        if (names != null) {
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                sb.append(name).append(": ").append(req.getHeader(name)).append("\n");
            }
        }
        // Extra context
        sb.append("\n[Remote-Addr: ").append(req.getRemoteAddr()).append("]");
        sb.append("\n[Remote-Port: ").append(req.getRemotePort()).append("]");
        sb.append("\n[Server-Port: ").append(req.getServerPort()).append("]");
        sb.append("\n[Scheme: ").append(req.getScheme()).append("]");
        String cookies = req.getHeader("Cookie");
        if (cookies != null) sb.append("\n[Parsed-Cookies: ").append(cookies).append("]");
        return sb.toString().trim();
    }

    // ══════════════════════════════════════════════════════════════════
    // Port Scanner — LAN-optimized (300ms timeout, 22 ports)
    // ══════════════════════════════════════════════════════════════════

    private static final int[]    SCAN_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        1433, 3306, 3389, 4444, 5900, 6379, 8080, 8443, 27017, 9200
    };
    private static final String[] PORT_NAMES = {
        "FTP","SSH","Telnet","SMTP","DNS","HTTP","POP3","RPC","NetBIOS","IMAP",
        "HTTPS","SMB","MSSQL","MySQL","RDP","Meterpreter","VNC","Redis",
        "HTTP-Alt","HTTPS-Alt","MongoDB","Elasticsearch"
    };

    public static String scanPorts(String ip) {
        int timeout = isLAN(ip) ? 300 : 600;
        ExecutorService pool = Executors.newFixedThreadPool(SCAN_PORTS.length);
        List<Future<String>> futures = new ArrayList<>();

        for (int idx = 0; idx < SCAN_PORTS.length; idx++) {
            final int port = SCAN_PORTS[idx];
            final String name = PORT_NAMES[idx];
            futures.add(pool.submit(() -> {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(ip, port), timeout);
                    return port + "/" + name;
                } catch (IOException e) { return null; }
            }));
        }
        pool.shutdown();
        try { pool.awaitTermination(12, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}

        List<String> open = new ArrayList<>();
        for (Future<String> f : futures) {
            try {
                String r = f.get(100, TimeUnit.MILLISECONDS);
                if (r != null) open.add(r);
            } catch (Exception ignored) {}
        }
        return open.isEmpty() ? "None detected" : String.join("  |  ", open);
    }

    public static boolean isLAN(String ip) {
        if (ip == null) return false;
        return ip.startsWith("192.168.") || ip.startsWith("10.")
            || ip.startsWith("172.16.") || ip.startsWith("172.17.")
            || ip.startsWith("172.18.") || ip.startsWith("172.19.")
            || ip.startsWith("172.2")   || ip.startsWith("172.3")
            || ip.equals("127.0.0.1")   || ip.equals("::1")
            || ip.equals("0:0:0:0:0:0:0:1");
    }
}
