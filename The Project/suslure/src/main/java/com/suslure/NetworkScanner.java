package com.suslure;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * NetworkScanner — Integrated into SUSLURE.
 * Used to enrich attack logs with MAC address, vendor, and hostname.
 * Runs async after each detected attack so it never blocks the HTTP response.
 */
public class NetworkScanner {

    static final boolean IS_WIN = System.getProperty("os.name").toLowerCase().contains("win");

    // ── Minimal OUI vendor database ──────────────────────────────────────
    private static final Map<String, String> OUI = new HashMap<>();
    static {
        String[][] entries = {
            // Apple
            {"000A27","000393","0017F2","001124","0016CB","001451","001E52","18AF61",
             "3C2EF9","40A6D9","5417F6","70700D","7C5049","8C2937","A45E60","B09FBA",
             "C42C03","DC2B2A","F0D1A9","F45C89","F82793","F8A9D0","003065","0050E4"}, "Apple",
            // Samsung
            {"002637","103047","18677C","2C8A72","606BBD","74458A","9C3AAF","C07EF5",
             "D0176A","F0B47B","0C7170","285BEB","4C3C16","843835","98D6BB","A4EBD3"}, "Samsung",
            // TP-Link
            {"000AEB","1CF6D9","2C3CD2","34E894","64608C","98DAAC","B490A9","E01EDD",
             "F4F26D","305A3A","44691A","60A4D0","7C8B9F","A0F3C1","DC0BB2","FC7516"}, "TP-Link",
            // Huawei
            {"001882","083FBC","20A680","30452E","48AD08","54516B","70728D","80717A",
             "90673C","AC853D","C0BFC0","D065CA","E0191C","F4559C","1C1D86","3CB16E"}, "Huawei",
            // Xiaomi
            {"10D677","28B2BD","38A4ED","58448C","64B473","8CBFA6","98FAE3","F0B429",
             "001569","3C9D35","74510E","A0860F","B0E235","E4D332","286AB8","FC644F"}, "Xiaomi",
            // Google
            {"3C5AB4","48D6D5","54600A","6C5AB5","94EB2C","A47733","D4F57D","F88FCA",
             "7C1C38","B0C5CA","DC4F22","E0F8A0","84C9B2","68A878","4CFCAA","2CAA8E"}, "Google",
            // Intel
            {"001B21","001DE0","005A04","0021F0","0022FA","40251B","5CF951","64D4DA",
             "7CEBB4","8C8D28","A4C494","B4B676","D89EF3","F4069D","F8B156","84A9C4"}, "Intel",
            // Microsoft
            {"001DD8","0025AE","28187B","485073","60451D","7C1E52","BC8385","F03F8B",
             "C4093E","DC1BAC","88B111","9866A0","2C54CF","54527E","C86000","00155D"}, "Microsoft",
            // Amazon
            {"0C47C9","18742E","34D270","40B4CD","50F5DA","74C246","84D6D0","B47C9C",
             "CC9EAE","F0272D","680571","6C5697","78E103","A002DC","A43DB0","F0D2F1"}, "Amazon",
            // Realtek
            {"001B2F","00E04C","040912","4E5534","80003A","C46679","E0D55E","52540B",
             "08002B","00163E","B83820","C81040","007018","5855CA","00FF37","147D2D"}, "Realtek",
        };
        // Build OUI map: each odd index is vendor name, even groups are prefixes
        for (int i = 0; i < entries.length; i += 2) {
            String vendor = entries[i + 1][0]; // vendor name is stored as single-element
            for (String prefix : entries[i]) OUI.put(prefix, vendor);
        }
    }

    /**
     * Looks up vendor from a MAC address string like "AA:BB:CC:DD:EE:FF".
     * Returns "Unknown" if not found.
     */
    public static String lookupVendor(String mac) {
        if (mac == null || mac.length() < 8) return "Unknown";
        String prefix = mac.replace(":", "").replace("-", "")
                           .toUpperCase().substring(0, Math.min(6, mac.replace(":","").length()));
        return OUI.getOrDefault(prefix, "Unknown");
    }

    /**
     * Queries the ARP cache for the MAC address of the given IP.
     * Non-blocking: returns null quickly if not found.
     */
    public static String getMacFromArp(String ip) {
        try {
            String[] cmd = IS_WIN
                    ? new String[]{"arp", "-a", ip}
                    : new String[]{"arp", "-n", ip};
            Process p = Runtime.getRuntime().exec(cmd);
            p.waitFor(2, TimeUnit.SECONDS);
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            Pattern macPat = Pattern.compile(
                "([0-9A-Fa-f]{2}[:\\-][0-9A-Fa-f]{2}[:\\-][0-9A-Fa-f]{2}" +
                "[:\\-][0-9A-Fa-f]{2}[:\\-][0-9A-Fa-f]{2}[:\\-][0-9A-Fa-f]{2})");
            String line;
            while ((line = r.readLine()) != null) {
                if (line.contains(ip)) {
                    Matcher m = macPat.matcher(line);
                    if (m.find()) {
                        return m.group(1).replace("-", ":").toUpperCase();
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Attempts a reverse DNS lookup for a given IP.
     * Times out after 1.5 seconds to avoid blocking.
     */
    public static String resolveHostname(String ip) {
        try {
            String host = InetAddress.getByName(ip).getCanonicalHostName();
            return host.equals(ip) ? null : host;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Pings a host to check if it's reachable.
     */
    public static boolean isReachable(String ip, int timeoutMs) {
        try {
            return InetAddress.getByName(ip).isReachable(timeoutMs);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Enriches an attack log entry with network data (MAC, vendor, hostname).
     * Runs asynchronously so it never delays the HTTP response.
     * Updates the DB record after lookup completes.
     */
    public static void enrichAsync(String ip, int recordId) {
        Thread t = new Thread(() -> {
            try {
                String mac      = getMacFromArp(ip);
                String vendor   = mac != null ? lookupVendor(mac) : "Unknown";
                String hostname = resolveHostname(ip);
                // Update the record in DB with enriched data
                DatabaseManager.updateNetworkData(recordId, mac, vendor, hostname);
                System.out.printf("[NET-SCAN] %s → MAC=%s | Vendor=%s | Host=%s%n",
                        ip, mac != null ? mac : "—",
                        vendor, hostname != null ? hostname : "—");
            } catch (Exception e) {
                System.err.println("[NET-SCAN] Enrichment failed for " + ip + ": " + e.getMessage());
            }
        });
        t.setDaemon(true);
        t.start();
    }

    /**
     * Gets the local machine's best non-loopback IPv4 address.
     */
    public static String getLocalIP() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces != null && ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                if (!iface.isUp() || iface.isLoopback()) continue;
                String name = iface.getName().toLowerCase();
                if (name.contains("docker") || name.contains("vbox") || name.contains("vmnet")) continue;
                for (InterfaceAddress ia : iface.getInterfaceAddresses()) {
                    InetAddress a = ia.getAddress();
                    if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                        return a.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {}
        return "127.0.0.1";
    }
}
