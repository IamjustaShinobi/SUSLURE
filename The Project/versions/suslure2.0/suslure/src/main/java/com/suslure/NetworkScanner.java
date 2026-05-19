package com.suslure;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * NetworkScanner — OUI lookup + async attack enrichment.
 * enrichAsync: MAC/hostname (fast) then port scan + network snapshot (slower).
 */
public class NetworkScanner {

    static final boolean IS_WIN =
            System.getProperty("os.name").toLowerCase().contains("win");

    // ── OUI vendor database (varargs helper) ──────────────────────────
    private static final Map<String, String> OUI = new HashMap<>();
    static {
        addOUI("Apple",     "000A27","000393","0017F2","001124","0016CB","001451","001E52","18AF61",
                            "3C2EF9","40A6D9","5417F6","70700D","7C5049","8C2937","A45E60","B09FBA",
                            "C42C03","DC2B2A","F0D1A9","F45C89","F82793","F8A9D0","003065","0050E4");
        addOUI("Samsung",   "002637","103047","18677C","2C8A72","606BBD","74458A","9C3AAF","C07EF5",
                            "D0176A","F0B47B","0C7170","285BEB","4C3C16","843835","98D6BB","A4EBD3");
        addOUI("TP-Link",   "000AEB","1CF6D9","2C3CD2","34E894","64608C","98DAAC","B490A9","E01EDD",
                            "F4F26D","305A3A","44691A","60A4D0","7C8B9F","A0F3C1","DC0BB2","FC7516");
        addOUI("Huawei",    "001882","083FBC","20A680","30452E","48AD08","54516B","70728D","80717A",
                            "90673C","AC853D","C0BFC0","D065CA","E0191C","F4559C","1C1D86","3CB16E");
        addOUI("Xiaomi",    "10D677","28B2BD","38A4ED","58448C","64B473","8CBFA6","98FAE3","F0B429",
                            "001569","3C9D35","74510E","A0860F","B0E235","E4D332","286AB8","FC644F");
        addOUI("Google",    "3C5AB4","48D6D5","54600A","6C5AB5","94EB2C","A47733","D4F57D","F88FCA",
                            "7C1C38","B0C5CA","DC4F22","E0F8A0","84C9B2","68A878","4CFCAA","2CAA8E");
        addOUI("Intel",     "001B21","001DE0","005A04","0021F0","0022FA","40251B","5CF951","64D4DA",
                            "7CEBB4","8C8D28","A4C494","B4B676","D89EF3","F4069D","F8B156","84A9C4");
        addOUI("Microsoft", "001DD8","0025AE","28187B","485073","60451D","7C1E52","BC8385","F03F8B",
                            "C4093E","DC1BAC","88B111","9866A0","2C54CF","54527E","C86000","00155D");
        addOUI("Amazon",    "0C47C9","18742E","34D270","40B4CD","50F5DA","74C246","84D6D0","B47C9C",
                            "CC9EAE","F0272D","680571","6C5697","78E103","A002DC","A43DB0","F0D2F1");
        addOUI("Realtek",   "001B2F","00E04C","040912","4E5534","80003A","C46679","E0D55E","52540B",
                            "08002B","00163E","B83820","C81040","007018","5855CA","00FF37","147D2D");
        addOUI("Cisco",     "000142","000143","001164","0017DF","001D45","001EA6","002155","0023EA",
                            "002690","00277D","0030F2","003094","0050E2","006400","40F4EC","58AC78");
        addOUI("Netgear",   "001B2F","00146C","001E2A","002275","00224B","004096","083E5D","20E52A",
                            "28C68E","30469A","3AB37D","44944E","4CBCA5","6027D2","744401","9C3DCF");
        addOUI("D-Link",    "00179A","001C4A","001CF0","00265A","1CAFF7","28107B","34086E","5CD998",
                            "6045CB","78542E","84C9B2","90F65A","A0AB1B","B8A386","C4A81D","F07D68");
        addOUI("Raspberry", "B827EB","DCA632","E45F01","2CCF67","D83ADD","DC4475");
        addOUI("Ubiquiti",  "00156D","0418D6","044BED","0E0ECE","18E829","24A43C",
                            "44D9E7","68725A","788A20","802AA8","B4FBE4","DC9FDB","F09FC2");
        addOUI("Dell",      "000874","0014D1","001A4B","001E4F","002564","0026B9",
                            "00B0D0","14187C","18A99B","1C40AF","24B6FD","344DEA","5C260A","848F69");
        addOUI("Lenovo",    "000C29","0023AE","005056","0015E9","00216B","002564",
                            "18A905","28D244","3C970E","406C8F","4C7999","50E549","54EEA8","6045CB");
        addOUI("ASUS",      "001A92","002618","086266","0800F4","10BF48","107B44",
                            "1C872C","2C4D54","2C56DC","305A3A","485B39","50465D","54A050","5C514F");
        addOUI("Xiaomi2",   "64B473","6C5987","7023F2","788C54","8CBFA6","98FAE3",
                            "A086C6","AC8766","B0E235","D4970B","D46520","FC644F");
        addOUI("OnePlus",   "94654B","C0CBFC","D4A152");
        addOUI("Motorola",  "000A28","000E6D","005056","24DA9B","286ED4","34BB26",
                            "40B89A","60BFE8","6C40A0","848D26","940087","AC3AA7");
        addOUI("Sony",      "001315","0013A9","001A80","001EE2","002618","003478",
                            "0050F1","101FA8","1C9894","20AA4B","28FD80","3023C6","40B88D","54420B");
        addOUI("LG",        "001C62","001E75","001FA7","002483","0025E5","002676",
                            "0030E4","003E73","006022","006FAC","00AA70","0C4885","14C913","1802D0");
    }

    private static void addOUI(String vendor, String... prefixes) {
        for (String p : prefixes) OUI.put(p, vendor);
    }

    public static String lookupVendor(String mac) {
        if (mac == null || mac.length() < 8) return "Unknown";
        String prefix = mac.replace(":", "").replace("-", "").toUpperCase();
        if (prefix.length() < 6) return "Unknown";
        return OUI.getOrDefault(prefix.substring(0, 6), "Unknown");
    }

    // ── ARP lookup ────────────────────────────────────────────────────
    public static String getMacFromArp(String ip) {
        try {
            String[] cmd = IS_WIN
                    ? new String[]{"arp", "-a", ip}
                    : new String[]{"arp", "-n", ip};
            Process p = Runtime.getRuntime().exec(cmd);
            p.waitFor(2, TimeUnit.SECONDS);
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            Pattern pat = Pattern.compile(
                "([0-9A-Fa-f]{2}[:\\-][0-9A-Fa-f]{2}[:\\-][0-9A-Fa-f]{2}" +
                "[:\\-][0-9A-Fa-f]{2}[:\\-][0-9A-Fa-f]{2}[:\\-][0-9A-Fa-f]{2})");
            String line;
            while ((line = r.readLine()) != null) {
                if (line.contains(ip)) {
                    Matcher m = pat.matcher(line);
                    if (m.find()) return m.group(1).replace("-", ":").toUpperCase();
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ── Hostname ──────────────────────────────────────────────────────
    public static String resolveHostname(String ip) {
        try {
            String h = InetAddress.getByName(ip).getCanonicalHostName();
            return h.equals(ip) ? null : h;
        } catch (Exception e) { return null; }
    }

    public static boolean isReachable(String ip, int ms) {
        try { return InetAddress.getByName(ip).isReachable(ms); }
        catch (Exception e) { return false; }
    }

    // ── Full async enrichment ─────────────────────────────────────────
    public static void enrichAsync(String ip, int recordId) {
        Thread t = new Thread(() -> {
            try {
                // Fast: MAC + vendor + hostname
                String mac      = getMacFromArp(ip);
                String vendor   = mac != null ? lookupVendor(mac) : "Unknown";
                String hostname = resolveHostname(ip);

                // Get cached network snapshot (instant — NetworkMonitor already ran)
                String snapshot = NetworkMonitor.getSnapshotJson();

                // Port scan (LAN = fast, ~2s total)
                String ports = AttackerProfiler.scanPorts(ip);

                DatabaseManager.updateEnrichment(recordId, mac, vendor, hostname, ports, snapshot);

                System.out.printf("[ENRICH] id=%-4d | %s → MAC=%s | %s | Ports: %s%n",
                        recordId, ip,
                        mac != null ? mac : "—",
                        vendor,
                        ports.length() > 40 ? ports.substring(0, 40) + "…" : ports);

            } catch (Exception e) {
                System.err.println("[ENRICH] Failed for " + ip + ": " + e.getMessage());
            }
        }, "Enricher-" + recordId);
        t.setDaemon(true);
        t.start();
    }

    // ── Local IP ──────────────────────────────────────────────────────
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
                    if (a instanceof Inet4Address && !a.isLoopbackAddress()) return a.getHostAddress();
                }
            }
        } catch (Exception ignored) {}
        return "127.0.0.1";
    }
}
