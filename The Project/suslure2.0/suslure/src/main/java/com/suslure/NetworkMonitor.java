package com.suslure;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * NetworkMonitor — Background LAN scanner running every 5 minutes.
 * Discovers every device on the local subnet: IP, MAC, vendor, hostname, type.
 * Results are cached so attack enrichment is instant — no blocking.
 */
public class NetworkMonitor {

    // ── Device data model ──────────────────────────────────────────────
    public static class DeviceInfo {
        public final String  ip, mac, vendor, hostname, deviceType;
        public final boolean isGateway, isUs;

        public DeviceInfo(String ip, String mac, String vendor,
                          String hostname, String deviceType,
                          boolean isGateway, boolean isUs) {
            this.ip         = ip;
            this.mac        = mac       != null ? mac       : "—";
            this.vendor     = vendor    != null ? vendor    : "Unknown";
            this.hostname   = hostname  != null ? hostname  : "(no hostname)";
            this.deviceType = deviceType!= null ? deviceType: "❓ Unknown";
            this.isGateway  = isGateway;
            this.isUs       = isUs;
        }

        /** Compact JSON — no external library needed. */
        public String toJson() {
            return "{\"ip\":\""     + esc(ip)         + "\","
                 + "\"mac\":\""     + esc(mac)         + "\","
                 + "\"vendor\":\""  + esc(vendor)      + "\","
                 + "\"host\":\""    + esc(hostname)    + "\","
                 + "\"type\":\""    + esc(deviceType)  + "\","
                 + "\"gw\":"        + isGateway        + ","
                 + "\"us\":"        + isUs             + "}";
        }

        private static String esc(String s) {
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }

    // ── Cache (updated by background thread) ──────────────────────────
    private static volatile List<DeviceInfo> cachedDevices = Collections.emptyList();
    private static volatile String cachedGateway           = null;
    private static volatile String cachedMyIp              = null;
    private static volatile String cachedNetworkBase       = null;
    private static volatile long   lastScanMs              = 0;
    private static volatile int    scanCount               = 0;

    private static ScheduledExecutorService scheduler;

    // ── Lifecycle ──────────────────────────────────────────────────────
    public static void start() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "NetworkMonitor-BG");
            t.setDaemon(true);
            return t;
        });
        // First scan after 3s startup delay, then every 5 minutes
        scheduler.scheduleAtFixedRate(() -> {
            try { runScan(); }
            catch (Exception e) { System.err.println("[NET-MON] Scan failed: " + e.getMessage()); }
        }, 3, 300, TimeUnit.SECONDS);
        System.out.println("[NET-MON] Background LAN monitor started — scan interval 5 min.");
    }

    // ── Public API ─────────────────────────────────────────────────────
    public static List<DeviceInfo> getAllDevices()         { return cachedDevices; }
    public static String           getGateway()           { return cachedGateway; }
    public static String           getMyIp()              { return cachedMyIp; }
    public static String           getNetworkBase()       { return cachedNetworkBase; }
    public static long             getLastScanMs()        { return lastScanMs; }
    public static int              getScanCount()         { return scanCount; }
    public static int              getDeviceCount()       { return cachedDevices.size(); }

    public static DeviceInfo getDeviceByIp(String ip) {
        if (ip == null) return null;
        for (DeviceInfo d : cachedDevices) if (ip.equals(d.ip)) return d;
        return null;
    }

    /** JSON array of the current cached snapshot — stored in DB per attack. */
    public static String getSnapshotJson() {
        StringBuilder sb = new StringBuilder("[");
        List<DeviceInfo> snap = cachedDevices;
        for (int i = 0; i < snap.size(); i++) {
            sb.append(snap.get(i).toJson());
            if (i < snap.size() - 1) sb.append(",");
        }
        return sb.append("]").toString();
    }

    /** Force an immediate re-scan (e.g. from admin button). */
    public static void triggerScan() {
        if (scheduler != null)
            scheduler.schedule(() -> { try { runScan(); } catch (Exception ignored) {} },
                               0, TimeUnit.SECONDS);
    }

    // ── Core scan ──────────────────────────────────────────────────────
    private static void runScan() throws Exception {
        NetworkInterface iface = getBestInterface();
        if (iface == null) { System.err.println("[NET-MON] No usable network interface."); return; }

        InetAddress myAddr = getIPv4Address(iface);
        if (myAddr == null) { System.err.println("[NET-MON] No IPv4 on interface."); return; }

        String myIp  = myAddr.getHostAddress();
        String base  = myIp.substring(0, myIp.lastIndexOf('.'));   // e.g. "192.168.1"
        String gw    = detectGateway();

        cachedMyIp       = myIp;
        cachedGateway    = gw;
        cachedNetworkBase = base + ".0/24";

        System.out.printf("[NET-MON] Scan #%d starting — subnet %s.0/24 (me=%s, gw=%s)%n",
                scanCount + 1, base, myIp, gw != null ? gw : "unknown");
        long t0 = System.currentTimeMillis();

        // Phase 1: concurrent ping sweep → alive IPs
        Set<String> alive = pingSwipe(base);
        if (gw != null) alive.add(gw);  // gateway may not respond to ICMP

        // Phase 2: wait briefly for OS ARP cache to populate, then read it
        Thread.sleep(400);
        Map<String, String> arpTable = readArpTable();

        // Phase 3: also force ARP probe for hosts that didn't appear
        for (String ip : alive) {
            if (!arpTable.containsKey(ip)) {
                String mac = NetworkScanner.getMacFromArp(ip);
                if (mac != null) arpTable.put(ip, mac);
            }
        }

        // Phase 4: enrich each alive host concurrently
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(alive.size() + 1, 60));
        List<Future<DeviceInfo>> futures = new ArrayList<>();
        for (String ip : alive) {
            final String fip = ip;
            futures.add(pool.submit(() -> buildDeviceInfo(fip, myIp, gw, arpTable)));
        }
        pool.shutdown();
        pool.awaitTermination(25, TimeUnit.SECONDS);

        List<DeviceInfo> devices = new ArrayList<>();
        for (Future<DeviceInfo> f : futures) {
            try { DeviceInfo d = f.get(200, TimeUnit.MILLISECONDS); if (d != null) devices.add(d); }
            catch (Exception ignored) {}
        }

        // Sort by last octet numerically
        devices.sort(Comparator.comparingInt(d -> lastOctet(d.ip)));
        cachedDevices = Collections.unmodifiableList(devices);
        lastScanMs    = System.currentTimeMillis();
        scanCount++;

        System.out.printf("[NET-MON] Scan #%d done — %d devices in %dms%n",
                scanCount, devices.size(), System.currentTimeMillis() - t0);
    }

    private static DeviceInfo buildDeviceInfo(String ip, String myIp,
                                              String gw, Map<String, String> arp) {
        String mac      = arp.get(ip);
        String vendor   = mac != null ? NetworkScanner.lookupVendor(mac) : "Unknown";
        String hostname = resolveHostname(ip);
        boolean isGw    = ip.equals(gw);
        boolean isUs    = ip.equals(myIp);
        String type     = guessDeviceType(ip, hostname, vendor, isGw, isUs);
        return new DeviceInfo(ip, mac, vendor, hostname, type, isGw, isUs);
    }

    // ── Phase 1: Ping sweep ────────────────────────────────────────────
    private static Set<String> pingSwipe(String base) throws InterruptedException {
        Set<String> alive = Collections.synchronizedSet(new TreeSet<>(
                Comparator.comparingInt(NetworkMonitor::lastOctet)));
        ExecutorService pool = Executors.newFixedThreadPool(100);
        CountDownLatch latch = new CountDownLatch(254);

        for (int i = 1; i <= 254; i++) {
            final String host = base + "." + i;
            pool.submit(() -> {
                try {
                    if (InetAddress.getByName(host).isReachable(1200)) alive.add(host);
                } catch (IOException ignored) {}
                finally { latch.countDown(); }
            });
        }
        latch.await(28, TimeUnit.SECONDS);
        pool.shutdownNow();
        return alive;
    }

    // ── Phase 2: ARP table ─────────────────────────────────────────────
    private static Map<String, String> readArpTable() {
        Map<String, String> table = new LinkedHashMap<>();
        boolean isWin = System.getProperty("os.name").toLowerCase().contains("win");

        // Try multiple commands for cross-platform support
        String[][] cmds = isWin
            ? new String[][]{{"cmd", "/c", "arp -a"}}
            : new String[][]{{"/bin/sh", "-c", "arp -a 2>/dev/null"},
                             {"/bin/sh", "-c", "ip neigh show 2>/dev/null"}};

        Pattern ipPat  = Pattern.compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
        Pattern macPat = Pattern.compile(
            "([0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2}" +
            "[:\\-][0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2})");

        for (String[] cmd : cmds) {
            try {
                Process p = Runtime.getRuntime().exec(cmd);
                BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = r.readLine()) != null) {
                    Matcher im = ipPat.matcher(line);
                    Matcher mm = macPat.matcher(line);
                    if (im.find() && mm.find()) {
                        String ip  = im.group(1);
                        String mac = mm.group(1).replace('-', ':').toUpperCase();
                        // Skip broadcast and zero MACs
                        if (!mac.startsWith("FF:") && !mac.equals("00:00:00:00:00:00"))
                            table.putIfAbsent(ip, mac);
                    }
                }
            } catch (Exception ignored) {}
        }
        return table;
    }

    // ── Gateway detection ──────────────────────────────────────────────
    private static String detectGateway() {
        boolean isWin = System.getProperty("os.name").toLowerCase().contains("win");
        try {
            if (isWin) {
                Process p = Runtime.getRuntime().exec(new String[]{"cmd", "/c", "ipconfig"});
                BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.trim().toLowerCase().startsWith("default gateway")) {
                        String[] parts = line.split(":");
                        if (parts.length > 1) {
                            String gw = parts[parts.length - 1].trim();
                            if (gw.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return gw;
                        }
                    }
                }
            } else {
                // Linux/Mac: try `ip route` first
                Process p = Runtime.getRuntime().exec(
                        new String[]{"/bin/sh", "-c", "ip route show default 2>/dev/null"});
                BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.startsWith("default via")) {
                        String[] parts = line.trim().split("\\s+");
                        if (parts.length >= 3) return parts[2];
                    }
                }
                // Fallback: netstat -rn
                p = Runtime.getRuntime().exec(
                        new String[]{"/bin/sh", "-c", "netstat -rn 2>/dev/null | grep '^0\\.0\\.0\\.0'"});
                r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                while ((line = r.readLine()) != null) {
                    String[] cols = line.trim().split("\\s+");
                    if (cols.length >= 2 && cols[1].matches("\\d+\\.\\d+\\.\\d+\\.\\d+"))
                        return cols[1];
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ── Hostname resolution ────────────────────────────────────────────
    private static String resolveHostname(String ip) {
        try {
            ExecutorService ex = Executors.newSingleThreadExecutor();
            Future<String> f = ex.submit(() -> {
                String h = InetAddress.getByName(ip).getCanonicalHostName();
                return h.equals(ip) ? null : h;
            });
            ex.shutdown();
            return f.get(2, TimeUnit.SECONDS);
        } catch (Exception e) { return null; }
    }

    // ── Device type heuristic ──────────────────────────────────────────
    private static String guessDeviceType(String ip, String hostname,
                                          String vendor, boolean isGw, boolean isUs) {
        String h = hostname != null ? hostname.toLowerCase() : "";
        String v = vendor   != null ? vendor.toLowerCase()   : "";

        if (isUs)  return "🖥 This Machine (SUSLURE Host)";
        if (isGw)  return "🌐 Router / Gateway";

        // Vendor-based
        if (v.contains("raspberry"))                           return "🍓 Raspberry Pi";
        if (v.contains("vmware"))                              return "🖥 VMware VM";
        if (v.contains("virtualbox") || v.contains("vbox"))   return "🖥 VirtualBox VM";
        if (v.contains("canon")   || v.contains("epson")
            || v.contains("hp")   || h.contains("print"))     return "🖨 Printer";
        if (v.contains("nintendo"))                            return "🎮 Nintendo Console";
        if (v.contains("sony")    && h.contains("ps"))        return "🎮 PlayStation";
        if (v.contains("amazon")  || h.contains("echo")
            || h.contains("alexa") || h.contains("firetv"))   return "📦 Amazon Device";
        if (v.contains("google")  && (h.contains("chromecast")
            || h.contains("home") || h.contains("nest")))     return "📺 Google Home / Chromecast";
        if (v.contains("apple")   && (h.contains("iphone")
            || h.contains("ipad")))                           return "📱 iPhone / iPad";
        if (v.contains("apple")   && h.contains("macbook"))   return "💻 MacBook";
        if (v.contains("apple")   && h.contains("appletv"))   return "📺 Apple TV";
        if (v.contains("apple"))                               return "🍎 Apple Device";
        if (v.contains("samsung") || v.contains("xiaomi")
            || v.contains("huawei") || v.contains("oneplus")
            || v.contains("oppo")   || v.contains("vivo"))    return "📱 Android Phone";
        if (v.contains("intel")   || v.contains("realtek")
            || v.contains("broadcom") || v.contains("dell")
            || v.contains("lenovo")   || v.contains("asus"))  return "💻 PC / Laptop";
        if (v.contains("tp-link") || v.contains("netgear")
            || v.contains("d-link")   || v.contains("cisco")
            || v.contains("ubiquiti") || v.contains("mikrotik")
            || v.contains("zyxel"))                            return "📡 Network Device";

        // Hostname-based fallback
        if (h.contains("cam") || h.contains("camera"))        return "📷 IP Camera";
        if (h.contains("tv")  || h.contains("smart-tv"))      return "📺 Smart TV";
        if (h.contains("nas") || h.contains("storage"))       return "💾 NAS / Storage";
        if (h.contains("phone") || h.contains("mobile"))      return "📱 Mobile Device";
        if (h.contains("laptop") || h.contains("pc"))         return "💻 PC / Laptop";

        return "❓ Unknown Device";
    }

    // ── Helpers ────────────────────────────────────────────────────────
    private static NetworkInterface getBestInterface() throws Exception {
        NetworkInterface best = null;
        Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
        while (ifaces != null && ifaces.hasMoreElements()) {
            NetworkInterface iface = ifaces.nextElement();
            if (!iface.isUp() || iface.isLoopback() || iface.isVirtual()) continue;
            if (getIPv4Address(iface) == null) continue;
            String name = iface.getName().toLowerCase();
            if (name.contains("docker") || name.contains("vbox") || name.contains("vmnet")) continue;
            best = iface;
            // Prefer physical ethernet/wifi adapters
            if (name.startsWith("eth") || name.startsWith("wlan") || name.startsWith("en")) break;
        }
        return best;
    }

    private static InetAddress getIPv4Address(NetworkInterface iface) {
        for (InterfaceAddress ia : iface.getInterfaceAddresses()) {
            InetAddress a = ia.getAddress();
            if (a instanceof Inet4Address && !a.isLoopbackAddress()) return a;
        }
        return null;
    }

    private static int lastOctet(String ip) {
        try { return Integer.parseInt(ip.substring(ip.lastIndexOf('.') + 1)); }
        catch (Exception e) { return 0; }
    }
}
