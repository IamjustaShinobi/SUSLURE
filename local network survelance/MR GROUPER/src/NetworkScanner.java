import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * NetworkScanner - Comprehensive Local Network Analysis Tool
 *
 * Features:
 *  - Private IP (non-loopback, non-virtual)
 *  - Public IP (via external API)
 *  - Network address & broadcast address
 *  - Subnet mask (dotted & CIDR)
 *  - Default gateway / router IP
 *  - Full /24 subnet scan with hostnames
 *  - ARP cache lookup for MAC addresses
 *  - Concurrent scanning for speed
 */
public class NetworkScanner {

    // ANSI color codes for terminal output
    static final String RESET  = "\u001B[0m";
    static final String BOLD   = "\u001B[1m";
    static final String GREEN  = "\u001B[32m";
    static final String CYAN   = "\u001B[36m";
    static final String YELLOW = "\u001B[33m";
    static final String RED    = "\u001B[31m";
    static final String BLUE   = "\u001B[34m";
    static final String DIM    = "\u001B[2m";

    // OS detection
    static final String OS = System.getProperty("os.name").toLowerCase();
    static final boolean IS_WINDOWS = OS.contains("win");

    public static void main(String[] args) throws Exception {
        printBanner();

        // ── 1. Find best local interface (skip loopback & virtual) ──────────
        NetworkInterface bestIface = getBestInterface();
        if (bestIface == null) {
            System.err.println(RED + "[ERROR] No suitable network interface found." + RESET);
            return;
        }

        InetAddress localAddr = getIPv4Address(bestIface);
        if (localAddr == null) {
            System.err.println(RED + "[ERROR] Could not determine local IPv4 address." + RESET);
            return;
        }

        short prefixLen = getPrefixLength(bestIface, localAddr);
        String subnetMask = cidrToMask(prefixLen);
        String networkAddr = getNetworkAddress(localAddr.getHostAddress(), subnetMask);
        String broadcastAddr = getBroadcastAddress(localAddr.getHostAddress(), subnetMask);
        String subnetBase = localAddr.getHostAddress().substring(0,
                localAddr.getHostAddress().lastIndexOf('.'));

        // ── 2. Display local interface info ──────────────────────────────────
        header("Network Interface");
        info("Interface Name", bestIface.getDisplayName());
        info("Private IP    ", localAddr.getHostAddress());
        info("Subnet Mask   ", subnetMask + "  (/" + prefixLen + ")");
        info("Network Addr  ", networkAddr);
        info("Broadcast Addr", broadcastAddr);

        // ── 3. Gateway ───────────────────────────────────────────────────────
        String gateway = getDefaultGateway();
        info("Default Gateway", gateway != null ? gateway : "Unable to determine");

        // ── 4. Public IP ─────────────────────────────────────────────────────
        header("Internet");
        System.out.print(DIM + "  Fetching public IP..." + RESET + "\r");
        String publicIP = getPublicIP();
        info("Public IP     ", publicIP);

        // ── 5. Subnet Scan ───────────────────────────────────────────────────
        header("Device Discovery  (scanning " + subnetBase + ".1 – " + subnetBase + ".254)");

        // Load ARP cache first for MAC lookup
        Map<String, String> arpTable = getArpTable();

        List<DeviceInfo> found = scanSubnetConcurrent(subnetBase, arpTable);

        // Print results table
        System.out.println();
        System.out.printf(BOLD + "  %-18s %-30s %-20s%n" + RESET, "IP ADDRESS", "HOSTNAME", "MAC ADDRESS");
        System.out.println("  " + "─".repeat(68));

        String myIP = localAddr.getHostAddress();

        for (DeviceInfo d : found) {
            String tag = d.ip.equals(myIP)        ? GREEN  + " ◄ YOU"     + RESET :
                         d.ip.equals(gateway)      ? YELLOW + " ◄ GATEWAY" + RESET : "";
            System.out.printf("  %-18s %-30s %-20s%s%n",
                    CYAN + d.ip + RESET,
                    d.hostname,
                    d.mac != null ? d.mac : DIM + "N/A" + RESET,
                    tag);
        }

        System.out.println();
        System.out.println(BOLD + "  Total devices found: " + GREEN + found.size() + RESET);
        System.out.println();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Interface & IP Utilities
    // ═══════════════════════════════════════════════════════════════════════

    /** Returns the most suitable non-loopback, non-virtual active interface. */
    static NetworkInterface getBestInterface() throws SocketException {
        Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
        NetworkInterface best = null;

        while (ifaces != null && ifaces.hasMoreElements()) {
            NetworkInterface iface = ifaces.nextElement();
            if (!iface.isUp() || iface.isLoopback() || iface.isVirtual()) continue;

            // Prefer interfaces that have a real IPv4 address
            InetAddress addr = getIPv4Address(iface);
            if (addr == null || addr.isLoopbackAddress()) continue;

            // Prefer ethernet/wifi over docker/virtual (heuristic: name check)
            String name = iface.getName().toLowerCase();
            boolean isVirtual = name.contains("docker") || name.contains("vbox")
                    || name.contains("vmnet") || name.contains("loopback");
            if (isVirtual) continue;

            best = iface;
            // Prefer named "eth" or "wlan" or "en0" on Linux/Mac
            if (name.startsWith("eth") || name.startsWith("wlan") || name.startsWith("en")) break;
        }
        return best;
    }

    /** Returns first non-loopback IPv4 address on the given interface. */
    static InetAddress getIPv4Address(NetworkInterface iface) {
        for (InterfaceAddress ia : iface.getInterfaceAddresses()) {
            InetAddress addr = ia.getAddress();
            if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) return addr;
        }
        return null;
    }

    /** Returns prefix length (e.g. 24 for /24) for the interface's IPv4 address. */
    static short getPrefixLength(NetworkInterface iface, InetAddress target) {
        for (InterfaceAddress ia : iface.getInterfaceAddresses()) {
            if (ia.getAddress().equals(target)) return ia.getNetworkPrefixLength();
        }
        return 24; // fallback
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Network Math
    // ═══════════════════════════════════════════════════════════════════════

    /** Convert CIDR prefix to dotted-decimal subnet mask. */
    static String cidrToMask(int prefix) {
        int mask = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix));
        return String.format("%d.%d.%d.%d",
                (mask >> 24) & 0xFF, (mask >> 16) & 0xFF,
                (mask >> 8)  & 0xFF,  mask         & 0xFF);
    }

    /** Compute network address from IP and mask. */
    static String getNetworkAddress(String ip, String mask) {
        try {
            byte[] ipBytes   = InetAddress.getByName(ip).getAddress();
            byte[] maskBytes = InetAddress.getByName(mask).getAddress();
            byte[] net = new byte[4];
            for (int i = 0; i < 4; i++) net[i] = (byte)(ipBytes[i] & maskBytes[i]);
            return InetAddress.getByAddress(net).getHostAddress();
        } catch (Exception e) { return "N/A"; }
    }

    /** Compute broadcast address from IP and mask. */
    static String getBroadcastAddress(String ip, String mask) {
        try {
            byte[] ipBytes   = InetAddress.getByName(ip).getAddress();
            byte[] maskBytes = InetAddress.getByName(mask).getAddress();
            byte[] bcast = new byte[4];
            for (int i = 0; i < 4; i++) bcast[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
            return InetAddress.getByAddress(bcast).getHostAddress();
        } catch (Exception e) { return "N/A"; }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public IP
    // ═══════════════════════════════════════════════════════════════════════

    /** Tries multiple public IP services in order. */
    static String getPublicIP() {
        String[] services = {
            "https://api.ipify.org",
            "https://checkip.amazonaws.com",
            "https://icanhazip.com",
            "https://ifconfig.me/ip"
        };
        for (String url : services) {
            try {
                HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
                con.setConnectTimeout(3000);
                con.setReadTimeout(3000);
                con.setRequestProperty("User-Agent", "Mozilla/5.0");
                try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                    String ip = br.readLine().trim();
                    if (ip.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return ip;
                }
            } catch (Exception ignored) {}
        }
        return RED + "Unavailable" + RESET;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Default Gateway
    // ═══════════════════════════════════════════════════════════════════════

    /** Parses the OS routing table to find the default gateway. */
    static String getDefaultGateway() {
        try {
            String[] cmd = IS_WINDOWS
                ? new String[]{"cmd", "/c", "ipconfig"}
                : new String[]{"/bin/sh", "-c", "ip route show default"};

            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;

            if (IS_WINDOWS) {
                // ipconfig: look for "Default Gateway" line with an actual IP
                while ((line = r.readLine()) != null) {
                    if (line.trim().startsWith("Default Gateway")) {
                        String[] parts = line.split(":");
                        if (parts.length > 1) {
                            String gw = parts[parts.length - 1].trim();
                            if (!gw.isEmpty() && !gw.equals("...")) return gw;
                        }
                    }
                }
            } else {
                // "ip route": "default via 192.168.1.1 dev eth0"
                while ((line = r.readLine()) != null) {
                    if (line.startsWith("default via")) {
                        String[] parts = line.split("\\s+");
                        if (parts.length >= 3) return parts[2];
                    }
                }
                // fallback: netstat -rn
                cmd = new String[]{"/bin/sh", "-c", "netstat -rn 2>/dev/null | grep '^0\\.0\\.0\\.0'"};
                p = Runtime.getRuntime().exec(cmd);
                r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                while ((line = r.readLine()) != null) {
                    String[] cols = line.trim().split("\\s+");
                    if (cols.length >= 2) return cols[1];
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARP Cache (MAC Addresses)
    // ═══════════════════════════════════════════════════════════════════════

    /** Reads the OS ARP table and returns a map of IP → MAC. */
    static Map<String, String> getArpTable() {
        Map<String, String> table = new HashMap<>();
        try {
            String[] cmd = IS_WINDOWS
                ? new String[]{"cmd", "/c", "arp -a"}
                : new String[]{"/bin/sh", "-c", "arp -a 2>/dev/null || ip neigh 2>/dev/null"};

            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;

            while ((line = r.readLine()) != null) {
                // Match IP and MAC from arp output
                // Windows: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
                // Linux:   "router (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] ..."
                String ipMatch = null, macMatch = null;

                // Extract IPv4
                java.util.regex.Matcher m =
                    java.util.regex.Pattern.compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})")
                        .matcher(line);
                if (m.find()) ipMatch = m.group(1);

                // Extract MAC (colon or hyphen separated)
                m = java.util.regex.Pattern.compile(
                        "([0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2}" +
                        "[:\\-][0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2})")
                    .matcher(line);
                if (m.find()) macMatch = m.group(1).replace('-', ':').toUpperCase();

                if (ipMatch != null && macMatch != null) {
                    table.put(ipMatch, macMatch);
                }
            }
        } catch (Exception ignored) {}
        return table;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Subnet Scanner (Concurrent)
    // ═══════════════════════════════════════════════════════════════════════

    static class DeviceInfo implements Comparable<DeviceInfo> {
        String ip, hostname, mac;
        int lastOctet;

        DeviceInfo(String ip, String hostname, String mac) {
            this.ip       = ip;
            this.hostname = hostname;
            this.mac      = mac;
            this.lastOctet = Integer.parseInt(ip.substring(ip.lastIndexOf('.') + 1));
        }

        @Override public int compareTo(DeviceInfo o) { return Integer.compare(this.lastOctet, o.lastOctet); }
    }

    /** Pings all 254 hosts concurrently, resolves hostnames, attaches MACs. */
    static List<DeviceInfo> scanSubnetConcurrent(String base, Map<String, String> arp) {
        int THREADS = 64;
        int TIMEOUT = 1200; // ms

        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        List<Future<DeviceInfo>> futures = new ArrayList<>();
        AtomicInteger scanned = new AtomicInteger(0);

        for (int i = 1; i < 255; i++) {
            final String host = base + "." + i;
            futures.add(pool.submit(() -> {
                try {
                    InetAddress addr = InetAddress.getByName(host);
                    if (addr.isReachable(TIMEOUT)) {
                        // Attempt reverse DNS without blocking too long
                        String hostname = addr.getCanonicalHostName();
                        if (hostname.equals(host)) hostname = DIM + "(no hostname)" + RESET;
                        String mac = arp.getOrDefault(host, null);
                        return new DeviceInfo(host, hostname, mac);
                    }
                } catch (IOException ignored) {}
                finally {
                    int done = scanned.incrementAndGet();
                    if (done % 25 == 0 || done == 254) {
                        System.out.printf(DIM + "  Scanning... %d/254\r" + RESET, done);
                    }
                }
                return null;
            }));
        }

        pool.shutdown();
        try { pool.awaitTermination(60, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}

        List<DeviceInfo> found = new ArrayList<>();
        for (Future<DeviceInfo> f : futures) {
            try {
                DeviceInfo d = f.get();
                if (d != null) found.add(d);
            } catch (Exception ignored) {}
        }

        System.out.print("                              \r"); // clear progress line
        Collections.sort(found);
        return found;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Display Helpers
    // ═══════════════════════════════════════════════════════════════════════

    static void header(String title) {
        System.out.println();
        System.out.println(BOLD + BLUE + "  ╔══ " + title + " " + "═".repeat(Math.max(0, 45 - title.length())) + "╗" + RESET);
    }

    static void info(String label, String value) {
        System.out.printf(BOLD + "  %-16s" + RESET + "  %s%n", label, value);
    }

    static void printBanner() {
        System.out.println(CYAN + BOLD);
        System.out.println("  ███╗   ██╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗");
        System.out.println("  ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║");
        System.out.println("  ██╔██╗ ██║█████╗     ██║       ███████╗██║     ███████║██╔██╗██║");
        System.out.println("  ██║╚██╗██║██╔══╝     ██║       ╚════██║██║     ██╔══██║██║╚████║");
        System.out.println("  ██║ ╚████║███████╗   ██║       ███████║╚██████╗██║  ██║██║ ╚███║");
        System.out.println("  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝");
        System.out.println(RESET + DIM + "                         Network Analysis Tool  v2.0" + RESET);
        System.out.println();
    }
}