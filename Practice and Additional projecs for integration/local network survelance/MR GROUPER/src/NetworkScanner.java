import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.*;

/**
 * NetworkScanner v3.0
 * ────────────────────────────────────────────────────────────────────
 *  - Private / Public / Network / Gateway / Broadcast IPs
 *  - Subnet mask (dotted + CIDR)
 *  - Full /24 concurrent subnet scan (100 threads)
 *  - Post-scan ARP refresh → accurate MACs for ALL devices
 *  - Built-in OUI vendor database (700+ prefixes, no internet needed)
 *  - Reverse-DNS hostname resolution with 2s timeout
 *  - Device type detection (Router/Phone/PC/Printer/IoT/etc.)
 * ────────────────────────────────────────────────────────────────────
 *  Compile : javac NetworkScanner.java
 *  Run     : sudo java NetworkScanner   (sudo needed for raw ARP on Linux)
 */
public class NetworkScanner {

    // ── ANSI ────────────────────────────────────────────────────────────────
    static final String R  = "\u001B[0m";
    static final String B  = "\u001B[1m";
    static final String D  = "\u001B[2m";
    static final String GR = "\u001B[32m";
    static final String CY = "\u001B[36m";
    static final String YE = "\u001B[33m";
    static final String RE = "\u001B[31m";
    static final String BL = "\u001B[34m";
    static final String MA = "\u001B[35m";
    static final String WH = "\u001B[97m";

    static final String OS_NAME = System.getProperty("os.name").toLowerCase();
    static final boolean IS_WIN = OS_NAME.contains("win");

    // ═══════════════════════════════════════════════════════════════════════
    // OUI Database — MAC prefix (6 uppercase hex chars) → Vendor name
    // ═══════════════════════════════════════════════════════════════════════
    static final Map<String, String> OUI = new HashMap<>();
    static {
        // Apple
        String[] apple = {
            "000A27","000393","0017F2","001124","0016CB","001451","001E52","001FF3",
            "002312","002500","0026B9","0026BB","003065","0050E4","007040","00C610",
            "040CCE","049269","04F7E4","086698","0C3E9F","0C7429","0CD746","10411A",
            "10DDB1","146090","1499E2","18AF61","18E7F4","1C1AC0","1C9179","200236",
            "2452AB","28CFE9","28E02C","2C1F23","2C3361","34159E","34A395","380F4A",
            "3C0754","3C2EF9","40A6D9","40D32D","44D884","485B39","48D705","4C7C5F",
            "4C8D79","502EAD","5417F6","544E90","58B035","60334B","60D9C7","60F81D",
            "6C4008","6C709F","6CF049","70700D","70CD60","7831C1","7C5049","7C6D62",
            "7CF05F","80006E","80929F","8863DF","8C2937","8C7B9D","8C8590","901B0E",
            "907240","90B0ED","98B8E3","98D6BB","9CF387","A01726","A02BB8","A0999B",
            "A45E60","A4B197","A4C361","A4D18C","A81B5A","A8968A","A8BBCF","AC3C0B",
            "AC7F3E","ACE433","B09FBA","B418D1","B4F0AB","BC3BAF","BC4CC4","BC9FEF",
            "C06599","C0847A","C0CECD","C42C03","C8BCC8","C8D083","C8E0EB","CC08E0",
            "D0254E","D0A637","D4619D","D49A20","D8004D","D88196","DC2B2A","DC2B61",
            "E06995","E0B9BA","E4CE8F","E8040B","E880F1","EC3586","F02475","F0B479",
            "F0D1A9","F40F24","F45C89","F49FF3","F82793","F8A9D0","FC253F","FCE998"
        };
        for (String o : apple) OUI.put(o, "Apple");

        // Samsung
        String[] samsung = {
            "002637","08FC88","0C7170","103047","1452A7","14568E","18677C","1C62B8",
            "1C66AA","200DB0","24920E","24DBB1","28987B","2C4401","2C8A72","30C7AE",
            "3452CB","34BE00","380A94","3C62FE","3C6200","40169F","400128","4434EA",
            "482C6A","4C3C16","506BC5","509EA7","5859E8","5C3C27","606BBD","60A10A",
            "6480DA","64B310","6C2F2C","6CB7F4","704161","74458A","784BF5","7C1C4E",
            "7C6196","80657C","84119E","8425DB","845127","88329B","88D544","90180D",
            "905716","9491AA","9C3AAF","9C65F9","A07591","A4EBD3","A8F274","AC36DD",
            "B047BF","B4EF39","B4F6E3","C07EF5","C440D0","C44619","C46AB7","C4731E",
            "C8A823","CC07AB","D0176A","D063B4","D0DFAA","D425F7","D4E8B2","D807B6",
            "D8CABA","DC7144","E4128B","E47CF9","E4E0C5","E8039A","EC107B","ECF400",
            "F05A77","F015B9","F06BCA","F49B8D","F8042E","FC19DE"
        };
        for (String o : samsung) OUI.put(o, "Samsung");

        // TP-Link
        String[] tplink = {
            "000AEB","001D0F","005452","0414DC","080289","10FED7","1062EB","14CC20",
            "1CF6D9","200BC5","2C3CD2","303219","34E894","38D547","3C84FF","44691A",
            "4C5E0C","5400E4","547EC3","5C628B","602AD0","60A4D0","64608C","6465E3",
            "6C5AB0","74DA38","78A1C5","7C8B9F","94D9B3","98DAAC","9C5316","A0F3C1",
            "B0487A","B09DC7","B490A9","C46E1F","D8EB97","DC0BB2","E01EDD","E894F6",
            "EC172F","ECADD8","F0A731","F4F26D","F8C091","FC7516"
        };
        for (String o : tplink) OUI.put(o, "TP-Link");

        // Huawei
        String[] huawei = {
            "001882","0019E0","001ECA","003048","0090E8","04021F","04BD70","083FBC",
            "0C37DC","0C96BF","10C61F","1416A8","1476AB","18C582","1C1D86","1C8E5C",
            "20A680","204E7F","20F3A3","240995","243C10","28313A","28FEE7","2C9B80",
            "3062EA","30452E","30A6D6","34B354","380B40","3CB16E","44C346","48AD08",
            "4CAC0A","4CBB58","4CE17A","50010E","500285","54516B","58605F","5C7D5E",
            "60DE44","688A08","6C8D4F","6CB3DF","70728D","70A8E3","74A063","786A89",
            "78D752","7CE8D0","7CF711","80717A","80B686","8C34FD","8CC8CD","90673C",
            "94DBB2","980143","9C74AE","A09C17","A44C29","A47174","AC853D","B02C02",
            "B4430D","B4CD27","B8BC1B","BC3EA3","C0BFC0","C43DEA","C4072F","C4F081",
            "C8D15E","CCCC81","D065CA","D0FF98","D4124B","D46AA8","D4F9A1","D880EB",
            "DC727C","E0191C","E0247F","E42B34","E4F1B5","E8088B","E88D28","EC23FD",
            "ECEFD3","F4559C","F48E92","F80113","F8E811","FC48EF"
        };
        for (String o : huawei) OUI.put(o, "Huawei");

        // Xiaomi
        String[] xiaomi = {
            "001569","0C1DAF","10D677","14F65A","283B96","2C5BB8","3480B3","38A4ED",
            "3C9D35","58448C","5CB021","64B473","6C5F1D","74510E","7851F6","7CFBC8",
            "8CBFA6","98FAE3","9C1421","A0860F","AC2374","B0E235","C09A60","D4970B",
            "E4D332","F0B429","F48B32","F8A45F","FC644F"
        };
        for (String o : xiaomi) OUI.put(o, "Xiaomi");

        // Google
        String[] google = {
            "3C5AB4","48D6D5","54600A","6C5AB5","7C1C38","94EB2C",
            "A47733","B0C5CA","D4F57D","DC4F22","F88FCA"
        };
        for (String o : google) OUI.put(o, "Google");

        // Amazon
        String[] amazon = {
            "0C47C9","18742E","34D270","40B4CD","44650D","50F5DA","680571","6C5697",
            "74C246","78E103","84D6D0","A002DC","A43DB0","AC63BE","B47C9C","B4A9FC",
            "CC9EAE","D0B224","E894F6","F0272D","F0D2F1","FC65DE"
        };
        for (String o : amazon) OUI.put(o, "Amazon");

        // Microsoft
        String[] microsoft = {
            "001DD8","0025AE","28187B","2C54CF","485073","54527E","60451D","7C1E52",
            "88B111","9866A0","BC8385","C4093E","C86000","DC1BAC","F03F8B"
        };
        for (String o : microsoft) OUI.put(o, "Microsoft");

        // Intel (Wi-Fi / NIC)
        String[] intel = {
            "001B21","001DE0","001E64","001E67","00215A","002170","0022FA","002369",
            "0024D6","40251B","44850F","5CF951","60676D","64D4DA","68059C","6CF6D9",
            "7CEBB4","80864F","84A9C4","8C8D28","905E7B","98C3B9","A4C494","A8A1D4",
            "AC9E17","B4B676","C4C729","D89EF3","E44B97","E8D8D1","F4069D","F8B156"
        };
        for (String o : intel) OUI.put(o, "Intel");

        // Realtek
        String[] realtek = {
            "001B2F","00E04C","040912","4E5534","80003A","C46679","E0D55E"
        };
        for (String o : realtek) OUI.put(o, "Realtek");

        // Broadcom
        String[] broadcom = {
            "000AF7","001018","043D98","0828A3","286AB8","34EF44","4417B8",
            "54AE27","7C1C39","904CE5","B8CA3A"
        };
        for (String o : broadcom) OUI.put(o, "Broadcom");

        // Qualcomm
        String[] qualcomm = {"002637","005356","381885","5C68AC","DC4400"};
        for (String o : qualcomm) OUI.put(o, "Qualcomm");

        // OnePlus
        String[] oneplus = {
            "0827CE","209E5D","3CFBD5","6403A4","7C6790","A06BBA","B4F135","CC0278"
        };
        for (String o : oneplus) OUI.put(o, "OnePlus");

        // Sony
        String[] sony = {
            "001315","0013A9","002191","0024BE","0026CC","001086","30104B","3CF872",
            "40B891","5476E5","70E3B6","9802D8","A8E063","B4524B","BC305B",
            "C0385F","D0E73B","F8D0AC"
        };
        for (String o : sony) OUI.put(o, "Sony");

        // Netgear
        String[] netgear = {
            "000E7F","001B2F","001E2A","00224A","002275","00265A","200E52","28C68E",
            "2CB05D","30469A","44940C","587D09","60A4B7","6CB0CE","744401",
            "84406F","9C3426","A040A0","C03F0E","C43DC7","E091F5"
        };
        for (String o : netgear) OUI.put(o, "Netgear");

        // Asus
        String[] asus = {
            "001A92","002354","0090A9","10BF48","1CB72C","2C4D54","40167E","50465D",
            "54BEF7","60A44C","700BC0","74D02B","7C10C9","88D7F6","90E6BA",
            "A8F94B","BC9741","C86FAD","E0CB4E","F832E4"
        };
        for (String o : asus) OUI.put(o, "Asus");

        // D-Link
        String[] dlink = {
            "001195","001B11","001CF0","0021E8","00224F","1C7EE5","282CAB","2CAB25",
            "34A84E","48EE0C","5CF4AB","6045CB","78542E","90948E","BCEE7B",
            "C8BE19","D0608C","F09FC2"
        };
        for (String o : dlink) OUI.put(o, "D-Link");

        // Linksys
        String[] linksys = {
            "000C41","000E08","001217","00185A","00226B","20AA4B","48F8B3","C0C1C0"
        };
        for (String o : linksys) OUI.put(o, "Linksys");

        // Cisco
        String[] cisco = {
            "000142","000143","000144","00017A","00012E","001B54","001C57","001C58",
            "004096","006476","009065","00902A","00D0FF","2C3124","3C0830","58AC78",
            "84783C","8CB64F","B0FAEB","CC46D6","D4AD71","E84F25","F44E05"
        };
        for (String o : cisco) OUI.put(o, "Cisco");

        // Ubiquiti
        String[] ubiquiti = {
            "002722","0418D6","044155","245A4C","44D9E7","687278","788A20","80255A",
            "94B40A","A802A0","B4FBE4","DCEF09","E063DA","F468A8"
        };
        for (String o : ubiquiti) OUI.put(o, "Ubiquiti");

        // MikroTik
        String[] mikrotik = {
            "000C42","18FD74","2CC8D0","6C3B6B","74DA88","B8692F","CC2D83","D4CA6D","DC2C6E","E48D8C"
        };
        for (String o : mikrotik) OUI.put(o, "MikroTik");

        // HP (printers + PCs)
        String[] hp = {
            "001B78","001C2E","001E0B","00237D","002564","003048","00508B","003558",
            "0017A4","001A4B","144FAE","1C977A","288023","3CD92B","40B034","50657A",
            "5CD28B","6CA876","706D15","74E6E2","784B87","80CE62","98E7F4","A0D3C1",
            "A4CA4B","B499BA","C4346B","D4850D","D8B190","E4AEA1","F0921C"
        };
        for (String o : hp) OUI.put(o, "HP");

        // Canon
        String[] canon = {
            "002AC8","00602C","087C63","1058F3","2CC2D9","40B395","4400F1","4CAD97",
            "5C0D59","6039D5","6415A7","6C0E0D","90B11C","98B0AF","A0168C",
            "A813DA","BCF1F2","C05627","C0EEA6","CC8FF5","D00EDC","DC0D30","E44CE0"
        };
        for (String o : canon) OUI.put(o, "Canon");

        // Epson
        String[] epson = {
            "0026AB","04E36B","0CB8AE","4C5BDB","646CB3","6C72E7","8C8C4B",
            "98D3E1","A83E86","B0C745","C03EBA","C489F0"
        };
        for (String o : epson) OUI.put(o, "Epson");

        // Raspberry Pi Foundation
        String[] rpi = {"B827EB","DCA632","E45F01"};
        for (String o : rpi) OUI.put(o, "Raspberry Pi");

        // VMware / VirtualBox
        OUI.put("000C29", "VMware");
        OUI.put("000569", "VMware");
        OUI.put("001C14", "VMware");
        OUI.put("080027", "VirtualBox");

        // LG Electronics
        String[] lg = {
            "001E75","006047","008765","002483","0019A1","0026E2","3C6200",
            "58FB84","700541","78A873","A81374","B4E621","CC2D8C","F81A67"
        };
        for (String o : lg) OUI.put(o, "LG");

        // Nintendo
        String[] nintendo = {"002709","0009BF","000FB6","001FC5","A4C0E1","98B6E9","8CCDE8"};
        for (String o : nintendo) OUI.put(o, "Nintendo");

        // Motorola
        String[] moto = {
            "000A28","000E6D","001374","001A6B","001DB3","002128","002312","00259C",
            "004096","00A04B","5C5188","5C935A","68C44D","78A755","C47D4F","E49AB5"
        };
        for (String o : moto) OUI.put(o, "Motorola");

        // Lenovo
        String[] lenovo = {
            "000732","001A6B","002590","002631","00906E","18A905","485B39","4CF95D",
            "54EE75","5CE0C5","706655","74E50B","84372F","8C69D3","98BE94","A4027B",
            "B8599F","C4774D","E8D8D1","F8BC12","FC7774"
        };
        for (String o : lenovo) OUI.put(o, "Lenovo");

        // Dell
        String[] dell = {
            "000874","001143","001422","0017C8","001EC9","00215B","002428","002564",
            "00265B","1418D4","18A99B","1C40AF","1CE6C7","204747","243D91","2CD05A",
            "34480A","3C2C30","3CF812","444553","483B38","5CF9DD","6C2B59","788CB5",
            "848D96","98901A","9CAF CA","B083FE","BCEE7B","C81F66","D067E5","D89EF3",
            "F0761C","F4E9D4","F48E92"
        };
        for (String o : dell) OUI.put(o, "Dell");

        // Oppo / Realme / OnePlus (BBK group)
        String[] oppo = {
            "00BEB3","18D041","1C7789","284C61","402CF4","4872FA","70D927","7CDFE0",
            "8C1AB5","90E6BA","A0CBD5","AC61EA","C4A880","D09420","D83678","E8D8D1"
        };
        for (String o : oppo) OUI.put(o, "Oppo/Realme");

        // Vivo (BBK)
        String[] vivo = {"002637","0090A9","0CF7D3","20A571","28B2BD","3C3C8F","4C1AB3","5C313E","E896A5"};
        for (String o : vivo) OUI.put(o, "Vivo");

        // ZTE
        String[] zte = {
            "000739","001A2C","000096","001626","001D10","001E8F","0026ED","005047",
            "08183F","0C8268","2C957F","3444C3","48CC2D","4C7201","6415A7","6C8E8C",
            "7C4017","7C7B8B","88299C","A4A600","B404FE","B8D274","BC1401","CC9E00",
            "D07220","DC1A03","E0AA96","E804A8","EC1726","F408D7"
        };
        for (String o : zte) OUI.put(o, "ZTE");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Data Model
    // ═══════════════════════════════════════════════════════════════════════
    static class DeviceInfo implements Comparable<DeviceInfo> {
        String ip, hostname, mac, vendor, deviceType;
        int lastOctet;
        DeviceInfo(String ip, String hostname, String mac, String vendor, String deviceType) {
            this.ip = ip; this.hostname = hostname; this.mac = mac;
            this.vendor = vendor; this.deviceType = deviceType;
            this.lastOctet = Integer.parseInt(ip.substring(ip.lastIndexOf('.') + 1));
        }
        @Override public int compareTo(DeviceInfo o) { return Integer.compare(lastOctet, o.lastOctet); }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MAIN
    // ═══════════════════════════════════════════════════════════════════════
    public static void main(String[] args) throws Exception {
        printBanner();

        NetworkInterface iface = getBestInterface();
        if (iface == null) { System.err.println(RE + "[ERROR] No network interface found." + R); return; }

        InetAddress localAddr = getIPv4Address(iface);
        if (localAddr == null) { System.err.println(RE + "[ERROR] No IPv4 address found." + R); return; }

        short  prefix  = getPrefixLength(iface, localAddr);
        String mask    = cidrToMask(prefix);
        String network = getNetworkAddress(localAddr.getHostAddress(), mask);
        String base    = localAddr.getHostAddress().substring(0, localAddr.getHostAddress().lastIndexOf('.'));
        String myIP    = localAddr.getHostAddress();
        String myMac   = getOwnMac(iface);

        // ── Interface / Network Info ───────────────────────────────────────
        header("Network Interface");
        info("Interface   ", iface.getDisplayName());
        info("Private IP  ", CY + B + myIP + R);
        info("Own MAC     ", myMac != null ? CY + myMac + R + "  " + D + "("+lookupVendor(myMac, "Unknown")+")" + R : D + "N/A" + R);
        info("Subnet Mask ", YE + mask + R + D + "  (/" + prefix + ")" + R);
        info("Network Addr", network);
        info("Broadcast   ", base + ".255");

        header("Gateway / Router");
        String gateway = getDefaultGateway();
        info("Gateway IP  ", gateway != null ? YE + B + gateway + R : RE + "Could not determine" + R);

        header("Internet");
        System.out.print(D + "  Fetching public IP ..." + R + "\r");
        String publicIP = getPublicIP();
        info("Public IP   ", GR + B + publicIP + R);

        // ── Scan ──────────────────────────────────────────────────────────
        header("Device Discovery  [ " + base + ".1 → " + base + ".254 ]");
        System.out.println();

        // PHASE 1 — Ping sweep (populates OS ARP cache)
        Set<String> alive = pingPhase(base);

        // PHASE 2 — Wait briefly for ARP replies, then read ARP table
        System.out.print(D + "  Refreshing ARP table ..." + R + "          \r");
        Thread.sleep(400);
        Map<String, String> arpTable = getArpTable();

        // PHASE 3 — Enrich (hostname + MAC + vendor + device type)
        System.out.print(D + "  Resolving hostnames ..." + R + "           \r");
        List<DeviceInfo> devices = enrichDevices(alive, arpTable, gateway, myIP);
        System.out.print("                                              \r");

        // ── Results Table ─────────────────────────────────────────────────
        System.out.println();
        int macCount  = (int) devices.stream().filter(d -> d.mac     != null).count();
        int hostCount = (int) devices.stream().filter(d -> !d.hostname.contains("no hostname")).count();

        String hdr = String.format(B + WH +
                "  %-4s  %-17s  %-26s  %-19s  %-22s  %-14s" + R,
                "#", "IP ADDRESS", "HOSTNAME", "MAC ADDRESS", "VENDOR", "TYPE");
        System.out.println(hdr);
        System.out.println("  " + "─".repeat(108));

        int idx = 1;
        for (DeviceInfo d : devices) {
            String ipColor = CY;
            String rowTag  = "";
            if (d.ip.equals(myIP))       { ipColor = GR; rowTag = GR + B + " ◄ YOU"    + R; }
            else if (d.ip.equals(gateway)) { ipColor = YE; rowTag = YE + B + " ◄ ROUTER" + R; }

            String macStr    = d.mac    != null ? d.mac              : D + "—" + R;
            String vendorStr = d.vendor != null ? MA + d.vendor + R  : D + "Unknown" + R;

            System.out.printf("  %-4s  %-26s  %-35s  %-28s  %-31s  %-14s%s%n",
                    D + idx++ + R,
                    ipColor + padR(d.ip, 17) + R,
                    padR(d.hostname, 26),
                    padR(macStr, 19),
                    padR(vendorStr, 22),
                    d.deviceType,
                    rowTag);
        }

        System.out.println("  " + "─".repeat(108));
        System.out.println();
        System.out.printf(B + "  Devices found   : " + R + GR + B + "%d%n" + R, devices.size());
        System.out.printf(B + "  With MAC        : " + R + "%d / %d%n",   macCount,  devices.size());
        System.out.printf(B + "  With hostname   : " + R + "%d / %d%n%n", hostCount, devices.size());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 1 — Concurrent Ping Sweep
    // ═══════════════════════════════════════════════════════════════════════
    static Set<String> pingPhase(String base) throws InterruptedException {
        final int THREADS = 100, TIMEOUT = 1500;
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        AtomicInteger done = new AtomicInteger(0);
        Set<String> alive = Collections.synchronizedSet(new TreeSet<>());

        for (int i = 1; i < 255; i++) {
            final String host = base + "." + i;
            pool.submit(() -> {
                try {
                    if (InetAddress.getByName(host).isReachable(TIMEOUT)) alive.add(host);
                } catch (IOException ignored) {}
                int n = done.incrementAndGet();
                if (n % 30 == 0 || n == 254)
                    System.out.printf(D + "  Pinging %s.* ... %3d/254  found: %d\r" + R,
                            base, n, alive.size());
            });
        }
        pool.shutdown();
        pool.awaitTermination(30, TimeUnit.SECONDS);
        System.out.printf("  Ping complete. %d host(s) responded.                  %n", alive.size());
        return alive;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 3 — Enrich Each Host
    // ═══════════════════════════════════════════════════════════════════════
    static List<DeviceInfo> enrichDevices(Set<String> ips, Map<String, String> arp,
                                          String gateway, String myIP) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(50);
        List<Future<DeviceInfo>> futures = new ArrayList<>();

        for (String ip : ips) {
            futures.add(pool.submit(() -> {
                String hostname = resolveHostname(ip);
                String mac      = arp.getOrDefault(ip, null);
                String vendor   = lookupVendor(mac, null);
                String type     = guessType(ip, hostname, vendor, ip.equals(gateway));
                return new DeviceInfo(ip, hostname, mac, vendor, type);
            }));
        }

        pool.shutdown();
        pool.awaitTermination(20, TimeUnit.SECONDS);

        List<DeviceInfo> list = new ArrayList<>();
        for (Future<DeviceInfo> f : futures) {
            try { DeviceInfo d = f.get(); if (d != null) list.add(d); } catch (Exception ignored) {}
        }
        Collections.sort(list);
        return list;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Hostname Resolution (max 2s)
    // ═══════════════════════════════════════════════════════════════════════
    static String resolveHostname(String ip) {
        ExecutorService ex = Executors.newSingleThreadExecutor();
        Future<String> f = ex.submit(() -> {
            String h = InetAddress.getByName(ip).getCanonicalHostName();
            return h.equals(ip) ? null : h;
        });
        ex.shutdown();
        try {
            String h = f.get(2, TimeUnit.SECONDS);
            return h != null ? h : D + "(no hostname)" + R;
        } catch (Exception e) {
            f.cancel(true);
            return D + "(no hostname)" + R;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // OUI / Vendor Lookup
    // ═══════════════════════════════════════════════════════════════════════
    static String lookupVendor(String mac, String fallback) {
        if (mac == null || mac.length() < 8) return fallback;
        String oui = mac.replaceAll("[:\\-\\.]", "").toUpperCase();
        if (oui.length() < 6) return fallback;
        return OUI.getOrDefault(oui.substring(0, 6), fallback);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Device Type Guesser
    // ═══════════════════════════════════════════════════════════════════════
    static String guessType(String ip, String hostname, String vendor, boolean isGateway) {
        String h = hostname != null ? hostname.toLowerCase() : "";
        String v = vendor   != null ? vendor.toLowerCase()   : "";

        if (isGateway)                                           return "🌐 Router";
        if (v.contains("raspberry"))                             return "🍓 Pi";
        if (v.contains("vmware") || v.contains("virtualbox"))   return "🖥  VM";
        if (v.contains("canon") || v.contains("epson")
         || h.contains("print") || h.contains("printer"))        return "🖨  Printer";
        if (v.contains("hp") && (h.contains("print")
         || h.contains("laserjet") || h.contains("officejet"))) return "🖨  Printer";
        if (v.contains("nintendo"))                              return "🎮 Nintendo";
        if (v.contains("sony") && h.contains("ps"))             return "🎮 PlayStation";
        if (v.contains("microsoft") && h.contains("xbox"))      return "🎮 Xbox";
        if (v.contains("sony"))                                  return "📺 Sony";
        if (v.contains("amazon") || h.contains("echo")
         || h.contains("alexa") || h.contains("kindle"))        return "📦 Amazon";
        if (v.contains("google") && (h.contains("chromecast")
         || h.contains("home")))                                 return "📺 Chromecast";
        if (v.contains("google"))                                return "🔵 Google";
        if (v.contains("apple") && (h.contains("iphone")
         || h.contains("ipad")))                                 return "📱 iPhone/iPad";
        if (v.contains("apple") && h.contains("macbook"))       return "💻 MacBook";
        if (v.contains("apple") && h.contains("appletv"))       return "📺 Apple TV";
        if (v.contains("apple"))                                 return "🍎 Apple";
        if ((v.contains("samsung") || v.contains("xiaomi")
         || v.contains("huawei") || v.contains("oneplus")
         || v.contains("oppo") || v.contains("vivo")
         || v.contains("motorola") || v.contains("lg"))
         && (h.contains("android") || h.contains("sm-")
         || h.contains("galaxy") || h.contains("phone")))       return "📱 Android";
        if (v.contains("samsung"))                               return "📺 Samsung";
        if (v.contains("xiaomi") || v.contains("qualcomm"))     return "📱 Android";
        if (v.contains("intel") || v.contains("realtek")
         || v.contains("broadcom"))                              return "💻 PC/Laptop";
        if (v.contains("dell") || v.contains("lenovo")
         || v.contains("hp") || v.contains("asus"))             return "💻 PC/Laptop";
        if (v.contains("tp-link") || v.contains("netgear")
         || v.contains("d-link") || v.contains("linksys")
         || v.contains("cisco") || v.contains("ubiquiti")
         || v.contains("mikrotik"))                              return "📡 Network AP";
        if (h.contains("cam") || h.contains("camera")
         || h.contains("ipc") || h.contains("dvr"))             return "📷 Camera";
        if (h.contains("tv") || h.contains("smart-tv")
         || h.contains("roku") || h.contains("firestick"))      return "📺 Smart TV";
        if (h.contains("phone") || h.contains("mobile"))        return "📱 Mobile";
        if (h.contains("router") || h.contains("gateway"))      return "🌐 Router";
        if (h.contains("desktop") || h.contains("pc-"))         return "🖥  Desktop";
        if (h.contains("laptop") || h.contains("book"))         return "💻 Laptop";
        return "❓ Unknown";
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARP Table — read AFTER ping sweep so cache is warm
    // ═══════════════════════════════════════════════════════════════════════
    static Map<String, String> getArpTable() {
        Map<String, String> table = new HashMap<>();
        Pattern ipPat  = Pattern.compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
        Pattern macPat = Pattern.compile(
                "([0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2}" +
                "[:\\-][0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2}[:\\-][0-9a-fA-F]{2})");

        String[][] cmds = IS_WIN
                ? new String[][]{{"cmd", "/c", "arp -a"}}
                : new String[][]{{"/bin/sh", "-c", "arp -a 2>/dev/null"},
                                 {"/bin/sh", "-c", "ip neigh show 2>/dev/null"}};

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
                        // Skip broadcast / invalid entries
                        if (!mac.startsWith("FF:") && !mac.equals("00:00:00:00:00:00"))
                            table.putIfAbsent(ip, mac);
                    }
                }
            } catch (Exception ignored) {}
        }
        return table;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Network Utilities
    // ═══════════════════════════════════════════════════════════════════════
    static NetworkInterface getBestInterface() throws SocketException {
        Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
        NetworkInterface best = null;
        while (ifaces != null && ifaces.hasMoreElements()) {
            NetworkInterface iface = ifaces.nextElement();
            if (!iface.isUp() || iface.isLoopback() || iface.isVirtual()) continue;
            InetAddress addr = getIPv4Address(iface);
            if (addr == null || addr.isLoopbackAddress()) continue;
            String name = iface.getName().toLowerCase();
            if (name.contains("docker") || name.contains("vbox") || name.contains("vmnet")) continue;
            best = iface;
            if (name.startsWith("eth") || name.startsWith("wlan") || name.startsWith("en")) break;
        }
        return best;
    }

    static InetAddress getIPv4Address(NetworkInterface iface) {
        for (InterfaceAddress ia : iface.getInterfaceAddresses()) {
            InetAddress a = ia.getAddress();
            if (a instanceof Inet4Address && !a.isLoopbackAddress()) return a;
        }
        return null;
    }

    static short getPrefixLength(NetworkInterface iface, InetAddress target) {
        for (InterfaceAddress ia : iface.getInterfaceAddresses())
            if (ia.getAddress().equals(target)) return ia.getNetworkPrefixLength();
        return 24;
    }

    static String cidrToMask(int prefix) {
        int m = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix));
        return String.format("%d.%d.%d.%d", (m>>24)&0xFF, (m>>16)&0xFF, (m>>8)&0xFF, m&0xFF);
    }

    static String getNetworkAddress(String ip, String mask) {
        try {
            byte[] i = InetAddress.getByName(ip).getAddress();
            byte[] m = InetAddress.getByName(mask).getAddress();
            byte[] n = new byte[4];
            for (int x = 0; x < 4; x++) n[x] = (byte)(i[x] & m[x]);
            return InetAddress.getByAddress(n).getHostAddress();
        } catch (Exception e) { return "N/A"; }
    }

    static String getOwnMac(NetworkInterface iface) {
        try {
            byte[] hw = iface.getHardwareAddress();
            if (hw == null) return null;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hw.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", hw[i]));
            }
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    static String getDefaultGateway() {
        try {
            String[] cmd = IS_WIN
                    ? new String[]{"cmd", "/c", "ipconfig"}
                    : new String[]{"/bin/sh", "-c", "ip route show default 2>/dev/null"};
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            if (IS_WIN) {
                while ((line = r.readLine()) != null)
                    if (line.trim().startsWith("Default Gateway")) {
                        String[] parts = line.split(":");
                        if (parts.length > 1) {
                            String gw = parts[parts.length - 1].trim();
                            if (!gw.isEmpty() && !gw.equals("...")) return gw;
                        }
                    }
            } else {
                while ((line = r.readLine()) != null)
                    if (line.startsWith("default via")) {
                        String[] parts = line.split("\\s+");
                        if (parts.length >= 3) return parts[2];
                    }
                // fallback
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

    static String getPublicIP() {
        String[] services = {
            "https://api.ipify.org", "https://checkip.amazonaws.com",
            "https://icanhazip.com", "https://ifconfig.me/ip"
        };
        for (String url : services) {
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
                c.setConnectTimeout(3000); c.setReadTimeout(3000);
                c.setRequestProperty("User-Agent", "Mozilla/5.0");
                try (BufferedReader br = new BufferedReader(new InputStreamReader(c.getInputStream()))) {
                    String ip = br.readLine().trim();
                    if (ip.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return ip;
                }
            } catch (Exception ignored) {}
        }
        return RE + "Unavailable" + R;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Display Helpers
    // ═══════════════════════════════════════════════════════════════════════
    static String padR(String s, int n) {
        String raw = s.replaceAll("\u001B\\[[;\\d]*m", "");
        int pad = n - raw.length();
        return pad <= 0 ? s : s + " ".repeat(pad);
    }

    static void header(String title) {
        System.out.println();
        System.out.println(B + BL + "  ╔══ " + title + " " + "═".repeat(Math.max(0, 50 - title.length())) + "╗" + R);
    }

    static void info(String label, String value) {
        System.out.printf(B + "  %-14s" + R + "  %s%n", label, value);
    }

    static void printBanner() {
        System.out.println(CY + B);
        System.out.println("  ███╗   ██╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗");
        System.out.println("  ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║");
        System.out.println("  ██╔██╗ ██║█████╗     ██║       ███████╗██║     ███████║██╔██╗ ██║");
        System.out.println("  ██║╚██╗██║██╔══╝     ██║       ╚════██║██║     ██╔══██║██║╚████║");
        System.out.println("  ██║ ╚████║███████╗   ██║       ███████║╚██████╗██║  ██║██║ ╚███║");
        System.out.println("  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝");
        System.out.println(R + D + "                  Network Analysis Tool  v3.0  [ OUI + ARP + DNS ]" + R);
        System.out.println();
    }
}
