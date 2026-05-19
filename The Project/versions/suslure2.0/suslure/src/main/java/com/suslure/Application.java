package com.suslure;

import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;

import java.io.File;

public class Application {
    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {

        // ── Init subsystems ────────────────────────────────────────────
        DatabaseManager.initialize();
        SessionManager.initialize();
        NetworkMonitor.start();          // background LAN scanner

        String localIP = NetworkScanner.getLocalIP();

        // ── Embedded Tomcat ────────────────────────────────────────────
        Tomcat tomcat = new Tomcat();
        tomcat.setPort(PORT);
        tomcat.getConnector();

        String workDir = System.getProperty("java.io.tmpdir") + "/suslure-tomcat";
        new File(workDir).mkdirs();
        tomcat.setBaseDir(workDir);

        Context ctx = tomcat.addContext("", new File(workDir).getAbsolutePath());

        // ── Servlets ───────────────────────────────────────────────────
        Tomcat.addServlet(ctx, "LoginServlet",    new LoginServlet());
        ctx.addServletMappingDecoded("/login",           "LoginServlet");
        ctx.addServletMappingDecoded("/",                "LoginServlet");

        Tomcat.addServlet(ctx, "SqliServlet",     new TrapController.SqliServlet());
        ctx.addServletMappingDecoded("/trap/sqli",       "SqliServlet");

        Tomcat.addServlet(ctx, "BruteServlet",    new TrapController.BruteServlet());
        ctx.addServletMappingDecoded("/trap/bruteforce", "BruteServlet");

        Tomcat.addServlet(ctx, "HijackServlet",   new TrapController.HijackServlet());
        ctx.addServletMappingDecoded("/trap/hijack",     "HijackServlet");

        Tomcat.addServlet(ctx, "AdminServlet",    new AdminServlet());
        ctx.addServletMappingDecoded("/admin",           "AdminServlet");

        Tomcat.addServlet(ctx, "SimulateServlet", new SimulateServlet());
        ctx.addServletMappingDecoded("/simulate",        "SimulateServlet");

        // ── DetectionFilter on /login ──────────────────────────────────
        FilterDef fd = new FilterDef();
        fd.setFilterName("DetectionFilter");
        fd.setFilter(new DetectionFilter());
        ctx.addFilterDef(fd);

        FilterMap fm = new FilterMap();
        fm.setFilterName("DetectionFilter");
        fm.addURLPattern("/login");
        ctx.addFilterMap(fm);

        // ── Start ──────────────────────────────────────────────────────
        tomcat.start();

        System.out.println();
        System.out.println("\u001B[32m\u001B[1m");
        System.out.println("   \u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557     \u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557");
        System.out.println("   \u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255D\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255D\u2588\u2588\u2551     \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255D");
        System.out.println("   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551     \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255D\u2588\u2588\u2588\u2588\u2588\u2557  ");
        System.out.println("   \u255A\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u255A\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u255D  ");
        System.out.println("   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u255A\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255D\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255A\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255D\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557");
        System.out.println("   \u255A\u2550\u2550\u2550\u2550\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u255D\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u255D \u255A\u2550\u255D  \u255A\u2550\u255D\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
        System.out.println("\u001B[0m");
        System.out.println("\u001B[32m\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\u001B[0m");
        System.out.printf( "\u001B[32m\u2551\u001B[0m  \u001B[1mSUSLURE v1.0\u001B[0m \u2014 Honeypot + LAN Intelligence     \u001B[32m\u2551\u001B[0m%n");
        System.out.println("\u001B[32m\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\u001B[0m");
        System.out.printf( "\u001B[32m\u2551\u001B[0m  Honeypot     \u001B[32m\u2192\u001B[0m  http://localhost:%d/login            \u001B[32m\u2551\u001B[0m%n", PORT);
        System.out.printf( "\u001B[32m\u2551\u001B[0m  Admin        \u001B[32m\u2192\u001B[0m  http://localhost:%d/admin            \u001B[32m\u2551\u001B[0m%n", PORT);
        System.out.printf( "\u001B[32m\u2551\u001B[0m  Network      \u001B[32m\u2192\u001B[0m  http://%s:%d/login %s\u001B[32m\u2551\u001B[0m%n",
                localIP, PORT, " ".repeat(Math.max(1, 30 - localIP.length())));
        System.out.println("\u001B[32m\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\u001B[0m");
        System.out.println("\u001B[32m\u2551\u001B[0m  Admin login: SusLure / thats a secret baby       \u001B[32m\u2551\u001B[0m");
        System.out.println("\u001B[32m\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\u001B[0m");
        System.out.println("\u001B[32m\u2551\u001B[0m  Traps: \u001B[31mSQLi\u001B[0m  \u00b7  \u001B[33mBrute Force\u001B[0m  \u00b7  \u001B[35mSession Hijack\u001B[0m           \u001B[32m\u2551\u001B[0m");
        System.out.println("\u001B[32m\u2551\u001B[0m  LAN scan: MAC \u00b7 Vendor \u00b7 Hostname \u00b7 Device Type     \u001B[32m\u2551\u001B[0m");
        System.out.println("\u001B[32m\u2551\u001B[0m  Port scan  \u00b7  UA fingerprint  \u00b7  Header dump      \u001B[32m\u2551\u001B[0m");
        System.out.println("\u001B[32m\u2551\u001B[0m  Press Ctrl+C to stop                               \u001B[32m\u2551\u001B[0m");
        System.out.println("\u001B[32m\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D\u001B[0m");
        System.out.println();

        tomcat.getServer().await();
    }
}
