package com.suslure;

import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;

import java.io.File;
import java.net.InetAddress;

/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║   SUSLURE v1.0 — Advanced Honeypot + Network Intelligence       ║
 * ║   Run: mvn package → java -jar target/suslure-1.0-jar-with-     ║
 * ║         dependencies.jar                                         ║
 * ║   Or:  Run Application.java in IntelliJ (Maven project)         ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */
public class Application {

    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {

        // ── Init subsystems ───────────────────────────────────────────────
        DatabaseManager.initialize();
        SessionManager.initialize();

        String localIP = NetworkScanner.getLocalIP();

        // ── Boot embedded Tomcat ──────────────────────────────────────────
        Tomcat tomcat = new Tomcat();
        tomcat.setPort(PORT);
        tomcat.getConnector(); // required to bind port

        String workDir = System.getProperty("java.io.tmpdir") + "/suslure-tomcat";
        new File(workDir).mkdirs();
        tomcat.setBaseDir(workDir);

        // ── Web context ────────────────────────────────────────────────────
        Context ctx = tomcat.addContext("", new File(workDir).getAbsolutePath());

        // ── Register Servlets ──────────────────────────────────────────────
        Tomcat.addServlet(ctx, "LoginServlet",    new LoginServlet());
        ctx.addServletMappingDecoded("/login",            "LoginServlet");
        ctx.addServletMappingDecoded("/",                 "LoginServlet");

        Tomcat.addServlet(ctx, "SqliServlet",     new TrapController.SqliServlet());
        ctx.addServletMappingDecoded("/trap/sqli",        "SqliServlet");

        Tomcat.addServlet(ctx, "BruteServlet",    new TrapController.BruteServlet());
        ctx.addServletMappingDecoded("/trap/bruteforce",  "BruteServlet");

        Tomcat.addServlet(ctx, "HijackServlet",   new TrapController.HijackServlet());
        ctx.addServletMappingDecoded("/trap/hijack",      "HijackServlet");

        Tomcat.addServlet(ctx, "AdminServlet",    new AdminServlet());
        ctx.addServletMappingDecoded("/admin",            "AdminServlet");

        Tomcat.addServlet(ctx, "SimulateServlet", new SimulateServlet());
        ctx.addServletMappingDecoded("/simulate",         "SimulateServlet");

        // ── Register DetectionFilter on /login ─────────────────────────────
        FilterDef fd = new FilterDef();
        fd.setFilterName("DetectionFilter");
        fd.setFilterClass(DetectionFilter.class.getName());
        ctx.addFilterDef(fd);

        FilterMap fm = new FilterMap();
        fm.setFilterName("DetectionFilter");
        fm.addURLPattern("/login");
        ctx.addFilterMap(fm);

        // ── Start! ─────────────────────────────────────────────────────────
        tomcat.start();

        // ── Startup banner ─────────────────────────────────────────────────
        System.out.println();
        System.out.println("\u001B[32m\u001B[1m");
        System.out.println("   ███████╗██╗   ██╗███████╗██╗     ██╗   ██╗██████╗ ███████╗");
        System.out.println("   ██╔════╝██║   ██║██╔════╝██║     ██║   ██║██╔══██╗██╔════╝");
        System.out.println("   ███████╗██║   ██║███████╗██║     ██║   ██║██████╔╝█████╗  ");
        System.out.println("   ╚════██║██║   ██║╚════██║██║     ██║   ██║██╔══██╗██╔══╝  ");
        System.out.println("   ███████║╚██████╔╝███████║███████╗╚██████╔╝██║  ██║███████╗");
        System.out.println("   ╚══════╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝");
        System.out.println("\u001B[0m");
        System.out.println("\u001B[32m╔══════════════════════════════════════════════════════════╗\u001B[0m");
        System.out.println("\u001B[32m║  \u001B[1mSUSLURE v1.0 — Honeypot System ACTIVE\u001B[0m\u001B[32m                   ║\u001B[0m");
        System.out.println("\u001B[32m╠══════════════════════════════════════════════════════════╣\u001B[0m");
        System.out.printf ("\u001B[32m║  \u001B[0mHoneypot Portal \u001B[32m→  http://localhost:%d/login%s\u001B[32m║\u001B[0m%n", PORT, " ".repeat(Math.max(1, 18)));
        System.out.printf ("\u001B[32m║  \u001B[0mAdmin Dashboard  \u001B[32m→  http://localhost:%d/admin%s\u001B[32m║\u001B[0m%n", PORT, " ".repeat(Math.max(1, 18)));
        System.out.printf ("\u001B[32m║  \u001B[0mLocal Network    \u001B[32m→  http://%s:%d/login%s\u001B[32m║\u001B[0m%n", localIP, PORT, " ".repeat(Math.max(1, 28 - localIP.length())));
        System.out.println("\u001B[32m╠══════════════════════════════════════════════════════════╣\u001B[0m");
        System.out.println("\u001B[32m║  \u001B[0mAdmin user: SusLure  |  Password: thats a secret baby  \u001B[32m║\u001B[0m");
        System.out.println("\u001B[32m╠══════════════════════════════════════════════════════════╣\u001B[0m");
        System.out.println("\u001B[32m║  \u001B[0mTraps: \u001B[31mSQLi\u001B[0m  ·  \u001B[33mBrute Force\u001B[0m  ·  \u001B[35mSession Hijack\u001B[0m           \u001B[32m║\u001B[0m");
        System.out.println("\u001B[32m║  \u001B[0mNetwork enrichment: MAC + Vendor + Hostname              \u001B[32m║\u001B[0m");
        System.out.println("\u001B[32m║  \u001B[0mPress Ctrl+C to stop                                     \u001B[32m║\u001B[0m");
        System.out.println("\u001B[32m╚══════════════════════════════════════════════════════════╝\u001B[0m");
        System.out.println();

        tomcat.getServer().await();
    }
}
