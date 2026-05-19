package com.honeytrap;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;

import javax.servlet.MultipartConfigElement;
import java.io.File;
import java.net.InetAddress;

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║   HoneyTrap v2 — Application Entry Point                    ║
 * ║   Boots embedded Tomcat, registers all servlets & filters.  ║
 * ║   Run: java -jar honeytrap-2.0-jar-with-dependencies.jar    ║
 * ║   Then open: http://localhost:8080/login                     ║
 * ╚══════════════════════════════════════════════════════════════╝
 */
public class Application {

    private static final int PORT = 8080;

    public static void main(String[] args) throws Exception {

        // ── Initialize database on startup ────────────────────────────────
        DatabaseManager.initialize();
        SessionManager.initialize();

        // ── Boot embedded Tomcat ──────────────────────────────────────────
        Tomcat tomcat = new Tomcat();
        tomcat.setPort(PORT);
        tomcat.getConnector(); // must call to bind the port

        // Work directory for Tomcat temp files
        String workDir = System.getProperty("java.io.tmpdir") + "/honeytrap-tomcat";
        tomcat.setBaseDir(workDir);

        // ── Create web context ────────────────────────────────────────────
        Context ctx = tomcat.addContext("", new File(workDir).getAbsolutePath());

        // ── Register Servlets ─────────────────────────────────────────────
        // Login portal (GET=show form, POST=process login)
        Tomcat.addServlet(ctx, "LoginServlet",    new LoginServlet());
        ctx.addServletMappingDecoded("/login",          "LoginServlet");
        ctx.addServletMappingDecoded("/",               "LoginServlet");

        // Trap pages
        Tomcat.addServlet(ctx, "SqliServlet",     new TrapController.SqliServlet());
        ctx.addServletMappingDecoded("/trap/sqli",      "SqliServlet");

        Tomcat.addServlet(ctx, "BruteServlet",    new TrapController.BruteServlet());
        ctx.addServletMappingDecoded("/trap/bruteforce","BruteServlet");

        Tomcat.addServlet(ctx, "HijackServlet",   new TrapController.HijackServlet());
        ctx.addServletMappingDecoded("/trap/hijack",    "HijackServlet");

        // Admin dashboard
        Tomcat.addServlet(ctx, "AdminServlet",    new AdminServlet());
        ctx.addServletMappingDecoded("/admin",          "AdminServlet");

        // Simulate attacks endpoint
        Tomcat.addServlet(ctx, "SimulateServlet", new SimulateServlet());
        ctx.addServletMappingDecoded("/simulate",       "SimulateServlet");

        // Static file serving (CSS)
        Tomcat.addServlet(ctx, "StaticServlet",
                new org.apache.catalina.servlets.DefaultServlet());
        ctx.addServletMappingDecoded("/static/*",       "StaticServlet");

        // ── Register Detection Filter on /login (POST) ────────────────────
        FilterDef filterDef = new FilterDef();
        filterDef.setFilterName("DetectionFilter");
        filterDef.setFilterClass(DetectionFilter.class.getName());
        ctx.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName("DetectionFilter");
        filterMap.addURLPattern("/login");
        ctx.addFilterMap(filterMap);

        // ── Start! ─────────────────────────────────────────────────────────
        tomcat.start();

        String localIP = InetAddress.getLocalHost().getHostAddress();
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║          🍯  HoneyTrap v2 is LIVE                        ║");
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        System.out.printf ("║  Login Portal  →  http://localhost:%d/login%s║%n", PORT, " ".repeat(19));
        System.out.printf ("║  Admin Panel   →  http://localhost:%d/admin%s║%n", PORT, " ".repeat(19));
        System.out.printf ("║  Local IP      →  http://%s:%d/login%s║%n", localIP, PORT, " ".repeat(Math.max(1, 30 - localIP.length())));
        System.out.println("╠══════════════════════════════════════════════════════════╣");
        System.out.println("║  Traps active: SQLi · Brute Force · Session Hijack      ║");
        System.out.println("║  Press Ctrl+C to stop the server                        ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println();

        tomcat.getServer().await();
    }
}
