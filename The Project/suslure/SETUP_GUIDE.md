# SUSLURE — Error Analysis & IntelliJ Setup Guide

---

## PART 1 — ALL ERRORS EXPLAINED

### ERROR 1 — CRITICAL COMPILE ERROR: `NetworkScanner.java` (Line ~41)

**File:** `NetworkScanner.java`  
**Severity:** Fatal — project will NOT compile at all  
**Type:** Type mismatch / incompatible types

#### What went wrong

The OUI vendor lookup table was declared as `String[][]` (a 2D array where every element must be a `String[]`), but vendor name entries like `"Apple"`, `"Samsung"` etc. were written as plain `String` literals instead of `String[]` arrays.

```java
// BROKEN — original code
String[][] entries = {
    {"000A27","000393", ...},  // ✓ this is String[] — OK
    "Apple",                   // ✗ this is String — NOT assignable to String[]
    {"002637","103047", ...},  // ✓ String[] — OK
    "Samsung",                 // ✗ String — COMPILE ERROR
    ...
};
```

Java's type system is strict: every element of a `String[][]` must itself be a `String[]`. A bare `String` is a completely different type.

The original loop also tried `entries[i + 1][0]` (array subscript on a String), which would cause an `ArrayIndexOutOfBoundsException` at runtime even if the compile error were somehow bypassed.

#### The Fix (applied in the fixed file)

Changed the array to `Object[][]` so it can hold mixed types, then cast when reading:

```java
// FIXED
Object[][] entries = {
    new String[]{"000A27","000393", ...}, "Apple",
    new String[]{"002637","103047", ...}, "Samsung",
    ...
};
for (int i = 0; i < entries.length; i += 2) {
    String   vendor   = (String)   entries[i + 1];   // safe cast
    String[] prefixes = (String[]) entries[i];        // safe cast
    for (String prefix : prefixes) OUI.put(prefix, vendor);
}
```

---

### ERROR 2 — CONFIGURATION ERROR: `.idea/misc.xml`

**File:** `.idea/misc.xml`  
**Severity:** Causes IntelliJ to show "Project SDK not defined" warning, blocks running  
**Type:** Wrong JDK name reference

#### What went wrong

```xml
<!-- BROKEN -->
<component name="ProjectRootManager" version="2"
    project-jdk-name="openjdk-26"   ← this JDK name almost certainly does not exist on your machine
    project-jdk-type="JavaSDK" />
```

IntelliJ stores JDK configurations by name. `"openjdk-26"` is a specific name that only exists if you added a JDK called exactly that in IntelliJ's SDK settings. If the name doesn't match, IntelliJ shows "SDK not defined", grays out the Run button, and refuses to compile.

#### The Fix (applied in the fixed file)

```xml
<!-- FIXED — uses "17" which matches standard JDK 17 setup in IntelliJ -->
<component name="ProjectRootManager" version="2"
    project-jdk-name="17"
    project-jdk-type="JavaSDK" />
```

If your JDK has a different name in IntelliJ, you must match it exactly (see Part 2, Step 4).

---

### ERROR 3 — STRUCTURE ERROR: Wrong file locations

**Severity:** Maven cannot find source files; project fails to compile  
**Type:** Maven project structure violation

#### What went wrong

The Java source files were in the wrong directory. Maven requires a strict layout:

```
project/
  pom.xml
  src/
    main/
      java/
        com/
          suslure/       ← .java files go HERE
```

The uploaded files were all flat (not in the Maven directory tree), so Maven's `mvn package` command would produce an empty JAR with no classes inside.

#### The Fix

All Java files have been moved to the correct path:
```
suslure/src/main/java/com/suslure/ClassName.java
```

---

### ERROR 4 — CONFIGURATION ERROR: `pom.xml` — `javax.servlet-api` scope

**File:** `pom.xml`  
**Severity:** Runtime `NoClassDefFoundError` in some environments  
**Type:** Wrong Maven dependency scope

#### What went wrong

```xml
<!-- Original -->
<dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>javax.servlet-api</artifactId>
    <version>4.0.1</version>
    <scope>provided</scope>   ← THIS IS THE PROBLEM
</dependency>
```

`provided` scope means Maven will NOT include this JAR in the fat JAR output. This works when deploying to a full Tomcat server (which already ships servlet-api). But SUSLURE uses **embedded Tomcat** (`tomcat-embed-core`), and while embed-core does bundle servlet support, the explicit `provided` scope can cause issues in certain configurations or IDE run modes where the classpath is set up differently.

#### The Fix

Change scope from `provided` to `compile` so it's always bundled:

```xml
<!-- FIXED pom.xml - see the delivered pom.xml -->
<dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>javax.servlet-api</artifactId>
    <version>4.0.1</version>
    <scope>compile</scope>
</dependency>
```

---

### ERROR 5 — RUNTIME WARNING: `DetectionFilter` classname registration

**File:** `Application.java` + `DetectionFilter.java`  
**Severity:** Low — works but causes a Tomcat startup warning in some versions  
**Type:** Embedded Tomcat filter registration quirk

#### What went wrong

```java
FilterDef fd = new FilterDef();
fd.setFilterClass(DetectionFilter.class.getName());   // string-based class lookup
```

Embedded Tomcat sometimes cannot instantiate filters by class name when the context classloader isn't set up with a full web app structure. This causes a logged warning like `Filter class not found`.

#### The Fix

Register the filter instance directly instead of by class name. Replace in `Application.java`:

```java
// FIXED — pass instance directly, avoids classloader lookup
FilterDef fd = new FilterDef();
fd.setFilterName("DetectionFilter");
fd.setFilter(new DetectionFilter());        // ← instance, not class name string
// Remove: fd.setFilterClass(...)
ctx.addFilterDef(fd);
```

This fix has been applied in the delivered `Application.java`.

---

## PART 2 — HOW TO RUN IN INTELLIJ (STEP BY STEP)

### Prerequisites

Before starting, confirm you have these installed:

| Tool | Version | Check command |
|------|---------|---------------|
| JDK | 17 or 21 | `java -version` |
| Maven | 3.8+ | `mvn -version` |
| IntelliJ IDEA | Any (Community or Ultimate) | — |

Download JDK 17 from https://adoptium.net if needed.

---

### Step 1 — Open the Project

1. Launch IntelliJ IDEA
2. Click **"Open"** (NOT "New Project")
3. Navigate to the `suslure/` folder (the one containing `pom.xml`)
4. Click **Open** and select **"Open as Project"**
5. When IntelliJ asks "Trust and open project?", click **Trust Project**

IntelliJ will detect the `pom.xml` and automatically import it as a Maven project. You'll see a loading bar in the bottom right — wait for it to finish (it downloads dependencies from the internet).

---

### Step 2 — Set the Project SDK

If IntelliJ shows a yellow banner saying "Project SDK not defined" or the run button is grayed out:

1. Go to **File → Project Structure** (shortcut: `Ctrl+Alt+Shift+S` on Windows/Linux, `⌘;` on Mac)
2. Under **Project**, look at the **SDK** dropdown
3. If it shows `<No SDK>`, click the dropdown and select your JDK 17 (or 21)
4. If your JDK isn't listed, click **Add SDK → JDK** and browse to where Java is installed:
   - Windows: `C:\Program Files\Eclipse Adoptium\jdk-17...`
   - macOS: `/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home`
   - Linux: `/usr/lib/jvm/java-17-openjdk-amd64`
5. Set **Language Level** to `17`
6. Click **Apply → OK**

---

### Step 3 — Reload Maven

1. Open the **Maven panel** on the right side of IntelliJ (click the "m" icon or **View → Tool Windows → Maven**)
2. Click the **circular arrows (Reload All Maven Projects)** button at the top of the Maven panel
3. Wait for the download bar at the bottom to complete
4. You should see no red errors in the Maven panel

---

### Step 4 — Verify the Build

In the Maven panel, expand **suslure → Lifecycle**, then double-click **compile**.

You should see:
```
[INFO] BUILD SUCCESS
```

If you see any errors here, they'll be clearly listed with file names and line numbers.

---

### Step 5 — Create a Run Configuration

1. In the top toolbar, click the dropdown that says **"Current File"** or **"Add Configuration"**
2. Click **Edit Configurations...**
3. Click the **"+"** button → choose **Application**
4. Fill in:
   - **Name:** `SUSLURE`
   - **Main class:** `com.suslure.Application`
   - **JDK:** Select your JDK 17
   - **Working directory:** `$MODULE_WORKING_DIR$` (click the folder icon to set it to the `suslure/` root)
5. Click **Apply → OK**

---

### Step 6 — Run It

1. Press the **green triangle (Run)** button in the top toolbar, or press `Shift+F10`
2. The console at the bottom will show startup output
3. Wait for the SUSLURE ASCII banner to appear:

```
   ███████╗██╗   ██╗███████╗██╗     ██╗   ██╗██████╗ ███████╗
   ...
   SUSLURE v1.0 — Honeypot System ACTIVE
   Honeypot Portal  →  http://localhost:8080/login
   Admin Dashboard  →  http://localhost:8080/admin
```

4. Open your browser and go to `http://localhost:8080/login`

---

### Step 7 — Access the Admin Dashboard

1. Go to `http://localhost:8080/admin`
2. Log in with:
   - Username: `SusLure`
   - Password: `thats a secret baby`
3. Click **"⚡ SIMULATE 20 ATTACKS"** to populate the dashboard with demo data

---

## PART 3 — BUILDING A RUNNABLE JAR (OPTIONAL)

If you want to run SUSLURE without IntelliJ (on any machine with Java):

**In IntelliJ terminal (Alt+F12):**
```bash
mvn clean package
```

This produces:
```
target/suslure-1.0-jar-with-dependencies.jar
```

Run it anywhere:
```bash
java -jar target/suslure-1.0-jar-with-dependencies.jar
```

The `suslure.db` SQLite database file will be created in whatever directory you run the jar from.

---

## PART 4 — TROUBLESHOOTING COMMON ISSUES

| Symptom | Cause | Fix |
|---------|-------|-----|
| Red underlines everywhere in IDE | SDK not set | Part 2, Step 2 |
| `BUILD FAILURE` on compile | Maven not reloaded | Part 2, Step 3 |
| `Address already in use: 8080` | Port 8080 taken | Kill the other process or change `PORT = 8080` in `Application.java` to `9090` |
| `NoClassDefFoundError: javax/servlet/...` | Servlet scope issue | Already fixed in delivered `pom.xml` |
| `NullPointerException` in NetworkScanner | ARP not available | Safe to ignore — enrichment fails gracefully |
| Admin page redirects to login | Session expired | Re-login at `/admin` |
| Database errors on startup | SQLite JDBC missing | Maven reload (Step 3) |
| `Filter class not found` warning | Filter registration | Already fixed in delivered `Application.java` |

---

## SUMMARY OF ALL FIXED FILES

| File | What Was Fixed |
|------|----------------|
| `NetworkScanner.java` | `String[][]` → `Object[][]` for OUI map; fixed loop casts |
| `.idea/misc.xml` | JDK name `openjdk-26` → `17` |
| `Application.java` | Filter registered via instance instead of class name string |
| `pom.xml` | `servlet-api` scope `provided` → `compile` |
| Project structure | All `.java` files moved to `src/main/java/com/suslure/` |
