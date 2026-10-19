import test from "node:test";
import assert from "node:assert/strict";
import { scanLine, scanVulnerabilityLine } from "../server/scanner.js";

function ruleIds(line, file = "src/main/java/App.java") {
  return scanVulnerabilityLine({ line, file, lineNumber: 1, source: "current" }).map((finding) => finding.ruleId);
}

function assertHits(ruleId, lines, file) {
  for (const line of lines) {
    assert.ok(ruleIds(line, file).includes(ruleId), `${ruleId} should match: ${line}`);
  }
}

function assertMisses(ruleId, lines, file) {
  for (const line of lines) {
    assert.ok(!ruleIds(line, file).includes(ruleId), `${ruleId} should not match: ${line}`);
  }
}

// ---- cwe-command-injection (generic) word-boundary fix ----

test("generic command injection matches concatenation followed by a space", () => {
  assertHits(
    "cwe-command-injection",
    [
      "exec(cmd + bar)",
      "child_process.exec('ls ' + dir, cb)",
      "os.system(\"rm -rf \" + path)",
      "execSync(base +",
      "exec(cmd+bar)",
      "exec(`convert ${req.query.file}`)",
      "spawn(cmd, { input: req.body.x })"
    ],
    "server.js"
  );
});

test("generic command injection stays narrow on constant commands", () => {
  assertMisses(
    "cwe-command-injection",
    ["exec('ls -la')", "execSync(\"git status\")", "for (let i = 0; i < n; i++) exec(cmd)", "spawn('node', ['index.js'])"],
    "server.js"
  );
});

test("generic command injection defers Java files to the Java rule", () => {
  const ids = ruleIds("Process p = Runtime.getRuntime().exec(cmd + bar);");
  assert.ok(!ids.includes("cwe-command-injection"));
  assert.ok(ids.includes("cwe-command-injection-java"));
});

// ---- cwe-command-injection-java ----

test("Java command injection rule matches Runtime.exec and ProcessBuilder sinks", () => {
  assertHits("cwe-command-injection-java", [
    "Process p = Runtime.getRuntime().exec(cmd + bar);",
    "Process p = r.exec(args, argsEnv);",
    "r.exec(cmd + bar, argsEnv, new java.io.File(System.getProperty(\"user.dir\")));",
    "ProcessBuilder pb = new ProcessBuilder(argList);",
    "ProcessBuilder pb = new java.lang.ProcessBuilder(\"sh\", \"-c\", input);",
    "pb.command(args);",
    "Process p = Runtime.getRuntime().exec("
  ]);
  const [finding] = scanVulnerabilityLine({ line: "pb.command(args);", file: "A.java", lineNumber: 7, source: "current" });
  assert.equal(finding.cwe, "CWE-78");
  assert.equal(finding.severity, "high");
  assert.equal(finding.evidenceLevel, "static_vulnerability_pattern");
  assert.equal(finding.line, 7);
});

test("Java command injection rule ignores literals, empty builders, comments and non-Java files", () => {
  assertMisses("cwe-command-injection-java", [
    "Process p = Runtime.getRuntime().exec(\"ls -la\");",
    "Process p = r.exec(LIST_CMD);",
    "ProcessBuilder pb = new ProcessBuilder();",
    "System.out.println(\"Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case\");",
    "// Process p = r.exec(cmd + bar);",
    " * r.exec(cmd + bar) is dangerous",
    "executor.execute(task);"
  ]);
  assertMisses("cwe-command-injection-java", ["pb.command(args);"], "builder.js");
});

// ---- cwe-sql-injection-java ----

test("Java SQL injection rule matches JDBC, JdbcTemplate, JPA and Hibernate sinks", () => {
  assertHits("cwe-sql-injection-java", [
    "java.sql.ResultSet rs = statement.executeQuery(sql);",
    "int count = stmt.executeUpdate(\"DELETE FROM users WHERE id = \" + id);",
    "statement.execute(sql, java.sql.Statement.RETURN_GENERATED_KEYS);",
    "statement.addBatch(sql);",
    "java.sql.PreparedStatement ps = connection.prepareStatement(sql);",
    "connection.prepareStatement(",
    "java.sql.CallableStatement cs = conn.prepareCall(\"{call \" + proc + \"}\");",
    "jdbcTemplate.query(sql, rowMapper);",
    "JDBCtemplate.execute(sql);",
    "jdbcTemplate.update(\"UPDATE t SET a = '\" + a + \"'\");",
    "jdbcTemplate.batchUpdate(sql);",
    "Object o = jdbcTemplate.queryForObject(sql, Long.class);",
    "em.createQuery(\"SELECT u FROM User u WHERE u.name = '\" + name + \"'\");",
    "entityManager.createNativeQuery(sql).getResultList();",
    "session.createSQLQuery(sql).list();",
    "session.createQuery(hql).list();"
  ]);
});

test("Java SQL injection rule ignores parameterized literals and unrelated execute calls", () => {
  assertMisses("cwe-sql-injection-java", [
    "connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");",
    "statement.executeQuery(\"SELECT 1\");",
    "statement.execute();",
    "java.sql.ResultSet rs = statement.executeQuery();",
    "connection.prepareStatement(FIND_USER_SQL);",
    "jdbcTemplate.query(Queries.FIND_ALL);",
    "cb.createQuery(User.class);",
    "executor.execute(task);",
    "cache.update(key, value);",
    "// statement.executeQuery(sql);",
    "System.out.println(\"No results returned for query: \" + sql);"
  ]);
});

// ---- cwe-path-traversal-java ----

test("Java path traversal rule matches java.io and java.nio file sinks", () => {
  assertHits("cwe-path-traversal-java", [
    "java.io.File fileTarget = new java.io.File(bar);",
    "new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR, bar);",
    "fis = new java.io.FileInputStream(new java.io.File(fileName));",
    "fos = new FileOutputStream(fileName, false);",
    "Reader r = new FileReader(base + name);",
    "Writer w = new java.io.FileWriter(path);",
    "RandomAccessFile raf = new RandomAccessFile(name, \"r\");",
    "java.nio.file.Path path = java.nio.file.Paths.get(fileName);",
    "Path p = Path.of(dir, name);",
    "is = java.nio.file.Files.newInputStream(path, java.nio.file.StandardOpenOption.READ);",
    "byte[] data = Files.readAllBytes(target);",
    "Files.write(target, bytes);",
    "java.io.File fileTarget = new java.io.File("
  ]);
});

test("Java path traversal rule ignores literal and constant paths", () => {
  assertMisses("cwe-path-traversal-java", [
    "File f = new File(\"/etc/app/config.properties\");",
    "File f = new java.io.File(CONFIG_PATH);",
    "File cwd = new java.io.File(System.getProperty(\"user.dir\"));",
    "Path p = Paths.get(\"data/out.txt\");",
    "java.io.FileOutputStream fos = null;",
    "System.out.println(\"Couldn't open FileInputStream on file: '\" + fileName + \"'\");",
    "// fis = new java.io.FileInputStream(fileName);",
    "new FileFilter(pattern);"
  ]);
});

// ---- cwe-xss-java ----

test("Java XSS rule matches servlet response writes of non-literal data", () => {
  assertHits("cwe-xss-java", [
    "response.getWriter().println(bar);",
    "response.getWriter().print(bar.toCharArray());",
    "response.getWriter().write(\"Parameter value: \" + bar);",
    "response.getWriter().write(bar, 0, length);",
    "response.getWriter().format(java.util.Locale.US, bar, obj);",
    "response.getWriter().printf(\"Formatted like: %1$s and %2$s.\", obj);",
    "resp.getWriter().append(name);",
    "response.getOutputStream().print(msg);",
    "out.println(request.getParameter(\"q\"));",
    "out.format(java.util.Locale.US, \"Formatted like: %1$s and %2$s.\", obj);"
  ]);
});

test("Java XSS rule ignores literal output, System.out and non-response writers", () => {
  assertMisses("cwe-xss-java", [
    "response.getWriter().println(\" But file doesn't exist yet.\");",
    "out.write(\"<!DOCTYPE html>\\n<html>\\n<body>\\n<p>\");",
    "System.out.println(\"value: \" + bar);",
    "java.io.PrintWriter out = response.getWriter();",
    "response.getWriter()",
    "logger.out.println(bar);",
    "// response.getWriter().println(bar);"
  ]);
});

test("Java rules flow through scanLine with CWE metadata", () => {
  const findings = scanLine({
    line: "java.sql.ResultSet rs = statement.executeQuery(sql);",
    file: "src/main/java/Dao.java",
    lineNumber: 42,
    source: "current"
  });
  const sqli = findings.find((finding) => finding.ruleId === "cwe-sql-injection-java");
  assert.ok(sqli);
  assert.equal(sqli.cwe, "CWE-89");
  assert.equal(sqli.stage, "vulnerability-pattern");
  assert.equal(sqli.context, "java.sql.ResultSet rs = statement.executeQuery(sql);");
});
