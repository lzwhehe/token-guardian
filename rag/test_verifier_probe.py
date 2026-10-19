"""代码审查用 25 个手写的真实漏洞探测核验器（v1 曾把其中 23 个误判为安全）。每一个都必须保持「不排除」。"""
RESULTS = []
import sys
sys.path.insert(0, r"E:\FIND_WORK\projects\portfolio-deploy\scanner\rag")
from verifier import verify

HEAD = """import java.sql.*;
import java.util.*;
public class T extends javax.servlet.http.HttpServlet {
"""

def wrap(body, extra=""):
    return HEAD + "  public void doPost(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {\n" + body + "\n  }\n" + extra + "}\n"

def run(name, code, cwe, claim=None):
    lines = code.split("\n")
    if claim is None:
        i = next(i for i, l in enumerate(lines, 1) if "doPost" in l)
        claim = {"type": "no_taint", "line": i, "expr": lines[i - 1].strip()}
    else:
        i = next(i for i, l in enumerate(lines, 1) if claim["expr"] in l)
        claim = {**claim, "line": i}
    r = verify(code, cwe, claim)
    RESULTS.append((name, r.ok, r.reason))
    print(f"{'DISMISSED' if r.ok else 'kept     '}  {name:28s} {r.reason}")

S = "    Statement st = DriverManager.getConnection(\"x\").createStatement();\n"

run("stringbuilder_chain", wrap(S + """    StringBuilder sb = new StringBuilder();
    sb.append("SELECT * FROM u WHERE n='").append(request.getParameter("x")).append("'");
    st.executeQuery(sb.toString());"""), "CWE-89")

run("array_elem_overwrite", wrap(S + """    String[] a = new String[2];
    a[0] = request.getParameter("x");
    a[1] = "safe";
    st.executeQuery("SELECT '" + a[0] + "'");"""), "CWE-89")

run("obj_field_write", wrap(S + """    Holder h = new Holder();
    h.v = request.getParameter("x");
    st.executeQuery("SELECT '" + h.v + "'");""", "  static class Holder { String v; }\n"), "CWE-89")

run("this_field", wrap(S + """    this.f = request.getParameter("x");
    st.executeQuery("SELECT '" + f + "'");""", "  private String f;\n"), "CWE-89")

run("getChars_outparam", wrap(S + """    String p = request.getParameter("x");
    char[] buf = new char[p.length()];
    p.getChars(0, p.length(), buf, 0);
    st.executeQuery("SELECT '" + new String(buf) + "'");"""), "CWE-89")

run("try_catch_partial", wrap(S + """    String p = request.getParameter("x");
    String sql = "SELECT '" + p + "'";
    try {
      Integer.parseInt(p);
      sql = "SELECT 1";
    } catch (NumberFormatException e) { }
    st.executeQuery(sql);"""), "CWE-89")

run("switch_no_default", wrap(S + """    String p = request.getParameter("x");
    String sql = "SELECT '" + p + "'";
    switch (p.charAt(0)) {
      case 'A': sql = "SELECT 1"; break;
      case 'B': sql = "SELECT 2"; break;
    }
    st.executeQuery(sql);"""), "CWE-89")

run("void_helper_stmt", wrap(S + """    st.executeQuery("SELECT 1");
    String p = request.getParameter("x");
    run(st, p);""", "  private void run(Statement s, String q) throws Exception { s.executeQuery(\"SELECT '\" + q + \"'\"); }\n"), "CWE-89")

run("overload", wrap(S + """    String p = request.getParameter("x");
    String v = q(p);
    st.executeQuery("SELECT '" + v + "'");""", "  private String q(String a) { return a; }\n  private String q(String a, int n) { return \"safe\"; }\n"), "CWE-89")

run("lambda_sink", wrap(S + """    String p = request.getParameter("x");
    Optional.of(p).ifPresent(z -> { try { st.executeQuery("SELECT '" + z + "'"); } catch (Exception e) { } });"""), "CWE-89")

run("while_cond_assign", wrap(S + """    java.io.BufferedReader r = request.getReader();
    String line; String body = "";
    while ((line = r.readLine()) != null) { body += line; }
    st.executeQuery("SELECT '" + body + "'");"""), "CWE-89")

run("sink_in_if_cond", wrap(S + """    st.execute("SELECT 1");
    String p = request.getParameter("x");
    if (st.execute("SELECT '" + p + "'")) { }"""), "CWE-89")

run("try_with_resources", wrap(S + """    st.execute("SELECT 1");
    String p = request.getParameter("x");
    try (ResultSet rs = st.executeQuery("SELECT '" + p + "'")) { }"""), "CWE-89")

run("synchronized", wrap(S + """    st.execute("SELECT 1");
    String p = request.getParameter("x");
    synchronized (this) { st.executeQuery("SELECT '" + p + "'"); }"""), "CWE-89")

run("for_init", wrap(S + """    String p = request.getParameter("x");
    for (String q = "SELECT '" + p + "'"; ; ) { st.executeQuery(q); break; }"""), "CWE-89")

run("unrecognised_path_sink", wrap("""    java.nio.file.Path base = java.nio.file.Paths.get("/srv/data");
    String p = request.getParameter("f");
    String s = java.nio.file.Files.readString(base.resolve(p));"""), "CWE-22")

run("req_named_req", (HEAD + """  public void doPost(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse response) throws Exception {
""" + S + """    st.executeQuery("SELECT '" + req.getParameter("x") + "'");
  }
}
"""), "CWE-89")

run("unescapeHtml", wrap("""    java.io.PrintWriter out = response.getWriter();
    String p = request.getParameter("x");
    out.println(org.apache.commons.lang.StringEscapeUtils.unescapeHtml(p));"""), "CWE-79",
    {"type": "sanitizer", "expr": "org.apache.commons.lang.StringEscapeUtils.unescapeHtml(p)"})

run("postinc_deadbranch", wrap(S + """    String p = request.getParameter("x");
    int n = 1;
    n++;
    String bar = (n == 1) ? "safe" : p;
    st.executeQuery("SELECT '" + bar + "'");"""), "CWE-89", {"type": "dead_branch", "expr": "String bar = (n == 1) ?"})

run("nested_not_deadbranch", wrap(S + """    String p = request.getParameter("x");
    boolean safe = false;
    String bar = "x";
    if (!safe && true) bar = p;
    st.executeQuery("SELECT '" + bar + "'");"""), "CWE-89", {"type": "dead_branch", "expr": "if (!safe && true) bar = p;"})

run("string_eq_deadbranch", wrap(S + """    String p = request.getParameter("x");
    String a = "a"; String b = "b";
    String bar = (a + b == "ab") ? "safe" : p;
    st.executeQuery("SELECT '" + bar + "'");"""), "CWE-89", {"type": "dead_branch", "expr": "String bar = (a + b == \"ab\")"})

run("intdiv_deadbranch", wrap(S + """    String p = request.getParameter("x");
    int m = -7;
    String bar = (m / 2 == -4) ? "safe" : p;
    st.executeQuery("SELECT '" + bar + "'");"""), "CWE-89", {"type": "dead_branch", "expr": "String bar = (m / 2 == -4)"})

run("list_alias", wrap(S + """    List<String> a = new ArrayList<>();
    a.add("safe");
    List<String> b = a;
    b.add(0, request.getParameter("x"));
    String v = a.get(0);
    st.executeQuery("SELECT '" + v + "'");"""), "CWE-89", {"type": "key_mismatch", "expr": "String v = a.get(0);"})

run("collections_addAll", wrap(S + """    List<String> a = new ArrayList<>();
    a.add("safe");
    Collections.addAll(a, request.getParameter("x"));
    String v = a.get(1);
    st.executeQuery("SELECT '" + v + "'");"""), "CWE-89")

run("map_literal_key_types", wrap(S + """    Map<String, String> m = new HashMap<>();
    m.put("k", request.getParameter("x"));
    String v = m.get("\u006b");
    st.executeQuery("SELECT '" + v + "'");"""), "CWE-89", {"type": "key_mismatch", "expr": "String v = m.get("})


def test_probe_cases_are_never_dismissed():
    bad = [(n, why) for n, ok, why in RESULTS if ok]
    assert not bad, bad


if __name__ == "__main__":
    bad = [(n, why) for n, ok, why in RESULTS if ok]
    print()
    print(f"{len(RESULTS) - len(bad)}/{len(RESULTS)} kept; dismissed: {bad}")
    sys.exit(1 if bad else 0)
