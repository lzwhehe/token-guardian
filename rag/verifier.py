"""确定性核验器（v2）：检查大模型给出的「误报理由」是否成立。

大模型负责「找理由」，核验器负责「确认理由」。核验通过才允许把告警判为误报；否则只能进人工复核。

v2 的原则：**看不懂就拒绝，不猜它安全**（fail closed）。v1 只覆盖了 Benchmark 里出现的写法，代码审查
用 25 个手写的真实漏洞测试，有 23 个被 v1 误判为安全（链式调用、数组 / 字段、请求参数不叫 request、
不认识的危险函数……）。v2 的改动见 docs/DECISIONS.md D12。

流程：
1. 理由里引用的 expr 必须逐字出现在代码里（不能整段位于字符串字面量内）；行号以原文实际所在行为准。
2. 检查理由本身：
   - dead_branch：该行的 if / 三元 / switch 条件可以按 Java 语义常量折叠（只用字面量和「声明后从未被
     修改的 int / char / boolean / String 局部变量」），据此剪掉不会执行的分支；
   - key_mismatch：该行从 List / Map 取值；集合从未被别名引用或传给其它方法时，按代码顺序精确模拟
     集合内容，取出的元素与用户输入无关；
   - sanitizer：该行调用的是白名单里的外部库编码函数（完整名字精确匹配、参数个数正确，且被扫描的
     代码里没有定义同名的类）；
   - overwritten / param_query / no_taint：不剪枝，直接靠下面的分析确认。
3. 把理由「代入」后跑保守的污点分析：只要任何地方引用了被污染的值就算污染；被污染的值传进方法，
   接收者和作为参数的对象都算污染；对象字段只要在任何地方被赋过非字面量的值就算污染；
   遇到 lambda、方法引用、匿名类、重载、不认识的语句、「像危险调用但不认识」的写法 → 直接拒绝。
   只有本类漏洞所有被识别的危险函数参数都不含用户输入时，才算核验通过。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import javalang
from javalang import tree as T


class Unsupported(Exception):
    """核验器不支持的写法：拒绝核验，交给人工。"""


# ---------- 每类漏洞的危险函数 ----------
SQL_PREFIXES = ("execute", "query", "update", "prepare", "addBatch", "batchUpdate", "nativeSQL")
SQL_EXTRA = {"createQuery", "createNativeQuery", "createSQLQuery"}
XSS_METHODS = {"print", "println", "write", "format", "printf", "append"}
PATH_CLASSES = {"File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile",
                "PrintWriter", "PrintStream", "FileHandler", "ZipFile", "JarFile", "Scanner"}
PATH_QUALIFIERS = {"Files", "Paths", "Path", "FileUtils", "FilenameUtils"}
CMD_SUSPICIOUS = {"CommandLine", "DefaultExecutor", "ProcessExecutor"}
STRING_BUILDERS = {"StringBuilder", "StringBuffer", "Formatter", "StringWriter"}

# 外部库编码函数白名单：完整调用链 → 适用的 CWE（只认最终那一层调用带 1 个参数）
SANITIZERS = {
    "org.owasp.esapi.ESAPI.encoder.encodeForHTML": {"CWE-79"},
    "org.owasp.esapi.ESAPI.encoder.encodeForHTMLAttribute": {"CWE-79"},
    "org.springframework.web.util.HtmlUtils.htmlEscape": {"CWE-79"},
    "org.apache.commons.lang.StringEscapeUtils.escapeHtml": {"CWE-79"},
    "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4": {"CWE-79"},
    "org.apache.commons.text.StringEscapeUtils.escapeHtml4": {"CWE-79"},
    "org.owasp.encoder.Encode.forHtml": {"CWE-79"},
}
SANITIZER_CLASSES = {"ESAPI", "HtmlUtils", "StringEscapeUtils", "Encode"}
SANITIZER_PACKAGES = ("org.owasp.esapi", "org.springframework.web.util", "org.apache.commons.lang", "org.apache.commons.text", "org.owasp.encoder")
REQUEST_TYPES = {"HttpServletRequest", "ServletRequest", "HttpServletRequestWrapper"}
INT_TYPES = {"int", "short", "byte", "char", "boolean", "String"}


@dataclass
class Claim:
    type: str
    line: int
    expr: str


@dataclass
class Result:
    ok: bool
    reason: str
    sinks: int = 0


# ---------- 工具 ----------
def typename(t) -> str:
    parts = []
    while t is not None:
        parts.append(getattr(t, "name", "") or "")
        t = getattr(t, "sub_type", None)
    return ".".join(p for p in parts if p)


def strip_strings(line: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', line)


def inside_string(text: str, pos: int, n: int) -> bool:
    """text[pos:pos+n] 是否整段落在某个字符串字面量里面。"""
    for m in re.finditer(r'"(?:\\.|[^"\\])*"', text):
        if m.start() < pos and pos + n <= m.end():
            return True
    return False


def java_unescape(s: str) -> str:
    out, i = [], 0
    simple = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "0": "\0", "\\": "\\", "'": "'", '"': '"'}
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "u":
                j = i + 1
                while j < len(s) and s[j] == "u":
                    j += 1
                out.append(chr(int(s[j : j + 4], 16)))
                i = j + 4
                continue
            if n in simple:
                out.append(simple[n])
                i += 2
                continue
            raise ValueError("escape")
        out.append(c)
        i += 1
    return "".join(out)


def wrap32(v: int) -> int:
    return (v + 2**31) % 2**32 - 2**31


# ---------- 常量折叠（Java 语义） ----------
class Const:
    def __init__(self, consts: dict):
        self.c = consts

    def _prefix(self, e, v):
        for op in reversed(getattr(e, "prefix_operators", None) or []):
            if op == "!":
                if not isinstance(v, bool):
                    raise ValueError("!")
                v = not v
            elif op == "-":
                if isinstance(v, bool) or not isinstance(v, int):
                    raise ValueError("-")
                v = wrap32(-v)
            elif op == "+":
                pass
            else:
                raise ValueError(op)
        if getattr(e, "postfix_operators", None):
            raise ValueError("postfix")
        return v

    def ev(self, e):
        if isinstance(e, T.Literal):
            if getattr(e, "selectors", None):
                raise ValueError("selectors")
            v = e.value
            if v in ("true", "false"):
                val = v == "true"
            elif v.startswith('"'):
                val = java_unescape(v[1:-1])
            elif v.startswith("'"):
                val = java_unescape(v[1:-1])
                if len(val) != 1:
                    raise ValueError("char")
                val = ("char", val)
            else:
                if not re.fullmatch(r"\d+", v):
                    raise ValueError("number")
                val = wrap32(int(v))
            return self._prefix(e, val)
        if isinstance(e, T.MemberReference):
            if e.qualifier or e.selectors or e.member not in self.c:
                raise ValueError("non-const")
            return self._prefix(e, self.c[e.member])
        if isinstance(e, T.BinaryOperation):
            a, b = self.ev(e.operandl), self.ev(e.operandr)
            return self._prefix(e, self.binop(e.operator, a, b))
        if isinstance(e, T.MethodInvocation):
            if not e.qualifier or e.qualifier not in self.c or e.selectors:
                raise ValueError("call")
            base = self.c[e.qualifier]
            args = [self.ev(a) for a in e.arguments or []]
            if not isinstance(base, str):
                raise ValueError("call")
            if e.member == "charAt" and len(args) == 1 and isinstance(args[0], int) and not isinstance(args[0], bool) and 0 <= args[0] < len(base):
                return self._prefix(e, ("char", base[args[0]]))
            if e.member == "length" and not args:
                return self._prefix(e, len(base))
            if e.member == "equals" and len(args) == 1 and isinstance(args[0], str):
                return self._prefix(e, base == args[0])
            raise ValueError("call")
        raise ValueError(type(e).__name__)

    @staticmethod
    def binop(op, a, b):
        def num(x):
            if isinstance(x, bool):
                raise ValueError("bool")
            if isinstance(x, tuple):
                return ord(x[1])
            if isinstance(x, int):
                return x
            raise ValueError("num")

        if op in ("&&", "||"):
            if not (isinstance(a, bool) and isinstance(b, bool)):
                raise ValueError(op)
            return (a and b) if op == "&&" else (a or b)
        if op in ("==", "!="):
            if isinstance(a, str) or isinstance(b, str):
                raise ValueError("string reference equality")
            if isinstance(a, bool) != isinstance(b, bool):
                raise ValueError("types")
            r = (a == b) if isinstance(a, bool) else (num(a) == num(b))
            return r if op == "==" else not r
        if op == "+" and (isinstance(a, str) or isinstance(b, str)):
            raise ValueError("string concat")
        x, y = num(a), num(b)
        if op == "+":
            return wrap32(x + y)
        if op == "-":
            return wrap32(x - y)
        if op == "*":
            return wrap32(x * y)
        if op in ("/", "%"):
            if y == 0:
                raise ValueError("div0")
            q = abs(x) // abs(y)
            q = q if (x >= 0) == (y >= 0) else -q
            return wrap32(q) if op == "/" else wrap32(x - y * q)
        if op in (">", "<", ">=", "<="):
            return {">": x > y, "<": x < y, ">=": x >= y, "<=": x <= y}[op]
        raise ValueError(op)


def collect_consts(method) -> dict:
    """声明时用字面量（或可折叠的表达式）初始化、之后从未被赋值 / 自增自减的 int、char、boolean、String 局部变量。"""
    decl, modified = {}, set()
    for _, n in method.filter(T.LocalVariableDeclaration):
        tn = typename(n.type) if n.type else ""
        dims = getattr(n.type, "dimensions", None)
        for d in n.declarators:
            if tn in INT_TYPES and not dims and d.initializer is not None and not d.dimensions:
                decl[d.name] = d.initializer
    for _, n in method.filter(T.Assignment):
        if isinstance(n.expressionl, T.MemberReference):
            modified.add(n.expressionl.member)
    for _, n in method.filter(T.MemberReference):
        ops = (n.prefix_operators or []) + (n.postfix_operators or [])
        if "++" in ops or "--" in ops:
            modified.add(n.member)
    consts = {}
    for name, init in decl.items():
        if name in modified:
            continue
        try:
            consts[name] = Const(consts).ev(init)
        except Exception:
            pass
    return consts


# ---------- 保守污点分析 ----------
@dataclass
class Env:
    tainted: set = field(default_factory=set)
    lists: dict = field(default_factory=dict)  # 名字 → [bool] 或 None（无法精确建模）
    maps: dict = field(default_factory=dict)  # 名字 → {key: bool} 或 None
    writers: set = field(default_factory=set)
    aliases: dict = field(default_factory=dict)  # 名字 → 与它指向同一对象的本地变量集合

    def copy(self) -> "Env":
        return Env(set(self.tainted), {k: (list(v) if v is not None else None) for k, v in self.lists.items()},
                   {k: (dict(v) if v is not None else None) for k, v in self.maps.items()}, set(self.writers),
                   {k: set(v) for k, v in self.aliases.items()})

    def taint(self, name: str):
        """弄脏一个对象：所有指向同一对象的别名一起变脏。"""
        for n in self.aliases.get(name, {name}) | {name}:
            self.tainted.add(n)

    def merge(self, o: "Env") -> "Env":
        self.tainted |= o.tainted
        self.writers |= o.writers
        for k, v in o.aliases.items():
            self.aliases[k] = self.aliases.get(k, set()) | v
        for k in set(self.lists) | set(o.lists):
            a, b = self.lists.get(k), o.lists.get(k)
            self.lists[k] = a if a == b else None
        for k in set(self.maps) | set(o.maps):
            a, b = self.maps.get(k), o.maps.get(k)
            self.maps[k] = a if a == b else None
        return self


SAFE_COLL_OPS = {"add", "remove", "set", "get", "put", "size", "isEmpty", "contains", "containsKey"}


class Analyzer:
    def __init__(self, cu, cwe: str, prune: dict, untaint: set, precise_get: set, helper_src: dict | None = None):
        self.cu, self.cwe = cu, cwe
        self.prune, self.untaint, self.precise_get = prune, untaint, precise_get
        self.sinks: dict = {}  # id(node) → (line, tainted)
        self.depth = 0
        if any(True for _ in cu.filter(T.LambdaExpression)) or any(True for _ in cu.filter(T.MethodReference)):
            raise Unsupported("包含 lambda / 方法引用")
        for _, c in cu.filter(T.ClassCreator):
            if c.body:
                raise Unsupported("包含匿名类")
        methods = [m for _, m in cu.filter(T.MethodDeclaration)]
        names = [m.name for m in methods]
        if len(names) != len(set(names)):
            raise Unsupported("存在同名（重载）方法")
        self.methods = {m.name: m for m in methods}
        # 字段：只有 final 且用字面量初始化的才算干净，其余一律视为可能被污染
        self.fields, self.clean_fields = set(), set()
        for _, f in cu.filter(T.FieldDeclaration):
            for d in f.declarators:
                self.fields.add(d.name)
                if "final" in (f.modifiers or set()) and isinstance(d.initializer, T.Literal):
                    self.clean_fields.add(d.name)
        self.locals_stack: list[set] = []
        self.types_stack: list[dict] = []
        self.coll_ok_stack: list[set] = []

    # ----- 名字解析 -----
    def locals(self) -> set:
        return self.locals_stack[-1] if self.locals_stack else set()

    def name_tainted(self, name: str, env: Env) -> bool:
        if name in env.tainted:
            return True
        if name in self.locals():
            return False
        if name in self.fields:
            return name not in self.clean_fields
        if name == "this" or name[:1].isupper():  # 类名 / 常量：外部静态成员
            return False
        return True  # 不认识的裸名字：保守地当作污染

    def ref_tainted(self, e: T.MemberReference, env: Env) -> bool:
        if e.qualifier:
            first = e.qualifier.split(".")[0]
            if first == "this":
                t = self.name_tainted(e.member, env) if e.member in self.fields else False
            else:
                t = self.name_tainted(first, env) if (first in self.locals() or first in env.tainted or first in self.fields) else False
        else:
            t = self.name_tainted(e.member, env)
        return t or any(self.te(s, env) for s in (e.selectors or []))

    # ----- 表达式污点 -----
    def te(self, e, env: Env) -> bool:
        if e is None:
            return False
        if isinstance(e, (list, tuple)):
            return any(self.te(x, env) for x in e)
        if isinstance(e, T.Literal):
            return any(self.te(s, env) for s in (e.selectors or []))
        if isinstance(e, T.MemberReference):
            return self.ref_tainted(e, env)
        if isinstance(e, T.MethodInvocation):
            if id(e) in self.untaint:
                return False
            if id(e) in self.precise_get:
                r = self.precise_value(e, env)
                if r is not None:
                    return r
            if (not e.qualifier or e.qualifier == "this") and e.member in self.methods:
                return self.call_inner(e, env) | self.te(list(e.selectors or []), env)
            if e.qualifier:
                first = e.qualifier.split(".")[0]
                if first == "this" or first in self.locals() or first in env.tainted or first in self.fields:
                    if self.name_tainted(first if first != "this" else e.qualifier.split(".")[1] if "." in e.qualifier else "this", env):
                        return True
            return self.te(list(e.arguments or []), env) or self.te(list(e.selectors or []), env)
        if isinstance(e, T.ClassCreator):
            t = self.te(list(e.arguments or []), env)
            for s in e.selectors or []:
                if isinstance(s, T.MethodInvocation) and s.member in self.methods:
                    t = self.call_inner(s, env) or t
                else:
                    t = self.te(s, env) or t
            return t
        if isinstance(e, T.BinaryOperation):
            return self.te(e.operandl, env) or self.te(e.operandr, env)
        if isinstance(e, T.TernaryExpression):
            p = self.prune.get(id(e))
            if p == "then":
                return self.te(e.if_true, env)
            if p == "else":
                return self.te(e.if_false, env)
            return self.te(e.if_true, env) or self.te(e.if_false, env)
        if isinstance(e, T.Cast):
            return self.te(e.expression, env)
        if isinstance(e, T.ArrayInitializer):
            return self.te(list(e.initializers or []), env)
        if isinstance(e, T.ArrayCreator):
            return self.te(e.initializer, env) if e.initializer else False
        if isinstance(e, T.Assignment):
            return self.te(e.value, env)
        if isinstance(e, T.This):
            sels = e.selectors or []
            if sels and isinstance(sels[0], T.MemberReference) and sels[0].member in self.fields:
                return self.name_tainted(sels[0].member, env) or self.te(sels[1:], env)
            if sels and isinstance(sels[0], T.MethodInvocation) and sels[0].member in self.methods:
                return self.call_inner(sels[0], env) or self.te(sels[1:], env)
            return self.te(list(sels), env)
        if isinstance(e, T.ArraySelector):
            return self.te(e.index, env)
        if isinstance(e, (T.TypeArgument, T.ReferenceType, T.BasicType)):
            return False
        if isinstance(e, T.ClassReference):
            return False
        raise Unsupported(f"不支持的表达式 {type(e).__name__}")

    def precise_value(self, e, env: Env):
        q = e.qualifier
        if q not in (self.coll_ok_stack[-1] if self.coll_ok_stack else set()):
            return None
        if not q or e.member != "get" or len(e.arguments or []) != 1 or e.selectors:
            return None
        arg = e.arguments[0]
        if not isinstance(arg, T.Literal) or arg.prefix_operators:
            return None
        try:
            key = Const({}).ev(arg)
        except Exception:
            return None
        if q in env.lists and env.lists[q] is not None and isinstance(key, int) and not isinstance(key, bool):
            lst = env.lists[q]
            return lst[key] if 0 <= key < len(lst) else None
        if q in env.maps and env.maps[q] is not None and isinstance(key, str):
            return env.maps[q].get(key, False)
        return None

    def call_inner(self, inv, env: Env) -> bool:
        m = self.methods.get(inv.member)
        if m is None:
            return True
        if self.depth >= 4:
            raise Unsupported("调用层次太深")
        args = list(inv.arguments or [])
        if len(args) != len(m.parameters or []):
            raise Unsupported("参数个数不匹配")
        inner = Env()
        for p, a in zip(m.parameters, args):
            if self.te(a, env):
                inner.tainted.add(p.name)
        self.depth += 1
        try:
            ret = self.method_body(m, inner)
        finally:
            self.depth -= 1
        # 被调用的方法可能修改作为参数传入的对象：只要传入了污点数据，所有引用类型的实参都算污染
        if inner.tainted:
            for a in args:
                if isinstance(a, T.MemberReference) and not a.qualifier and a.member in self.locals():
                    env.tainted.add(a.member)
        return ret

    def method_body(self, m, env: Env) -> bool:
        local_names = {p.name for p in (m.parameters or [])}
        types = {p.name: typename(p.type) for p in (m.parameters or [])}
        for _, d in m.filter(T.LocalVariableDeclaration):
            for x in d.declarators:
                local_names.add(x.name)
                types[x.name] = typename(d.type)
        for _, d in m.filter(T.VariableDeclaration):
            for x in d.declarators:
                local_names.add(x.name)
                types[x.name] = typename(d.type)
        for _, c in m.filter(T.CatchClauseParameter):
            local_names.add(c.name)
        for _, c in m.filter(T.EnhancedForControl):
            v = c.var
            for x in getattr(v, "declarators", None) or []:
                local_names.add(x.name)
            if getattr(v, "name", None):
                local_names.add(v.name)
        for _, r in m.filter(T.TryResource):
            local_names.add(r.name)
            types[r.name] = typename(r.type)
        names = [p.name for p in (m.parameters or [])] + [x.name for _, d in m.filter(T.LocalVariableDeclaration) for x in d.declarators]
        if len(names) != len(set(names)):
            raise Unsupported("重复声明 / 与参数同名的局部变量")
        self.locals_stack.append(local_names)
        self.types_stack.append(types)
        self.coll_ok_stack.append(self.collections_unaliased(m))
        try:
            return self.block(m.body or [], env)
        finally:
            self.locals_stack.pop()
            self.types_stack.pop()
            self.coll_ok_stack.pop()

    def collections_unaliased(self, m) -> set:
        """只被 add/remove/get/put… 直接操作、从未被别名引用或传给别的方法的集合变量，才允许精确建模。"""
        used_as_value = {n.member for _, n in m.filter(T.MemberReference) if not n.qualifier}
        bad_ops = {n.qualifier for _, n in m.filter(T.MethodInvocation) if n.qualifier and n.member not in SAFE_COLL_OPS}
        return {name for name in self.locals() if name not in used_as_value and name not in bad_ops} if self.locals_stack else set()

    # ----- 副作用：赋值、调用、sink -----
    def effects(self, e, env: Env):
        if e is None:
            return
        if isinstance(e, (list, tuple)):
            for x in e:
                self.effects(x, env)
            return
        self.check_sink(e, env)
        for _, n in e.filter(T.Assignment):
            self.assign(n.expressionl, n.value, n.type, env)
        for _, n in e.filter(T.MethodInvocation):
            self.invocation_effect(n, env)

    def invocation_effect(self, n, env: Env):
        args = list(n.arguments or [])
        q = n.qualifier.split(".")[0] if n.qualifier else ""
        if (not n.qualifier or n.qualifier == "this") and n.member in self.methods:
            self.call_inner(n, env)
            return
        ta = [self.te(a, env) for a in args]
        # 链式调用 sb.append(a).append(b)：后面各层的参数也会写进同一个接收者
        chain_args = [x for sel in (n.selectors or []) if isinstance(sel, T.MethodInvocation) for x in (sel.arguments or [])]
        chain_tainted = any(self.te(x, env) for x in chain_args)
        coll_ok = self.coll_ok_stack[-1] if self.coll_ok_stack else set()
        if q and q in env.lists and env.lists[q] is not None and q in coll_ok:
            lst = env.lists[q]
            key = self._lit(args[0]) if args else None
            if n.member == "add" and len(args) == 1:
                lst.append(ta[0])
            elif n.member == "add" and len(args) == 2 and isinstance(key, int) and 0 <= key <= len(lst):
                lst.insert(key, ta[1])
            elif n.member == "remove" and len(args) == 1 and isinstance(key, int) and 0 <= key < len(lst):
                lst.pop(key)
            elif n.member == "set" and len(args) == 2 and isinstance(key, int) and 0 <= key < len(lst):
                lst[key] = ta[1]
            elif n.member not in ("get", "size", "isEmpty", "contains"):
                env.lists[q] = None
        elif q and q in env.lists:
            env.lists[q] = None
        if q and q in env.maps and env.maps[q] is not None and q in coll_ok:
            key = self._lit(args[0]) if args else None
            if n.member == "put" and len(args) == 2 and isinstance(key, str):
                env.maps[q][key] = ta[1]
            elif n.member not in ("get", "containsKey", "size", "isEmpty"):
                env.maps[q] = None
        elif q and q in env.maps:
            env.maps[q] = None
        if any(ta) or chain_tainted:
            # 污点数据进了方法：接收者、以及作为参数传入的本地对象都算污染（可能被写入）
            if q and q in self.locals():
                env.taint(q)
            for a in args + chain_args:
                if isinstance(a, T.MemberReference) and not a.qualifier and a.member in self.locals():
                    env.taint(a.member)
            for a in args:
                if isinstance(a, T.MemberReference) and not a.qualifier:
                    if a.member in env.lists:
                        env.lists[a.member] = None
                    if a.member in env.maps:
                        env.maps[a.member] = None

    @staticmethod
    def _lit(a):
        if isinstance(a, T.Literal) and not a.prefix_operators:
            try:
                return Const({}).ev(a)
            except Exception:
                return None
        return None

    def assign(self, target, value, op: str, env: Env):
        t = self.te(value, env)
        if isinstance(target, T.MemberReference):
            if not target.qualifier and not target.selectors and target.member in self.locals():
                name = target.member
                if op == "=":
                    # 先断开旧的别名关系
                    for other in env.aliases.pop(name, set()):
                        if other in env.aliases:
                            env.aliases[other].discard(name)
                    if t:
                        env.tainted.add(name)
                    else:
                        env.tainted.discard(name)
                    self._init_collection(name, value, env)
                    src = value.expression if isinstance(value, T.Cast) else value
                    if isinstance(src, T.MemberReference) and not src.qualifier and not src.selectors and src.member in self.locals():
                        group = env.aliases.get(src.member, {src.member}) | {src.member, name}
                        for g in group:
                            env.aliases[g] = set(group)
                        for g in (src.member,):
                            if g in env.lists:
                                env.lists[g] = None
                            if g in env.maps:
                                env.maps[g] = None
                    if isinstance(value, T.MethodInvocation) and value.member == "getWriter" and not value.selectors:
                        env.writers.add(name)
                    else:
                        env.writers.discard(name)
                elif t:
                    env.taint(name)
                return
            # 字段 / 数组元素 / 对象成员：只能变脏，不能变干净
            base = target.qualifier.split(".")[0] if target.qualifier else target.member
            if base == "this" and target.qualifier:
                base = target.member
            if t:
                if base in self.locals():
                    env.taint(base)
                    if base in env.lists:
                        env.lists[base] = None
                    if base in env.maps:
                        env.maps[base] = None
                elif base in self.fields:
                    self.clean_fields.discard(base)
            return
        if isinstance(target, T.This):
            sels = target.selectors or []
            if t and sels and isinstance(sels[0], T.MemberReference):
                self.clean_fields.discard(sels[0].member)
            return
        raise Unsupported(f"不支持的赋值目标 {type(target).__name__}")

    def _init_collection(self, name, value, env: Env):
        env.lists.pop(name, None)
        env.maps.pop(name, None)
        if isinstance(value, T.ClassCreator) and value.type is not None and not value.arguments:
            tn = typename(value.type).split(".")[-1]
            if tn in ("ArrayList", "LinkedList", "Vector"):
                env.lists[name] = []
            elif tn in ("HashMap", "LinkedHashMap", "TreeMap", "Hashtable"):
                env.maps[name] = {}

    def check_sink(self, e, env: Env):
        types = self.types_stack[-1] if self.types_stack else {}
        nodes = [n for _, n in e.filter(T.Node)]
        selector_ids = {id(x) for n in nodes for x in (getattr(n, "selectors", None) or [])}
        for n in nodes:
            if isinstance(n, T.MethodInvocation):
                if id(n) not in selector_ids:
                    self._sink_invocation(n, env, types)
                for s in n.selectors or []:
                    if isinstance(s, T.MethodInvocation):
                        self._sink_selector(n, s, env, types)
            elif isinstance(n, T.ClassCreator) and n.type is not None:
                tn = typename(n.type).split(".")[-1]
                args = list(n.arguments or [])
                for sel in n.selectors or []:
                    if self.cwe == "CWE-79" and isinstance(sel, T.MethodInvocation) and sel.member in XSS_METHODS and tn not in STRING_BUILDERS:
                        raise Unsupported(f"不认识的输出调用 new {tn}().{sel.member}")
                if self.cwe == "CWE-78" and tn == "ProcessBuilder":
                    self._record(n, self.te(args, env)) if args else self._record(n, False)
                elif self.cwe == "CWE-78" and tn in CMD_SUSPICIOUS:
                    raise Unsupported(f"不认识的命令执行写法 {tn}")
                elif self.cwe == "CWE-22" and tn in PATH_CLASSES and args:
                    self._record(n, self.te(args, env))

    def _record(self, n, tainted: bool):
        pos = getattr(n, "position", None)
        prev = self.sinks.get(id(n), (pos.line if pos else -1, False))
        self.sinks[id(n)] = (prev[0], prev[1] or tainted)

    def _sink_invocation(self, n, env: Env, types: dict):
        name, q = n.member, n.qualifier or ""
        last = q.split(".")[-1] if q else ""
        first = q.split(".")[0] if q else ""
        args = list(n.arguments or [])
        if self.cwe == "CWE-89" and (name.startswith(SQL_PREFIXES) or name in SQL_EXTRA):
            if args:
                self._record(n, self.te(args[0], env))
        elif self.cwe == "CWE-78" and name in ("exec", "command"):
            self._record(n, self.te(args, env))
        elif self.cwe == "CWE-22" and last in PATH_QUALIFIERS:
            if args:
                self._record(n, self.te(args, env))
        elif self.cwe == "CWE-22" and name in ("getResource", "getResourceAsStream") and args:
            self._record(n, self.te(args, env))
        elif self.cwe == "CWE-79" and name in XSS_METHODS and args:
            if first in env.writers:
                self._record(n, self.te(args, env))
            elif q in ("System.out", "System.err"):
                pass
            elif first and types.get(first, "").split(".")[-1] in STRING_BUILDERS:
                pass
            elif not q:
                raise Unsupported(f"不认识的输出调用 {name}")
            else:
                raise Unsupported(f"不认识的输出调用 {q}.{name}")

    def _sink_selector(self, n, s, env: Env, types: dict):
        """链式调用：response.getWriter().println(x)、response.getOutputStream().write(x)。"""
        if self.cwe == "CWE-79" and n.member in ("getWriter", "getOutputStream") and s.member in XSS_METHODS and s.arguments:
            self._record(n, self.te(list(s.arguments), env))
        elif self.cwe == "CWE-79" and s.member in XSS_METHODS:
            root = (n.qualifier or "").split(".")[0]
            if n.qualifier in ("System.out", "System.err") or types.get(root, "").split(".")[-1] in STRING_BUILDERS:
                return
            raise Unsupported(f"不认识的链式输出调用 {n.qualifier or ''}.{n.member}().{s.member}")
        elif self.cwe == "CWE-89" and (s.member.startswith(SQL_PREFIXES) or s.member in SQL_EXTRA) and s.arguments:
            self._record(s, self.te(s.arguments[0], env))
        elif self.cwe == "CWE-78" and s.member in ("exec", "command"):
            self._record(s, self.te(list(s.arguments or []), env))

    # ----- 语句 -----
    def block(self, stmts, env: Env) -> bool:
        ret = False
        for s in stmts or []:
            ret = self.stmt(s, env) or ret
        return ret

    def run_cases(self, cases, env: Env) -> bool:
        r = False
        for c in cases:
            r = self.block(c.statements, env) or r
            if any(isinstance(x, T.BreakStatement) for x in c.statements):
                break
        return r

    def stmt(self, s, env: Env) -> bool:
        if s is None:
            return False
        if isinstance(s, (T.LocalVariableDeclaration, T.VariableDeclaration)):
            for d in s.declarators:
                if d.initializer is not None:
                    self.effects(d.initializer, env)
                    self.assign(T.MemberReference(member=d.name, qualifier="", selectors=[], prefix_operators=[], postfix_operators=[]), d.initializer, "=", env)
            return False
        if isinstance(s, T.StatementExpression):
            self.effects(s.expression, env)
            return False
        if isinstance(s, T.IfStatement):
            self.effects(s.condition, env)
            p = self.prune.get(id(s))
            if p == "then":
                return self.stmt(s.then_statement, env)
            if p == "else":
                return self.stmt(s.else_statement, env) if s.else_statement else False
            a, b = env.copy(), env.copy()
            r = self.stmt(s.then_statement, a)
            r = (self.stmt(s.else_statement, b) if s.else_statement else False) or r
            self._replace(env, a.merge(b))
            return r
        if isinstance(s, T.SwitchStatement):
            self.effects(s.expression, env)
            cases = s.cases or []
            p = self.prune.get(id(s))
            if isinstance(p, int):
                return self.run_cases(cases[p:], env)
            has_default = any((not c.case) or any(isinstance(x, str) and x == "default" for x in c.case) for c in cases)
            out, r = (env.copy() if not has_default else None), False
            for i in range(len(cases)):
                e2 = env.copy()
                r = self.run_cases(cases[i:], e2) or r
                out = e2 if out is None else out.merge(e2)
            if out is not None:
                self._replace(env, out)
            return r
        if isinstance(s, T.BlockStatement):
            return self.block(s.statements, env)
        if isinstance(s, T.TryStatement):
            for res in s.resources or []:
                self.effects(res.value, env)
                self.assign(T.MemberReference(member=res.name, qualifier="", selectors=[], prefix_operators=[], postfix_operators=[]), res.value, "=", env)
            pre = env.copy()
            r = self.block(s.block, env)
            post = env.copy()
            outs = [post]
            for c in s.catches or []:
                e2 = pre.copy().merge(post)
                r = self.block(c.block, e2) or r
                outs.append(e2)
            merged = outs[0]
            for o in outs[1:]:
                merged = merged.merge(o)
            self._replace(env, merged)
            if s.finally_block:
                r = self.block(s.finally_block, env) or r
            return r
        if isinstance(s, (T.WhileStatement, T.DoStatement)):
            self.effects(s.condition, env)
            pre = env.copy()
            r = self.stmt(s.body, env)
            self.effects(s.condition, env)
            r = self.stmt(s.body, env) or r
            self.effects(s.condition, env)
            env.merge(pre)
            return r
        if isinstance(s, T.ForStatement):
            ctl = s.control
            pre = env.copy()
            if isinstance(ctl, T.EnhancedForControl):
                self.effects(ctl.iterable, env)
                t = self.te(ctl.iterable, env)
                for d in ctl.var.declarators:
                    (env.tainted.add if t else env.tainted.discard)(d.name)
            elif isinstance(ctl, T.ForControl):
                init = ctl.init
                if isinstance(init, (T.VariableDeclaration, T.LocalVariableDeclaration)):
                    self.stmt(init, env)
                else:
                    self.effects(init or [], env)
                self.effects(ctl.condition, env)
            else:
                raise Unsupported("不支持的 for 写法")
            r = False
            for _ in range(2):
                r = self.stmt(s.body, env) or r
                if isinstance(ctl, T.ForControl):
                    self.effects(ctl.update or [], env)
                    self.effects(ctl.condition, env)
            env.merge(pre)
            return r
        if isinstance(s, T.ReturnStatement):
            if s.expression is not None:
                self.effects(s.expression, env)
                return self.te(s.expression, env)
            return False
        if isinstance(s, T.ThrowStatement):
            self.effects(s.expression, env)
            return False
        if isinstance(s, T.SynchronizedStatement):
            self.effects(s.lock, env)
            return self.block(s.block, env)
        if isinstance(s, (T.BreakStatement, T.ContinueStatement, T.AssertStatement)):
            return False
        if type(s) is T.Statement:  # 空语句
            return False
        raise Unsupported(f"不支持的语句 {type(s).__name__}")

    @staticmethod
    def _replace(env: Env, other: Env):
        env.tainted, env.lists, env.maps, env.writers = other.tainted, other.lists, other.maps, other.writers

    def run(self) -> tuple[int, int]:
        """分析所有接收 HttpServletRequest 的方法；返回 (识别出的 sink 数, 有污点的 sink 数)。"""
        entries = [m for m in self.methods.values() if any(typename(p.type).split(".")[-1] in REQUEST_TYPES for p in (m.parameters or []))]
        if not entries:
            raise Unsupported("找不到接收 HttpServletRequest 的入口方法")
        for m in entries:
            env = Env()
            for p in m.parameters or []:
                if typename(p.type).split(".")[-1] in REQUEST_TYPES:
                    env.tainted.add(p.name)
            self.method_body(m, env)
        return len(self.sinks), sum(1 for _, t in self.sinks.values() if t)


# ---------- 理由核验 ----------
def find_nodes_on_line(cu, line: int, kinds):
    out = []
    for path, n in cu:
        if isinstance(n, kinds):
            stmt_line = None
            for p in [n, *reversed([x for x in path if isinstance(x, T.Node)])]:
                pos = getattr(p, "position", None)
                if pos:
                    stmt_line = pos.line
                    break
            if stmt_line == line:
                out.append(n)
    return out


def import_map(cu) -> dict:
    out = {}
    for imp in cu.imports or []:
        if not imp.wildcard and not imp.static:
            out[imp.path.split(".")[-1]] = imp.path
    return out


def call_chain(inv, imports: dict) -> tuple[str, list]:
    """把 a.b.C.m().n(x) 还原成 a.b.C.m.n，返回 (链, 各层调用的参数个数)。"""
    q = inv.qualifier or ""
    parts = q.split(".") if q else []
    if parts and parts[0] in imports:
        parts = imports[parts[0]].split(".") + parts[1:]
    parts.append(inv.member)
    argc = [len(inv.arguments or [])]
    for s in inv.selectors or []:
        if not isinstance(s, T.MethodInvocation):
            return "", []
        parts.append(s.member)
        argc.append(len(s.arguments or []))
    return ".".join(parts), argc


def repo_defines_sanitizer(cu, helper_src: dict | None) -> bool:
    pkg = cu.package.name if cu.package else ""
    if pkg.startswith(SANITIZER_PACKAGES):
        return True
    for _, c in cu.filter(T.ClassDeclaration):
        if c.name in SANITIZER_CLASSES:
            return True
    for src in (helper_src or {}).values():
        if re.search(rf"\bclass\s+({'|'.join(SANITIZER_CLASSES)})\b", src) or re.search(r"^\s*package\s+(" + "|".join(re.escape(p) for p in SANITIZER_PACKAGES) + r")", src, re.M):
            return True
    return False


def strip_java_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    return re.sub(r"//[^\n]*", " ", src)


def resolve_sanitizer(inv, cwe: str, imports: dict, helper_src: dict | None) -> bool:
    chain, argc = call_chain(inv, imports)
    if chain in SANITIZERS and cwe in SANITIZERS[chain] and argc and argc[-1] == 1 and all(c == 0 for c in argc[:-1]):
        return True
    # 仓库自带的辅助函数：函数体必须恰好是 return 白名单函数(唯一参数); 且没有同名重载
    if helper_src and inv.qualifier and not inv.selectors and len(inv.arguments or []) == 1:
        cls = inv.qualifier.split(".")[-1]
        src = strip_java_comments(helper_src.get(cls, ""))
        decls = re.findall(rf"\b(?:public|private|protected|static|final|synchronized)\b[\w\s<>\[\],.]*?\b{re.escape(inv.member)}\s*\(", src)
        if not src or len(decls) != 1:
            return False
        chains = "|".join(re.escape(c.rsplit(".", 1)[0].replace(".encoder", ".encoder()") + "." + c.rsplit(".", 1)[1]) for c, cw in SANITIZERS.items() if cwe in cw)
        m = re.search(rf"\b{re.escape(inv.member)}\s*\(\s*(?:final\s+)?String\s+(\w+)\s*\)\s*(?:throws[^{{]*)?\{{\s*return\s+({chains})\s*\(\s*\1\s*\)\s*;\s*\}}", src)
        return bool(m)
    return False


def verify(code: str, cwe: str, claim: dict, helper_src: dict | None = None, cu=None, flagged_lines: list | None = None) -> Result:
    try:
        c = Claim(str(claim.get("type", "")), int(claim.get("line", 0)), str(claim.get("expr", "")).strip())
    except (TypeError, ValueError):
        return Result(False, "理由格式不合法")
    lines = code.split("\n")
    if c.type in ("", "none"):
        return Result(False, "没有给出理由")
    if not c.expr:
        return Result(False, "原文缺失")
    # 1. 原文必须逐字出现在代码里，且不能整段落在字符串字面量内部（可以包含字符串，如 map.get("k")）。
    #    模型常把行号写偏一两行：以原文实际开始的行为准；原文出现在多处时，必须与声称的行一致。
    expr_norm = re.sub(r"\s+", " ", c.expr)
    starts = []
    for i in range(len(lines)):
        first = re.sub(r"\s+", " ", lines[i].strip())
        if first.startswith("//") or first.startswith("*") or first.startswith("/*"):
            continue
        window = re.sub(r"\s+", " ", " ".join(l.strip() for l in lines[i : i + 3]))
        pos = window.find(expr_norm)
        while pos != -1 and pos < len(first):
            if not inside_string(window, pos, len(expr_norm)):
                starts.append(i + 1)
                break
            pos = window.find(expr_norm, pos + 1)
    if not starts:
        return Result(False, "引用的原文不在代码中（或位于注释 / 字符串字面量里）")
    if c.line not in starts:
        if len(starts) > 1:
            return Result(False, "引用的原文在多处出现，且与声称的行号不符")
        c.line = starts[0]
    if cu is None:
        try:
            cu = javalang.parse.parse(code)
        except Exception:
            return Result(False, "代码无法解析")

    prune, untaint, precise = {}, set(), set()
    methods = [m for _, m in cu.filter(T.MethodDeclaration)]

    if c.type == "dead_branch":
        done = False
        for m in methods:
            cf = Const(collect_consts(m))
            for n in find_nodes_on_line(m, c.line, (T.IfStatement, T.TernaryExpression, T.SwitchStatement)):
                try:
                    if isinstance(n, T.SwitchStatement):
                        v = cf.ev(n.expression)
                        idx = None
                        for i, case in enumerate(n.cases):
                            labels = [cf.ev(x) for x in case.case if not isinstance(x, str)]
                            if v in labels:
                                idx = i
                                break
                        if idx is None:
                            idx = next((i for i, case in enumerate(n.cases) if (not case.case) or any(isinstance(x, str) and x == "default" for x in case.case)), None)
                        if idx is None:
                            continue
                        prune[id(n)] = idx
                    else:
                        v = cf.ev(n.condition)
                        if not isinstance(v, bool):
                            continue
                        prune[id(n)] = "then" if v else "else"
                    done = True
                except Exception:
                    continue
        if not done:
            return Result(False, "该行的条件无法按 Java 语义确定为常量")
    elif c.type == "key_mismatch":
        gets = [n for m in methods for n in find_nodes_on_line(m, c.line, (T.MethodInvocation,)) if n.member == "get"]
        if not gets:
            return Result(False, "该行没有集合取值")
        precise = {id(n) for n in gets}
    elif c.type == "sanitizer":
        if repo_defines_sanitizer(cu, helper_src):
            return Result(False, "被扫描的代码里定义了与白名单同名的类 / 包，不认可")
        imports = import_map(cu)
        cands = [n for m in methods for n in find_nodes_on_line(m, c.line, (T.MethodInvocation,))]
        ok = [n for n in cands if resolve_sanitizer(n, cwe, imports, helper_src)]
        if not ok:
            return Result(False, "该行没有适用于本类漏洞的白名单编码函数")
        untaint = {id(n) for n in ok}
    elif c.type not in ("overwritten", "param_query", "no_taint"):
        return Result(False, f"未知理由类型 {c.type}")

    try:
        an = Analyzer(cu, cwe, prune, untaint, precise, helper_src)
        n_sink, n_tainted = an.run()
    except Unsupported as exc:
        return Result(False, f"包含核验器不支持的写法（{exc}），交给人工")
    except RecursionError:
        return Result(False, "分析出错：递归过深")
    if n_sink == 0:
        return Result(False, "没找到本类漏洞的危险函数，无法确认", 0)
    if flagged_lines:
        sink_lines = {ln for ln, _ in an.sinks.values()}
        missing = [fl for fl in flagged_lines if not any(abs(fl - sl) <= 2 for sl in sink_lines)]
        if missing:
            return Result(False, f"扫描器报警的第 {missing[0]} 行不是核验器认识的危险函数，无法确认", n_sink)
    if n_tainted:
        return Result(False, f"代入理由后仍有 {n_tainted}/{n_sink} 个危险函数接收用户输入", n_sink)
    return Result(True, f"代入理由后 {n_sink} 个危险函数都不再接收用户输入", n_sink)


def candidate_claims(code: str) -> list[dict]:
    """枚举一份代码里「看起来可能」的理由（启发式挑选的候选行），用于核验器自检：
    真漏洞上不应有任何理由能通过；误报上至少有一个理由能通过的比例 = 大模型能做到的上限。"""
    lines = code.split("\n")
    out = []
    for i, raw in enumerate(lines, 1):
        t = raw.strip()
        if not t or t.startswith("import") or t.startswith("package"):
            continue
        if re.search(r"\bif\s*\(|\?.*:|switch\s*\(", t):
            out.append({"type": "dead_branch", "line": i, "expr": t})
        if ".get(" in t:
            out.append({"type": "key_mismatch", "line": i, "expr": t})
        if re.search(r"encode|escape|Escape|htmlEscape|forHtml", t):
            out.append({"type": "sanitizer", "line": i, "expr": t})
    first = next((i for i, l in enumerate(lines, 1) if l.strip().startswith(("public void doPost", "public void doGet"))), 1)
    out.append({"type": "no_taint", "line": first, "expr": lines[first - 1].strip()})
    return out
