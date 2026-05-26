

from __future__ import annotations

import re
from typing import List

from .lexer import tokenize, Token, TokenType
from .parser import (
    parse,
    ASTNode,
    ProgramNode,
    FunctionDeclNode,
    FunctionCallNode,
    VarDeclNode,
    AssignmentNode,
    ForNode,
    WhileNode,
    IfNode,
    ReturnNode,
    ExpressionNode,
)
from .rules import VULNERABILITY_RULES




UNSAFE_FUNCTIONS: dict[str, dict] = {

    "gets":     {"type": "buffer_overflow",    "severity": "HIGH",   "fix": "Use fgets() with a size limit."},
    "strcpy":   {"type": "buffer_overflow",    "severity": "HIGH",   "fix": "Use strncpy() or strlcpy()."},
    "strcat":   {"type": "buffer_overflow",    "severity": "HIGH",   "fix": "Use strncat() or strlcat()."},
    "sprintf":  {"type": "buffer_overflow",    "severity": "HIGH",   "fix": "Use snprintf() with a size limit."},
    "vsprintf": {"type": "buffer_overflow",    "severity": "HIGH",   "fix": "Use vsnprintf()."},
    "getwd":    {"type": "buffer_overflow",    "severity": "HIGH",   "fix": "Use getcwd() with a size limit."},
    "scanf":    {"type": "buffer_overflow",    "severity": "MEDIUM", "fix": "Limit input width, e.g. scanf(\"%99s\", buf)."},
    "wcscpy":   {"type": "buffer_overflow",    "severity": "HIGH",   "fix": "Use wcsncpy()."},
    "wcscat":   {"type": "buffer_overflow",    "severity": "HIGH",   "fix": "Use wcsncat()."},
    "stpcpy":   {"type": "buffer_overflow",    "severity": "HIGH",   "fix": "Use stpncpy()."},
    "realpath": {"type": "buffer_overflow",    "severity": "MEDIUM", "fix": "Ensure resolved buffer is PATH_MAX."},

    "system":   {"type": "command_injection",  "severity": "HIGH",   "fix": "Avoid system(); use execvp() with validated args."},
    "popen":    {"type": "command_injection",  "severity": "HIGH",   "fix": "Avoid popen(); use pipe()+fork()+exec()."},
    "exec":     {"type": "command_injection",  "severity": "HIGH",   "fix": "Sanitise all arguments."},
    "execl":    {"type": "command_injection",  "severity": "HIGH",   "fix": "Never pass user input directly."},
    "execle":   {"type": "command_injection",  "severity": "HIGH",   "fix": "Sanitise inputs."},
    "execlp":   {"type": "command_injection",  "severity": "HIGH",   "fix": "Avoid user-controlled args."},
    "execv":    {"type": "command_injection",  "severity": "HIGH",   "fix": "Validate all arguments."},
    "execvp":   {"type": "command_injection",  "severity": "HIGH",   "fix": "Avoid user input in exec."},

    "atoi":     {"type": "input_validation",   "severity": "MEDIUM", "fix": "Use strtol() with error checking."},
    "atof":     {"type": "input_validation",   "severity": "MEDIUM", "fix": "Use strtod() with error checking."},
    "atol":     {"type": "input_validation",   "severity": "MEDIUM", "fix": "Use strtol() with error checking."},

    "tmpnam":   {"type": "unsafe_tmp_file",    "severity": "HIGH",   "fix": "Use mkstemp() instead."},
    "mktemp":   {"type": "unsafe_tmp_file",    "severity": "HIGH",   "fix": "Use mkstemp() instead."},
    "tempnam":  {"type": "unsafe_tmp_file",    "severity": "HIGH",   "fix": "Use mkstemp() instead."},

    "rand":     {"type": "weak_random",        "severity": "MEDIUM", "fix": "Use a cryptographic RNG for security-sensitive code."},
    "srand":    {"type": "weak_random",        "severity": "LOW",    "fix": "srand()+rand() is not cryptographically secure."},

    "md5":      {"type": "insecure_hash",      "severity": "HIGH",   "fix": "Use SHA-256 or stronger."},
    "sha1":     {"type": "insecure_hash",      "severity": "HIGH",   "fix": "SHA-1 is broken; use SHA-256."},
    "MD5_Init": {"type": "insecure_hash",      "severity": "HIGH",   "fix": "Use SHA-256 or bcrypt."},
    "SHA1_Init":{"type": "insecure_hash",      "severity": "HIGH",   "fix": "SHA-1 is broken; use SHA-256."},

    "access":   {"type": "race_condition",     "severity": "MEDIUM", "fix": "TOCTOU risk — open file directly and check error."},

    "setuid":   {"type": "privilege_escalation","severity": "HIGH",   "fix": "Avoid privilege escalation; drop privileges early."},
    "seteuid":  {"type": "privilege_escalation","severity": "HIGH",   "fix": "Drop privileges as soon as possible."},
    "setgid":   {"type": "privilege_escalation","severity": "HIGH",   "fix": "Check return value."},

    "cuserid":  {"type": "deprecated_function","severity": "MEDIUM", "fix": "Removed in POSIX.1-2001; use getlogin_r()."},
    "rindex":   {"type": "deprecated_function","severity": "LOW",    "fix": "Use strrchr()."},
    "bcopy":    {"type": "deprecated_function","severity": "LOW",    "fix": "Use memmove()."},
    "bzero":    {"type": "deprecated_function","severity": "LOW",    "fix": "Use memset()."},
}


_PRINTF_FAMILY = {"printf", "fprintf", "sprintf", "snprintf", "syslog", "wprintf", "dprintf"}




def analyze(code: str) -> list[dict]:
    """
    Run the full three-phase compiler pipeline and return a vulnerability
    report as a list of finding dicts.
    """

    tokens = tokenize(code)


    ast = parse(tokens)


    report: list[dict] = []
    seen: set[tuple] = set()


    _check_unsafe_calls(ast, report, seen)
    _check_format_strings(ast, report, seen)
    _check_use_after_free(ast, report, seen)
    _check_double_free(ast, report, seen)
    _check_unchecked_return(ast, report, seen, code)
    _check_large_stack_arrays(ast, report, seen)
    _check_uninitialized_vars(ast, report, seen)


    _regex_sweep(code, report, seen)

    return report




def _walk(node: ASTNode):

    if not isinstance(node, ASTNode):
        return
    yield node

    for attr in ["children", "body", "then_body", "else_body", "arguments", "initializer", "value"]:
        val = getattr(node, attr, None)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, ASTNode):
                    yield from _walk(item)
        elif isinstance(val, ASTNode):
            yield from _walk(val)


def _add(report, seen, **finding):
    key = (finding["type"], finding["line"], finding.get("pattern", ""))
    if key not in seen:
        seen.add(key)
        report.append(finding)




def _check_unsafe_calls(ast: ASTNode, report, seen):

    for node in _walk(ast):
        if isinstance(node, FunctionCallNode) and node.name in UNSAFE_FUNCTIONS:
            info = UNSAFE_FUNCTIONS[node.name]
            _add(report, seen,
                 type=info["type"], pattern=f"{node.name}()",
                 severity=info["severity"], fix=info["fix"],
                 line=node.line, phase="semantic")


def _check_format_strings(ast: ASTNode, report, seen):
    """
    Detect format-string vulnerabilities:
      printf(variable)           → HIGH  (user-controlled format)
      printf("%s", variable)     → safe
    """
    for node in _walk(ast):
        if not isinstance(node, FunctionCallNode):
            continue
        if node.name not in _PRINTF_FAMILY:
            continue


        fmt_idx = 1 if node.name in ("fprintf", "snprintf", "dprintf") else 0
        if node.name == "snprintf":
            fmt_idx = 2  # snprintf(buf, size, fmt, ...)

        args = node.arguments
        if len(args) <= fmt_idx:
            continue

        fmt_arg = args[fmt_idx]
        if isinstance(fmt_arg, ExpressionNode) and fmt_arg.tokens:
            first = fmt_arg.tokens[0]
            if first.type != TokenType.STRING:
                _add(report, seen,
                     type="format_string",
                     pattern=f"{node.name}()",
                     severity="HIGH",
                     fix=f'Do not pass a variable as the format string. Use {node.name}("%s", var) instead.',
                     line=node.line, phase="semantic")


def _check_use_after_free(ast: ASTNode, report, seen):
    """
    Track free(ptr) calls inside function bodies; flag if ptr is used
    again later without being reassigned.
    """
    for node in _walk(ast):
        if not isinstance(node, FunctionDeclNode):
            continue
        _uaf_in_stmts(node.body, report, seen)


def _uaf_in_stmts(stmts: list[ASTNode], report, seen):
    # Tracks pointers that have been freed (var name -> line freed).
    # Used to flag subsequent uses without an intervening re-assignment.
    freed: dict[str, int] = {}


    for stmt in stmts:

        if isinstance(stmt, FunctionCallNode) and stmt.name == "free":
            if stmt.arguments:
                arg = stmt.arguments[0]
                if isinstance(arg, ExpressionNode) and len(arg.tokens) == 1:
                    freed[arg.tokens[0].value] = stmt.line
            continue


        # ONLY if the target is exactly the name (ptr = ...), NOT a dereference (*ptr = ...)
        if isinstance(stmt, AssignmentNode) and stmt.target in freed:
            del freed[stmt.target]
            continue


        if freed:
            for tok in _all_tokens(stmt):
                if tok.type == TokenType.IDENTIFIER and tok.value in freed:
                    _add(report, seen,
                         type="use_after_free",
                         pattern=f"use of '{tok.value}' after free()",
                         severity="HIGH",
                         fix=f"Pointer '{tok.value}' was freed on line {freed[tok.value]}. Set to NULL after free.",
                         line=tok.line, phase="semantic")


def _check_double_free(ast: ASTNode, report, seen):

    for node in _walk(ast):
        if not isinstance(node, FunctionDeclNode):
            continue
        _double_free_in_stmts(node.body, report, seen)


def _double_free_in_stmts(stmts: list[ASTNode], report, seen):
    freed: dict[str, int] = {}

    for stmt in stmts:
        if isinstance(stmt, FunctionCallNode) and stmt.name == "free":
            if stmt.arguments:
                arg = stmt.arguments[0]
                if isinstance(arg, ExpressionNode) and len(arg.tokens) == 1:
                    var = arg.tokens[0].value
                    if var in freed:
                        _add(report, seen,
                             type="double_free",
                             pattern=f"double free of '{var}'",
                             severity="HIGH",
                             fix=f"'{var}' was already freed on line {freed[var]}. Set pointer to NULL after free.",
                             line=stmt.line, phase="semantic")
                    else:
                        freed[var] = stmt.line
            continue


        if isinstance(stmt, AssignmentNode) and stmt.target in freed:
            del freed[stmt.target]


def _check_unchecked_return(ast: ASTNode, report, seen, code: str):
    """
    Flag malloc/calloc/fopen calls whose return value is used
    without a NULL check nearby.
    """
    alloc_fns = {"malloc", "calloc", "realloc", "fopen", "fopen64"}
    lines = code.splitlines()

    for node in _walk(ast):
        if not isinstance(node, FunctionDeclNode):
            continue

        for stmt in node.body:

            if isinstance(stmt, AssignmentNode) and stmt.value:
                vtoks = _expr_tokens(stmt.value)
                call_names = [t.value for t in vtoks if t.type == TokenType.IDENTIFIER]
                for fn in call_names:
                    if fn in alloc_fns:
                        var = stmt.target

                        if not _has_null_check(lines, stmt.line, var):
                            _add(report, seen,
                                 type="unchecked_return",
                                 pattern=f"{fn}() return unchecked",
                                 severity="MEDIUM",
                                 fix=f"Check if '{var}' is NULL after {fn}().",
                                 line=stmt.line, phase="semantic")
                        break


def _has_null_check(lines: list[str], start_line: int, var: str) -> bool:

    end = min(start_line + 6, len(lines))
    for i in range(start_line, end):
        line = lines[i]
        if re.search(rf"\b{re.escape(var)}\s*==\s*NULL\b", line):
            return True
        if re.search(rf"\b{re.escape(var)}\s*!=\s*NULL\b", line):
            return True
        if re.search(rf"if\s*\(\s*!?\s*{re.escape(var)}\s*\)", line):
            return True
    return False


def _check_large_stack_arrays(ast: ASTNode, report, seen):

    THRESHOLD = 10_000

    for node in _walk(ast):
        if isinstance(node, VarDeclNode) and node.is_array:
            try:
                size = int(node.array_size)
                if size >= THRESHOLD:
                    _add(report, seen,
                         type="stack_overflow",
                         pattern=f"{node.name}[{size}]",
                         severity="MEDIUM",
                         fix=f"Array of {size} elements on stack may cause overflow. Use heap allocation.",
                         line=node.line, phase="semantic")
            except (ValueError, TypeError):
                pass


def _check_uninitialized_vars(ast: ASTNode, report, seen):

    for node in _walk(ast):
        if isinstance(node, VarDeclNode):
            if node.is_pointer and node.initializer is None and not node.is_array:
                _add(report, seen,
                     type="uninitialized_pointer",
                     pattern=f"{node.var_type} {node.name}",
                     severity="MEDIUM",
                     fix=f"Initialise pointer '{node.name}' to NULL on declaration.",
                     line=node.line, phase="semantic")




def _regex_sweep(code: str, report, seen):
    """
    Run regex-based rules from rules.py for patterns that benefit from
    raw text scanning (hardcoded secrets, magic permissions, etc.).
    """
    lines = code.splitlines()

    def strip_comments(line: str) -> str:
        return re.sub(r"//.*", "", line)


    supplementary = {
        "hardcoded_secret", "insecure_permissions", "env_exposure",
        "unsafe_file_handling", "infinite_loop", "integer_overflow",
    }

    for vuln_type, rule_list in VULNERABILITY_RULES.items():
        if vuln_type not in supplementary:
            continue

        for rule in rule_list:
            pattern = rule.get("pattern", "")
            severity = rule.get("severity", "HIGH")
            fix = rule.get("fix", "")
            if not pattern:
                continue

            looks_like_regex = bool(re.search(r"[\\{}\[\]+*?|^$]", pattern))
            if looks_like_regex:
                try:
                    regex = re.compile(pattern)
                except re.error:
                    continue
                label = pattern
            else:
                func_name = pattern.replace("(", "")
                regex = re.compile(r"\b" + re.escape(func_name) + r"\s*\(")
                label = func_name + "("

            for idx, line in enumerate(lines, start=1):
                clean = strip_comments(line)
                if regex.search(clean):

                    issue_severity = severity
                    issue_fix = fix
                    if vuln_type == "integer_overflow":
                        var_match = re.search(r"malloc\s*\(\s*([A-Za-z_]\w*)\s*\*\s*sizeof", clean)
                        if var_match:
                            var = var_match.group(1)
                            has_guard = _has_overflow_guard(lines, idx, var)
                            issue_severity = "LOW" if has_guard else "MEDIUM"
                            issue_fix = (
                                f"Validate size before allocation: "
                                f"if ({var} > SIZE_MAX / sizeof(type)) {{ abort(); }}"
                            )

                    _add(report, seen,
                         type=vuln_type, pattern=label,
                         severity=issue_severity, fix=issue_fix,
                         line=idx, phase="regex")


def _has_overflow_guard(lines: list[str], line_idx: int, var_name: str) -> bool:
    start = max(0, line_idx - 10)
    guard_re = re.compile(
        rf"if\s*\(\s*{re.escape(var_name)}\s*>"
        r"\s*(?:INT_MAX|UINT_MAX|LONG_MAX|ULONG_MAX|SIZE_MAX)\s*/\s*sizeof\s*\("
    )
    for candidate in lines[start:line_idx]:
        clean = re.sub(r"//.*", "", candidate)
        if guard_re.search(clean):
            return True
    return False




def _all_tokens(node: ASTNode) -> list[Token]:

    result: list[Token] = []
    for child in _walk(node):
        if isinstance(child, ExpressionNode):
            result.extend(child.tokens)
        if isinstance(child, FunctionCallNode):
            result.append(Token(TokenType.IDENTIFIER, child.name, child.line))
        if isinstance(child, AssignmentNode):

            target = child.target

            for match in re.finditer(r'\b[A-Za-z_]\w*\b', target):
                result.append(Token(TokenType.IDENTIFIER, match.group(), child.line))
    return result


def _expr_tokens(node: ASTNode) -> list[Token]:

    if isinstance(node, ExpressionNode):
        return node.tokens
    return []