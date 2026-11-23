#!/usr/bin/env python3
"""Static checks for the PowerShell engine (winharden.ps1 and engine/*.ps1).

Why this exists: the engine is written for Windows PowerShell 5.1 and cannot be executed where it is developed. These
checks are a safety net, not a proof. They catch the mistakes that a quick read misses:

  * non-ASCII text (5.1 reads a script without a BOM as ANSI) and syntax from newer PowerShell versions;
  * unbalanced braces, parentheses and brackets;
  * a call to a function that does not exist, or with a parameter that function does not have;
  * a variable that is used but never assigned (a typo reads as $null in PowerShell, silently);
  * the wrong number of arguments in a provider call (Invoke-WhProv 'Name' ...);
  * a statement-level call to a function that returns a value (it leaks into the caller's output);
  * provider tables that disagree with each other, and operation types that a dispatcher forgets;
  * index assignment on a [pscustomobject] ($facts['x'] = ...), which PowerShell does not allow.

It reads text only. Usage:  python tools/check_engine.py   (exit status 1 when it finds a problem)
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

AUTOMATIC = {
    "_", "args", "input", "true", "false", "null", "psitem", "psscriptroot", "pscommandpath", "pshome", "home", "pwd",
    "error", "lastexitcode", "erroractionpreference", "warningpreference", "progresspreference", "verbosepreference",
    "matches", "executioncontext", "host", "pscmdlet", "myinvocation", "pid", "foreach", "switch", "this", "psboundparameters",
    "confirmpreference", "whatifpreference", "psversiontable", "profile", "shellid", "stacktrace", "pssenderinfo",
}
SCOPES = ("script", "global", "local", "private", "using", "env")
OPERATORS = {
    "eq", "ne", "gt", "ge", "lt", "le", "like", "notlike", "match", "notmatch", "contains", "notcontains", "in", "notin",
    "is", "isnot", "as", "and", "or", "not", "xor", "band", "bor", "bxor", "bnot", "shl", "shr", "join", "split",
    "replace", "f", "ceq", "cne", "cgt", "cge", "clt", "cle", "clike", "cnotlike", "cmatch", "cnotmatch", "ccontains",
    "cnotcontains", "ieq", "ine", "igt", "ige", "ilt", "ile", "ilike", "inotlike", "imatch", "inotmatch", "icontains",
    "inotcontains", "creplace", "ireplace", "csplit", "isplit",
}
# Statement-level calls of these built-ins produce output that must not leak into a function's result.
LEAKY_CMDLETS = (
    "New-Item", "Disable-ScheduledTask", "Enable-ScheduledTask", "Register-ScheduledTask", "Enable-WindowsOptionalFeature",
    "Disable-WindowsOptionalFeature", "Remove-AppxProvisionedPackage", "Start-Process", "New-Object",
)
BANNED = [
    (r"\?\?", "null-coalescing operator (PowerShell 7)"),
    (r"\?\.\w", "null-conditional member access (PowerShell 7)"),
    (r"\?\[", "null-conditional index (PowerShell 7)"),
    (r"&&", "pipeline chain operator && (PowerShell 7)"),
    (r"\|\|", "pipeline chain operator || (PowerShell 7)"),
    (r"-Parallel\b", "-Parallel (PowerShell 7)"),
    (r"\$Is(?:Windows|Linux|MacOS)\b", "$IsWindows and friends (PowerShell 6+)"),
    (r"-AsHashtable\b", "ConvertFrom-Json -AsHashtable (PowerShell 6+)"),
    (r"-NoEnumerate\b", "ConvertFrom-Json -NoEnumerate (PowerShell 6.2+)"),
    (r"\bTest-Json\b", "Test-Json (PowerShell 6+)"),
    (r"\bJoin-String\b", "Join-String (PowerShell 6.2+)"),
    (r"-AsByteStream\b", "-AsByteStream (PowerShell 6+)"),
    (r"\bGet-Error\b", "Get-Error (PowerShell 7)"),
    (r"\$PSStyle\b", "$PSStyle (PowerShell 7.2)"),
    (r"\[Environment\]::ProcessPath", "Environment.ProcessPath (.NET 6)"),
    (r"System\.Collections\.ArrayList", "ArrayList.Add returns the index and leaks into the output; use List[T]"),
    (r"@\(\s*ConvertFrom-(?:Wh)?Json\b", "@(ConvertFrom-Json ...) nests a top-level array on 5.1; assign the result and flatten"),
    (r"\bConvertFrom-Json\b[^\n]*-Depth\b", "ConvertFrom-Json -Depth does not exist on 5.1"),
    (r"-Encoding\s+(?:utf8NoBOM|UTF8BOM|utf8)\b", "-Encoding utf8 variants differ between 5.1 and 7; use the .NET encoding"),
]


@dataclass
class Problem:
    file: str
    line: int
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: [{self.code}] {self.message}"


@dataclass
class Func:
    name: str
    file: str
    line: int
    params: list[str]
    body: str  # comments and string contents blanked
    body_text: str  # comments blanked, strings kept
    start: int  # offset of the body in the blanked file text
    returns_value: bool = False


@dataclass
class Source:
    path: Path
    rel: str
    raw: str
    nocomment: str = ""
    blank: str = ""
    funcs: list[Func] = field(default_factory=list)
    dq_with_dollar: list[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Lexing: blank out comments and strings, keep offsets and line breaks
# ---------------------------------------------------------------------------
def _blank_run(text: str) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in text)


def _blank_string(text: str) -> str:
    """Content of a string literal: not whitespace, so a tokenizer still sees one token."""
    return "".join("\n" if ch == "\n" else "\x01" for ch in text)


def strip_source(src: str) -> tuple[str, str, list[int]]:
    """Returns (nocomment, blank, offsets of double-quoted strings that contain an unescaped dollar)."""
    nocomment: list[str] = []
    blank: list[str] = []
    dq_dollar: list[int] = []
    i, n = 0, len(src)

    def emit(raw: str, keep_text: bool, keep_blank: bool) -> None:
        nocomment.append(raw if keep_text else _blank_run(raw))
        blank.append(raw if keep_blank else _blank_run(raw))

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "<" and nxt == "#":
            j = src.find("#>", i + 2)
            j = n if j < 0 else j + 2
            emit(src[i:j], False, False)
            i = j
            continue
        if c == "#":
            j = src.find("\n", i)
            j = n if j < 0 else j
            emit(src[i:j], False, False)
            i = j
            continue
        if c == "@" and nxt in ("'", '"'):
            m = re.match(r"@" + re.escape(nxt) + r"[ \t]*\r?\n", src[i:])
            if m:
                close = "\n" + nxt + "@"
                j = src.find(close, i + m.end() - 1)
                j = n if j < 0 else j + len(close)
                emit(src[i:j], True, False)
                i = j
                continue
        if c == "'":
            j = i + 1
            while j < n:
                if src[j] == "'":
                    if j + 1 < n and src[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            j = min(j + 1, n)
            emit(src[i:j], True, False)
            blank[-1] = "'" + _blank_string(src[i + 1 : j - 1]) + "'"
            i = j
            continue
        if c == '"':
            j = i + 1
            has_dollar = False
            while j < n:
                ch = src[j]
                if ch == "`":
                    j += 2
                    continue
                if ch == '"':
                    if j + 1 < n and src[j + 1] == '"':
                        j += 2
                        continue
                    break
                if ch == "$" and j + 1 < n and (src[j + 1].isalpha() or src[j + 1] in "_({"):
                    has_dollar = True
                j += 1
            j = min(j + 1, n)
            if has_dollar:
                dq_dollar.append(i)
            emit(src[i:j], True, False)
            blank[-1] = '"' + _blank_string(src[i + 1 : j - 1]) + '"'
            i = j
            continue
        emit(c, True, True)
        i += 1
    return "".join(nocomment), "".join(blank), dq_dollar


def match_close(text: str, open_pos: int) -> int:
    """Offset of the bracket that closes the one at open_pos, or -1."""
    pairs = {"{": "}", "(": ")", "[": "]"}
    stack: list[str] = []
    for k in range(open_pos, len(text)):
        ch = text[k]
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")}]":
            if not stack or stack.pop() != ch:
                return -1
            if not stack:
                return k
    return -1


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def split_top_level(text: str, sep: str = ",") -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def parse_param_names(block: str) -> list[str]:
    names = []
    for item in split_top_level(block):
        head = item.split("=", 1)[0]
        head = re.sub(r"\[[^\]]*\]", " ", head)
        m = re.search(r"\$([A-Za-z_]\w*)", head)
        if m:
            names.append(m.group(1))
    return names


FUNC_RE = re.compile(r"^[ \t]*function[ \t]+([A-Za-z][\w\-]*)[ \t]*\{", re.M)


def load_source(path: Path, root: Path) -> Source:
    raw = path.read_text(encoding="utf-8")
    src = Source(path=path, rel=path.relative_to(root).as_posix(), raw=raw)
    src.nocomment, src.blank, src.dq_with_dollar = strip_source(raw)
    for m in FUNC_RE.finditer(src.blank):
        open_pos = m.end() - 1
        close = match_close(src.blank, open_pos)
        if close < 0:
            continue
        body = src.blank[open_pos + 1 : close]
        body_text = src.nocomment[open_pos + 1 : close]
        params: list[str] = []
        pm = re.match(r"\s*(?:\[[^\]]*\]\s*)*param\s*\(", body)
        if pm:
            popen = open_pos + 1 + pm.end() - 1
            pclose = match_close(src.blank, popen)
            if pclose > 0:
                params = parse_param_names(src.blank[popen + 1 : pclose])
        fn = Func(m.group(1), src.rel, line_of(src.blank, m.start()), params, body, body_text, open_pos + 1)
        fn.returns_value = bool(re.search(r"\breturn\s+(?![;}\s])", body)) or bool(re.search(r"\breturn\s*\(", body))
        src.funcs.append(fn)
    return src


def engine_files(root: Path) -> list[Path]:
    files = [root / "winharden.ps1"]
    files += sorted((root / "engine").glob("*.ps1"))
    return [f for f in files if f.exists()]


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------
def check_text(sources: list[Source]) -> list[Problem]:
    out: list[Problem] = []
    for s in sources:
        data = s.path.read_bytes()
        for i, b in enumerate(data):
            if b > 127:
                out.append(Problem(s.rel, data.count(b"\n", 0, i) + 1, "ASCII", "non-ASCII byte; Windows PowerShell 5.1 reads a file without a BOM as ANSI"))
                break
        if b"\t" in data:
            out.append(Problem(s.rel, data.index(b"\t") and data.count(b"\n", 0, data.index(b"\t")) + 1, "STYLE", "tab character; use spaces"))
        for pattern, why in BANNED:
            for m in re.finditer(pattern, s.blank):
                out.append(Problem(s.rel, line_of(s.blank, m.start()), "SYNTAX", why))
        for pos in s.dq_with_dollar:
            out.append(Problem(s.rel, line_of(s.raw, pos), "STYLE", "double-quoted string with a $ (interpolation); build the text with + instead"))
        for open_ch, close_ch in ("{}", "()", "[]"):
            if s.blank.count(open_ch) != s.blank.count(close_ch):
                out.append(Problem(s.rel, 1, "BALANCE", f"unbalanced {open_ch}{close_ch}: {s.blank.count(open_ch)} open, {s.blank.count(close_ch)} close"))
        if not s.raw.endswith("\n"):
            out.append(Problem(s.rel, line_of(s.raw, len(s.raw)), "STYLE", "no newline at end of file"))
    return out


def all_functions(sources: list[Source]) -> dict[str, Func]:
    table: dict[str, Func] = {}
    for s in sources:
        for fn in s.funcs:
            table.setdefault(fn.name.lower(), fn)
    return table


def check_duplicates(sources: list[Source]) -> list[Problem]:
    seen: dict[str, Func] = {}
    out = []
    for s in sources:
        for fn in s.funcs:
            key = fn.name.lower()
            if key in seen:
                out.append(Problem(s.rel, fn.line, "DUP", f"function {fn.name} is also defined in {seen[key].file}:{seen[key].line}"))
            else:
                seen[key] = fn
    return out


CALL_RE = re.compile(r"(?<![\w\-$.:])([A-Za-z]+-Wh[A-Za-z0-9]+)\b")


def call_params(blank: str, end: int) -> tuple[list[str], list[str]]:
    """Named parameters and depth-0 positional tokens of a call whose name ends at `end`."""
    names: list[str] = []
    positional: list[str] = []
    depth = 0
    k, n = end, len(blank)
    token: list[str] = []

    def flush() -> None:
        if token:
            positional.append("".join(token))
            token.clear()

    while k < n:
        ch = blank[k]
        if depth == 0:
            if ch in ";|":
                break
            if ch in ")}]":
                break
            if ch == "\n":
                break
        if ch in "([{":
            depth += 1
            token.append(ch)
        elif ch in ")]}":
            depth -= 1
            token.append(ch)
        elif depth == 0 and ch in " \t":
            flush()
        else:
            token.append(ch)
        k += 1
    flush()
    skip_next = False
    for tok in positional:
        m = re.fullmatch(r"-([A-Za-z][A-Za-z0-9]*)(?::.*)?", tok)
        if m and m.group(1).lower() not in OPERATORS:
            names.append(m.group(1))
    return names, positional


def check_calls(sources: list[Source], funcs: dict[str, Func]) -> list[Problem]:
    out: list[Problem] = []
    for s in sources:
        for m in CALL_RE.finditer(s.blank):
            name = m.group(1)
            before = s.blank[max(0, m.start() - 12) : m.start()]
            if re.search(r"function\s+$", before):
                continue
            fn = funcs.get(name.lower())
            line = line_of(s.blank, m.start())
            if fn is None:
                out.append(Problem(s.rel, line, "CALL", f"call to undefined function {name}"))
                continue
            names, positional = call_params(s.blank, m.end())
            declared = [p.lower() for p in fn.params]
            for given in names:
                g = given.lower()
                if g in declared:
                    continue
                if len([d for d in declared if d.startswith(g)]) == 1:
                    continue
                out.append(Problem(s.rel, line, "PARAM", f"{name} has no parameter -{given} (it has: {', '.join(fn.params) or 'none'})"))
    return out


def provider_tables(sources: list[Source]) -> dict[str, dict[str, str]]:
    tables: dict[str, dict[str, str]] = {}
    for s in sources:
        for m in re.finditer(r"\$script:(Wh(?:Real|Fake)Provider)\s*=\s*@\{", s.nocomment):
            close = match_close(s.nocomment, m.end() - 1)
            body = s.nocomment[m.end() : close]
            tables[m.group(1)] = dict(re.findall(r"^\s*(\w+)\s*=\s*'([^']+)'", body, re.M))
    return tables


def check_provider(sources: list[Source], funcs: dict[str, Func]) -> list[Problem]:
    out: list[Problem] = []
    tables = provider_tables(sources)
    real, fake = tables.get("WhRealProvider", {}), tables.get("WhFakeProvider", {})
    if not real or not fake:
        return [Problem("engine/Provider.ps1", 1, "PROVIDER", "provider tables not found")]
    if set(real) != set(fake):
        out.append(Problem("engine/Provider.ps1", 1, "PROVIDER", f"the real and the fake table have different keys: {sorted(set(real) ^ set(fake))}"))
    for kind, table in (("real", real), ("fake", fake)):
        for key, fname in table.items():
            if fname.lower() not in funcs:
                out.append(Problem("engine/Provider.ps1", 1, "PROVIDER", f"{kind} provider {key} names undefined function {fname}"))
    for key in set(real) & set(fake):
        fr, ff = funcs.get(real[key].lower()), funcs.get(fake[key].lower())
        if fr and ff and [p.lower() for p in fr.params] != [p.lower() for p in ff.params]:
            out.append(Problem(ff.file, ff.line, "PROVIDER", f"{key}: fake parameters {ff.params} differ from real parameters {fr.params}"))
    # Invoke-WhProv 'Op' a b c: the number of arguments must equal the number of parameters of the provider function.
    for s in sources:
        for m in re.finditer(r"(?<![\w\-$.:])Invoke-WhProv\b", s.blank):
            _, positional = call_params(s.blank, m.end())
            if not positional:
                continue
            op_match = re.match(r"\s*'([A-Za-z]+)'", s.nocomment[m.end() :])
            line = line_of(s.blank, m.start())
            if not op_match:
                continue
            op = op_match.group(1)
            if op not in real:
                out.append(Problem(s.rel, line, "PROVIDER", f"Invoke-WhProv with unknown operation {op}"))
                continue
            fr = funcs.get(real[op].lower())
            if fr and len(positional) - 1 != len(fr.params):
                out.append(Problem(s.rel, line, "PROVIDER", f"Invoke-WhProv '{op}' passes {len(positional) - 1} arguments, {fr.name} takes {len(fr.params)}"))
    return out


def check_variables(sources: list[Source]) -> list[Problem]:
    out: list[Problem] = []
    script_assigned: set[str] = set()
    for s in sources:
        for m in re.finditer(r"\$script:([A-Za-z_]\w*)(?:\[[^\]]*\]|\.\w+)*\s*[+\-*/%]?=(?!=)", s.blank):
            script_assigned.add(m.group(1).lower())
        for m in re.finditer(r"-(?:Out|Error|Warning|Information)Variable\s+(\w+)", s.blank):
            pass
    assign_re = re.compile(r"(?<![\w$.:])\$(?!(?:script|global|local|private|using|env):)([A-Za-z_]\w*)\s*[+\-*/%]?=(?!=)")
    foreach_re = re.compile(r"\bforeach\s*\(\s*\$([A-Za-z_]\w*)\s+in\b", re.I)
    outvar_re = re.compile(r"-(?:Out|Error|Warning|Information)Variable\s+([A-Za-z_]\w*)", re.I)
    use_re = re.compile(r"\$(?!(?:script|global|local|private|using|env):)(\{[^}]*\}|[A-Za-z_]\w*)")
    for s in sources:
        # variables the file itself assigns outside any function (script parameters, loop variables at top level)
        top = s.blank
        for fn in sorted(s.funcs, key=lambda f: -f.start):
            top = top[: fn.start] + _blank_run(top[fn.start : fn.start + len(fn.body)]) + top[fn.start + len(fn.body) :]
        file_level = {m.group(1).lower() for m in assign_re.finditer(top)}
        pm = re.search(r"^\s*(?:\[CmdletBinding\(\)\]\s*)?param\s*\(", top, re.M)
        if pm and s.path.name == "winharden.ps1":
            popen = pm.end() - 1
            pclose = match_close(top, popen)
            file_level |= {p.lower() for p in parse_param_names(top[popen + 1 : pclose])}
        if s.path.name != "winharden.ps1":
            file_level = set()
        for fn in s.funcs:
            defined = {p.lower() for p in fn.params} | AUTOMATIC | file_level
            defined |= {m.group(1).lower() for m in assign_re.finditer(fn.body)}
            defined |= {m.group(1).lower() for m in foreach_re.finditer(fn.body)}
            defined |= {m.group(1).lower() for m in outvar_re.finditer(fn.body)}
            # nested function definitions and scriptblock params
            for pm2 in re.finditer(r"\bparam\s*\(", fn.body):
                pc = match_close(fn.body, pm2.end() - 1)
                if pc > 0:
                    defined |= {p.lower() for p in parse_param_names(fn.body[pm2.end() : pc])}
            for m in use_re.finditer(fn.body):
                name = m.group(1)
                if name.startswith("{"):
                    continue
                if name.lower() not in defined:
                    out.append(Problem(s.rel, line_of(s.blank, fn.start + m.start()), "VAR", f"${name} is used in {fn.name} but never assigned there"))
            for m in re.finditer(r"\$script:([A-Za-z_]\w*)", fn.body):
                if m.group(1).lower() not in script_assigned:
                    out.append(Problem(s.rel, line_of(s.blank, fn.start + m.start()), "VAR", f"$script:{m.group(1)} is read in {fn.name} but never assigned anywhere"))
    # report each (file, function, name) once
    seen, unique = set(), []
    for p in out:
        key = (p.file, p.code, p.message)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def check_leaks(sources: list[Source], funcs: dict[str, Func]) -> list[Problem]:
    """A statement that starts with a call to a function that returns a value leaks that value into the caller."""
    out: list[Problem] = []
    for s in sources:
        for fn in s.funcs:
            for m in re.finditer(r"^[ \t]*([A-Za-z]+-[A-Za-z][A-Za-z0-9]*)\b", fn.body, re.M):
                name = m.group(1)
                callee = funcs.get(name.lower())
                line = line_of(s.blank, fn.start + m.start())
                if callee is not None and callee.returns_value:
                    out.append(Problem(s.rel, line, "LEAK", f"{name} returns a value and its result is not used in {fn.name}; wrap it in [void]( ) or assign it"))
                elif name in LEAKY_CMDLETS:
                    out.append(Problem(s.rel, line, "LEAK", f"{name} writes an object to the output in {fn.name}; wrap it in [void]( )"))
            for m in re.finditer(r"^[ \t]*\$[A-Za-z_][\w:]*(?:\.\w+)*\.(Append|AppendLine|AppendChild|Remove|Add)\(", fn.body, re.M):
                if m.group(1) in ("Append", "AppendLine", "AppendChild"):
                    out.append(Problem(s.rel, line_of(s.blank, fn.start + m.start()), "LEAK", f".{m.group(1)}() returns an object; prefix it with [void]"))
    return out


def check_ordered_assignments(sources: list[Source]) -> list[Problem]:
    """`$d.key = value` on an [ordered] dictionary: adding a new key that way is not reliable in Windows PowerShell 5.1."""
    out: list[Problem] = []
    for s in sources:
        for fn in s.funcs:
            names = {m.group(1).lower() for m in re.finditer(r"\$([A-Za-z_]\w*)\s*=\s*\[ordered\]\s*@\{", fn.body)}
            for n in sorted(names):
                for m in re.finditer(r"^[ \t]*\$" + re.escape(n) + r"\.\w+\s*=(?!=)", fn.body, re.M | re.I):
                    out.append(Problem(s.rel, line_of(s.blank, fn.start + m.start()), "STYLE",
                                       f"${n}.name = ... on an ordered dictionary in {fn.name}; write ${n}['name'] = ..."))
    return out


def check_object_index_assignments(sources: list[Source]) -> list[Problem]:
    """`$o['name'] = value` on a [pscustomobject], or on the fake provider's facts (which are one): PowerShell cannot index into it."""
    out: list[Problem] = []
    for s in sources:
        for fn in s.funcs:
            names = {m.group(1).lower() for m in re.finditer(
                r"\$([A-Za-z_]\w*)\s*=\s*(?:\[pscustomobject\]\s*@\{|Invoke-WhProv\s+'Facts')", fn.body_text)}
            for n in sorted(names):
                for m in re.finditer(r"^[ \t]*\$" + re.escape(n) + r"\s*\[[^\]\n]+\]\s*=(?!=)", fn.body, re.M | re.I):
                    out.append(Problem(s.rel, line_of(s.blank, fn.start + m.start()), "STYLE",
                                       f"${n}[...] = ... on an object in {fn.name}; PowerShell cannot index into a [pscustomobject], write ${n}.name = ..."))
            for m in re.finditer(r"^[ \t]*\$script:WhFake\.facts\s*\[[^\]\n]+\]\s*=(?!=)", fn.body, re.M | re.I):
                out.append(Problem(s.rel, line_of(s.blank, fn.start + m.start()), "STYLE",
                                   f"index assignment on the fake facts in {fn.name}; they are a [pscustomobject], write $script:WhFake.facts.name = ..."))
    return out


def check_op_types(sources: list[Source], funcs: dict[str, Func], schema_path: Path) -> list[Problem]:
    out: list[Problem] = []
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    text = json.dumps(schema)
    m = re.search(r'"type": \{[^{}]*"enum": \[([^\]]*"registry"[^\]]*)\]', text)
    types = re.findall(r'"([a-z_]+)"', m.group(1)) if m else []
    if not types:
        return [Problem("schema/manifest.schema.json", 1, "OPTYPE", "could not read the operation types from the schema")]
    dispatchers = [
        "Get-WhOpSlots", "Read-WhSlotState", "Get-WhSlotVerdict", "Invoke-WhSlotApply", "Restore-WhSlot", "Read-WhIdentState",
        "Get-WhOpProblems",
    ]
    for t in types:
        for d in dispatchers:
            fn = funcs.get(d.lower())
            if fn is None:
                out.append(Problem("engine", 1, "OPTYPE", f"dispatcher {d} is missing"))
            elif f"'{t}'" not in fn.body_text:
                out.append(Problem(fn.file, fn.line, "OPTYPE", f"{d} does not handle operation type {t}"))
        man = [s for s in sources if s.path.name == "Manifest.ps1"]
        if man and not re.search(r"^\s*" + re.escape(t) + r"\s*=\s*@\(", man[0].nocomment, re.M):
            out.append(Problem(man[0].rel, 1, "OPTYPE", f"$script:WhOpFields has no entry for {t}"))
    return out


def run_checks(root: Path = ROOT) -> list[Problem]:
    sources = [load_source(p, root) for p in engine_files(root)]
    funcs = all_functions(sources)
    problems: list[Problem] = []
    problems += check_text(sources)
    problems += check_duplicates(sources)
    problems += check_calls(sources, funcs)
    problems += check_provider(sources, funcs)
    problems += check_variables(sources)
    problems += check_leaks(sources, funcs)
    problems += check_ordered_assignments(sources)
    problems += check_object_index_assignments(sources)
    problems += check_op_types(sources, funcs, root / "schema" / "manifest.schema.json")
    return problems


def main() -> int:
    problems = run_checks()
    for p in problems:
        print(p)
    n_files = len(engine_files(ROOT))
    print(f"{n_files} files checked, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
