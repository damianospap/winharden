#!/usr/bin/env python3
"""winharden manifest validator.

Pipeline: JSON Schema -> cross-field rules R01..R21 -> never-touch and allow-list policy (R07, R12).
Dev/CI tool (needs `jsonschema`). The PowerShell engine repeats the never-touch
check at runtime; it does not depend on this file.

Usage:  python3 tools/validate_manifests.py [--manifests DIR] [--schema FILE] [--policy FILE]
Exit:   0 clean, 1 findings, 2 unreadable input or missing dependency.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:  # reported by main()
    jsonschema = None

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA = ROOT / "schema" / "manifest.schema.json"
DEFAULT_POLICY = ROOT / "policy" / "never-touch.json"
DEFAULT_MANIFESTS = ROOT / "manifests"

RISK_MIN_PROFILE = {"low": 1, "medium": 2, "high": 3}
TRUSTED_GRADES = {"ms-doc", "ms-statement"}

# --------------------------------------------------------------------------
# R10: audit-command lint (defense in depth; the engine also runs audits in a
# restricted runspace). Allow-list of verbs, deny-list of everything that can
# smuggle a write past a verb scan.
# --------------------------------------------------------------------------
ALLOWED_VERBS = {
    "get", "test", "select", "where", "foreach", "sort", "measure", "format",
    "convertto", "convertfrom", "compare", "group", "join", "split", "resolve", "out",
}
ALLOWED_OUT = {"out-string", "out-null"}
# Read-only cmdlets whose verb is not on the list above. They are allowed by exact name, never by verb.
ALLOWED_EXACT = {"confirm-securebootuefi"}
ALLOWED_METHODS = {
    "tostring", "trim", "trimstart", "trimend", "split", "contains", "startswith",
    "endswith", "replace", "tolower", "toupper", "substring", "indexof", "where",
    "foreach", "gettype",
}
_STR = re.compile(r"'(?:[^']|'')*'")
_CMDLET = re.compile(r"(?<![\w$.:\-])([A-Za-z]+)-([A-Za-z]+)\b")
_METHOD = re.compile(r"\.([A-Za-z_]\w*)\s*\(")
_NETWORK = re.compile(
    r"https?://|DownloadString|DownloadFile|WebClient|System\.Net|FromBase64String|-enc(?:odedcommand)?\b",
    re.I,
)
_CMD_POS = r"(?:^|[|;({&=])\s*"
_ALIAS = re.compile(
    _CMD_POS
    + r"(iex|iwr|irm|sc|rm|ri|del|erase|rd|rmdir|mv|mi|move|cp|cpi|copy|ni|si|sp|sv|rv|rni|ren|"
    r"clc|clp|ac|saps|start|kill|spps|sasv|spsv|curl|wget|md|mkdir|cmd|powershell|pwsh|reg|net|"
    r"schtasks|bcdedit|wmic|netsh|dism|setx|icacls|takeown|attrib|cacls|vssadmin|wevtutil|"
    r"fsutil|diskpart|cipher|mountvol|robocopy|xcopy|mshta|rundll32|regsvr32)(?:\.exe)?(?![\w\-])",
    re.I,
)
_DOT_SOURCE = re.compile(_CMD_POS + r"\.\s")
# auditpol is the one native tool an audit may use, and only to read: `auditpol /get ...` (rule R10).
_AUDITPOL = re.compile(r"(?<![\w\-])auditpol(?:\.exe)?(?![\w\-])", re.I)
_AUDITPOL_GET = re.compile(r"(?<![\w\-])auditpol(?:\.exe)?\s+/get\b", re.I)
_AUDITPOL_WRITE = re.compile(r"/(?:set|clear|remove|restore|backup|resourcesacl|file)\b", re.I)
# Read-only verbs that still reach the network or write a file.
DENIED_CMDLETS = {
    "test-netconnection", "test-connection", "resolve-dnsname", "test-wsman", "get-windowsupdatelog",
}


def lint_audit(cmd: str) -> list[str]:
    """Return reasons why `cmd` is not an acceptable read-only audit command."""
    why: list[str] = []
    if "\n" in cmd or "\r" in cmd:
        why.append("must be a single line")
    if '"' in cmd:
        why.append("use single-quoted strings only")
    if _NETWORK.search(cmd):
        why.append("network or encoding primitive")
    bare = _STR.sub("''", cmd)
    for token, reason in (("`", "backtick"), ("&", "call operator '&'"), (">", "redirection '>'"),
                          ("::", ".NET static call '::'")):
        if token in bare:
            why.append(f"{reason} not allowed")
    for m in _CMDLET.finditer(bare):
        verb, whole = m.group(1).lower(), m.group(0).lower()
        if whole in DENIED_CMDLETS:
            why.append(f"command '{m.group(0)}' touches the network or writes a file")
        elif whole in ALLOWED_EXACT:
            continue
        elif verb not in ALLOWED_VERBS or (verb == "out" and whole not in ALLOWED_OUT):
            why.append(f"command '{m.group(0)}' is not on the read-only allow-list")
    for m in _ALIAS.finditer(bare):
        why.append(f"alias or native command '{m.group(1)}' not allowed")
    if _DOT_SOURCE.search(bare):
        why.append("dot-sourcing not allowed")
    if _AUDITPOL.search(bare):
        if len(_AUDITPOL.findall(bare)) != len(_AUDITPOL_GET.findall(bare)) or _AUDITPOL_WRITE.search(bare):
            why.append("auditpol is only allowed as 'auditpol /get' without write options")
    for m in _METHOD.finditer(bare):
        if m.group(1).lower() not in ALLOWED_METHODS:
            why.append(f"method '.{m.group(1)}()' not allowed")
    return why


# --------------------------------------------------------------------------
# R07 / R12: never-touch policy
# --------------------------------------------------------------------------
def _norm(path: str) -> str:
    return path.replace("/", "\\").strip("\\").lower()


def has_wildcard(path: str) -> bool:
    return "*" in path or "?" in path


def _glob_overlaps(path: str, prefix: str) -> bool:
    """True when some key matched by `path` is the same as, or lies under, `prefix`, or the other way round.
    Only the last segment of `path` may hold a wildcard (rule R20)."""
    p, q = _norm(path).split("\\"), _norm(prefix).split("\\")
    for i in range(min(len(p), len(q))):
        if i == len(p) - 1 and has_wildcard(p[i]):
            if not fnmatch.fnmatchcase(q[i], p[i]):
                return False
        elif p[i] != q[i]:
            return False
    return True


def _under(path: str, prefix: str) -> bool:
    if has_wildcard(path):
        return _glob_overlaps(path, prefix)
    p, q = _norm(path), _norm(prefix)
    return p == q or p.startswith(q + "\\")


_SERVICE_KEY = re.compile(r"^system\\(?:currentcontrolset|controlset\d{3})\\services\\([^\\]+)(\\.*)?$")


def _task_full(op: dict) -> str:
    return (str(op.get("path", "")).rstrip("\\") + "\\" + str(op.get("name", ""))).lower()


def op_violations(op: dict, policy: dict) -> list[str]:
    """Never-touch violations of one apply operation (R07)."""
    out: list[str] = []
    kind = op.get("type")
    never_services = {s.lower() for s in policy["services"]}
    if kind == "service":
        if str(op.get("name", "")).lower() in never_services:
            out.append(f"service '{op.get('name')}' is on the never-touch list")
    elif kind == "registry":
        hive = str(op.get("hive", "")).upper()
        path, name = str(op.get("path", "")), str(op.get("name", ""))
        for rule in policy["registry_prefixes"]:
            if rule["hive"].upper() == hive and _under(path, rule["path"]):
                out.append(f"{hive}\\{path} is under never-touch prefix '{rule['path']}' ({rule['reason']})")
        for rule in policy["registry_values"]:
            names = {n.lower() for n in rule["names"]}
            if rule["hive"].upper() == hive and _under(path, rule["path_prefix"]) and name.lower() in names:
                out.append(f"value '{name}' under '{rule['path_prefix']}' is never-touch ({rule['reason']})")
        m = _SERVICE_KEY.match(_norm(path)) if hive == "HKLM" else None
        if m:
            if has_wildcard(m.group(1)):
                hit = sorted(s for s in never_services if fnmatch.fnmatchcase(s, m.group(1)))
                if hit:
                    out.append(f"service key pattern '{m.group(1)}' matches never-touch service '{hit[0]}'")
            elif m.group(1) in never_services:
                out.append(f"registry key of never-touch service '{m.group(1)}'")
            elif m.group(2) is None and name.lower() in {"start", "delayedautostart"}:
                out.append("service startup must use a 'service' operation, not a raw registry write")
    elif kind == "scheduled_task":
        full = _task_full(op)
        for pattern in policy["scheduled_tasks"]:
            if fnmatch.fnmatchcase(full, pattern.lower()):
                out.append(f"scheduled task '{full}' matches never-touch pattern '{pattern}'")
    elif kind == "appx":
        pkg = str(op.get("package_name", "")).lower()
        for pattern in policy["appx_names"]:
            if fnmatch.fnmatchcase(pkg, pattern.lower()):
                out.append(f"AppX package '{op.get('package_name')}' matches never-remove pattern '{pattern}'")
    elif kind == "optional_feature":
        if str(op.get("name", "")).lower() in {f.lower() for f in policy["optional_features"]}:
            out.append(f"optional feature '{op.get('name')}' is on the never-touch list")
    elif kind == "setting":
        table = policy["settings"].get(str(op.get("kind")), {})
        name = str(op.get("name", ""))
        key = next((k for k in table if k.lower() == name.lower()), None)
        if key is None:
            out.append(f"setting {op.get('kind')} '{name}' is not on the settings allow-list")
        elif canon_value(op.get("value")) not in {canon_value(v) for v in table[key]}:
            out.append(f"value {op.get('value')!r} is not allowed for {op.get('kind')} '{name}'")
    elif kind == "file_cleanup":
        root = str(op.get("root", "")).lower()
        if not any(r["scope"] == op.get("scope") and r["path"].lower() == root for r in policy["cleanup"]["roots"]):
            out.append(f"cleanup folder '{op.get('root')}' ({op.get('scope')}) is not on the cleanup allow-list")
    return out


def canon_value(value: object) -> str:
    """Text form used to compare manifest values with the policy lists: 2 -> '2', True -> 'true', 'Block' -> 'block'."""
    return str(value).lower()


def servicing_adjacent(op: dict, policy: dict) -> bool:
    adj = policy["servicing_adjacent"]
    if op.get("type") == "service":
        return str(op.get("name", "")).lower() in {s.lower() for s in adj["services"]}
    if op.get("type") == "scheduled_task":
        return _task_full(op) in {t.lower() for t in adj["scheduled_tasks"]}
    return False


# --------------------------------------------------------------------------
# Cross-field rules
# --------------------------------------------------------------------------
def data_matches_kind(kind: str, data: object) -> bool:
    is_int = isinstance(data, int) and not isinstance(data, bool)
    if kind == "DWord":
        return is_int and 0 <= data <= 0xFFFFFFFF
    if kind == "QWord":
        return is_int and 0 <= data <= 0xFFFFFFFFFFFFFFFF
    if kind in ("String", "ExpandString"):
        return isinstance(data, str)
    if kind == "MultiString":
        return isinstance(data, list) and all(isinstance(x, str) for x in data)
    return False


def entry_errors(e: dict, file_module: str | None, policy: dict) -> list[str]:
    errs: list[str] = []

    def add(code: str, msg: str) -> None:
        errs.append(f"[{code}] {msg}")

    tier, prof, mode = e.get("tier"), e.get("min_profile"), e.get("mode")
    chan, home, risk = e.get("channel_class"), e.get("home_effective"), e.get("risk")
    flags = e.get("flags") if isinstance(e.get("flags"), dict) else {}
    ops = [o for o in e.get("apply", []) if isinstance(o, dict)] if isinstance(e.get("apply"), list) else []
    evidence = e.get("evidence") if isinstance(e.get("evidence"), list) else []
    grades = {x.get("grade") for x in evidence if isinstance(x, dict)}
    rollback = e.get("rollback") if isinstance(e.get("rollback"), dict) else {}

    if file_module is not None and e.get("module") != file_module:
        add("R13", f"entry module '{e.get('module')}' differs from file module '{file_module}'")

    if tier == "T2" and prof != 3:
        add("R02", "tier T2 is allowed only at min_profile 3")

    if tier == "T0":
        if not grades & TRUSTED_GRADES:
            add("R03", "T0 needs ms-doc or ms-statement evidence")
        if home not in ("verified", "expected"):
            add("R03", "T0 needs home_effective verified or expected")
        if chan == "unsupported":
            add("R03", "T0 cannot use an unsupported channel")

    if chan == "unsupported":
        if tier != "T2":
            add("R04", "unsupported channel requires tier T2")
        if len(e.get("unsupported_justification") or "") < 40:
            add("R04", "unsupported channel requires unsupported_justification (at least 40 chars)")

    if home == "verified" and not e.get("verified"):
        add("R05", "home_effective=verified requires a 'verified' object (build, date)")

    if mode in ("enforce", "once") and not ops:
        add("R06", f"mode={mode} requires a non-empty apply")
    if mode in ("attest", "manual") and e.get("apply"):
        add("R06", f"mode={mode} must not have apply")
    if mode == "manual" and not e.get("manual_steps"):
        add("R06", "mode=manual requires manual_steps")

    if rollback.get("reversibility") == "partial" and len(rollback.get("limitation") or "") < 20:
        add("R08", "partial reversibility requires a limitation (at least 20 chars)")
    if any(o.get("type") == "appx" for o in ops) and rollback.get("reversibility") != "partial":
        add("R08", "AppX removal must declare reversibility=partial")

    if flags.get("deletes_user_data"):
        if mode not in ("enforce", "once"):
            add("R18", "flags.deletes_user_data only makes sense for mode=enforce or mode=once")
        if rollback.get("reversibility") != "partial":
            add("R18", "an entry that deletes user data cannot be fully reversible")

    refs = e.get("references") if isinstance(e.get("references"), list) else []
    urls = [r.get("url") for r in refs if isinstance(r, dict)]
    if len(urls) != len(set(urls)):
        add("R09", "duplicate reference URLs")

    audit = e.get("audit") if isinstance(e.get("audit"), dict) else {}
    raw_checks = audit.get("checks")
    checks = [c for c in raw_checks if isinstance(c, dict)] if isinstance(raw_checks, list) else []
    if mode in ("enforce", "attest") and not checks:
        add("R17", f"mode={mode} requires audit.checks")
    if mode == "once" and not checks and not audit.get("manual_check"):
        add("R17", "mode=once requires audit.checks or audit.manual_check")
    if mode == "manual" and not audit.get("manual_check"):
        add("R17", "mode=manual requires audit.manual_check")
    for i, check in enumerate(checks):
        for reason in lint_audit(str(check.get("command", ""))):
            add("R10", f"audit.checks[{i}]: {reason}")

    if home == "na" and mode == "enforce":
        add("R14", "home_effective=na cannot be enforced")

    if risk in RISK_MIN_PROFILE and isinstance(prof, int) and prof < RISK_MIN_PROFILE[risk]:
        add("R16", f"risk={risk} needs min_profile >= {RISK_MIN_PROFILE[risk]}")

    cleanup_only = bool(ops) and all(o.get("type") == "file_cleanup" for o in ops)
    if mode == "once":
        if not cleanup_only:
            add("R19", "mode=once is only for entries whose operations are all file_cleanup")
        if rollback.get("reversibility") != "partial":
            add("R19", "a one-time cleanup cannot be reversed: reversibility must be partial")
    elif any(o.get("type") == "file_cleanup" for o in ops):
        add("R19", "file_cleanup operations need mode=once: there is no state to enforce or verify")

    for i, op in enumerate(ops):
        for v in op_violations(op, policy):
            add("R07", f"apply[{i}]: {v}")
        if servicing_adjacent(op, policy) and not (flags.get("servicing_adjacent") and prof == 3):
            add("R12", f"apply[{i}]: servicing-adjacent target needs flags.servicing_adjacent=true and min_profile 3")
        if op.get("type") == "registry":
            hive, scope = op.get("hive"), op.get("scope")
            if (hive, scope) not in (("HKLM", "machine"), ("HKCU", "user")):
                add("R11", f"apply[{i}]: hive {hive} does not match scope {scope}")
            if not data_matches_kind(str(op.get("kind")), op.get("data")):
                add("R15", f"apply[{i}]: data {op.get('data')!r} does not fit kind {op.get('kind')}")
            path = str(op.get("path", ""))
            if has_wildcard(path):
                parent, _, leaf = path.rpartition("\\")
                if not parent or has_wildcard(parent) or not has_wildcard(leaf) or "[" in path or "]" in path:
                    add("R20", f"apply[{i}]: a wildcard is allowed only in the last segment of the path, below a fixed parent key")
                if op.get("merge"):
                    add("R20", f"apply[{i}]: merge cannot be combined with a wildcard path")
            if op.get("merge") == "hide-list" and not (
                op.get("kind") == "String" and str(op.get("data", "")).lower().startswith("hide:")
            ):
                add("R15", f"apply[{i}]: merge=hide-list needs kind String and data 'hide:...'")
        if op.get("type") == "setting":
            table = policy["settings"].get(str(op.get("kind")), {})
            key = next((k for k in table if k.lower() == str(op.get("name", "")).lower()), None)
            if key is not None and table[key] and type(op.get("value")) is not type(table[key][0]):
                add("R21", f"apply[{i}]: value {op.get('value')!r} has the wrong JSON type for {op.get('kind')} '{op.get('name')}'")
    return errs


def schema_errors(doc: object, schema: dict) -> list[str]:
    validator = jsonschema.Draft202012Validator(schema)
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda x: [str(p) for p in x.absolute_path]):
        loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"[SCHEMA] {loc}: {err.message}")
    return out


def validate_all(docs: list[tuple[str, object]], schema: dict, policy: dict) -> list[str]:
    """docs = [(file name, parsed JSON)]. Returns a list of findings; empty means clean."""
    errors: list[str] = []
    seen: dict[str, str] = {}
    for fname, doc in docs:
        errors += [f"{fname}: {m}" for m in schema_errors(doc, schema)]
        if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
            continue
        for idx, e in enumerate(doc["entries"]):
            if not isinstance(e, dict):
                continue
            eid = str(e.get("id", f"<entry {idx}>"))
            if eid in seen:
                errors.append(f"{fname}:{eid}: [R01] duplicate id (first seen in {seen[eid]})")
            else:
                seen[eid] = fname
            errors += [f"{fname}:{eid}: {m}" for m in entry_errors(e, doc.get("module"), policy)]
    return errors


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate winharden manifests.")
    ap.add_argument("--manifests", type=Path, default=DEFAULT_MANIFESTS)
    ap.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    ap.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    args = ap.parse_args(argv)
    if jsonschema is None:
        print("ERROR: needs jsonschema (pip install -r tools/requirements.txt)", file=sys.stderr)
        return 2
    try:
        schema, policy = load_json(args.schema), load_json(args.policy)
        files = sorted(args.manifests.glob("*.json"))
        if not files:
            raise FileNotFoundError(f"no manifest files in {args.manifests}")
        docs = [(f.name, load_json(f)) for f in files]
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    errors = validate_all(docs, schema, policy)
    if errors:
        print("\n".join(errors))
        print(f"FAIL: {len(errors)} finding(s)")
        return 1
    count = sum(len(d["entries"]) for _, d in docs)
    print(f"OK: {count} entries in {len(files)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
