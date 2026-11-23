"""The engine cannot be executed where it is developed (no PowerShell), so these tests are its safety net.

Part 1 runs tools/check_engine.py on the real engine: it must report nothing.
Part 2 proves the checker itself works: each test injects one fault into a copy of the engine and expects the checker to
name it. A checker that never fails would be worse than none.
Part 3 runs the shared test vectors (the same files `winharden.ps1 selftest` reads) against the Python implementation of
the same rules, so the PowerShell and the Python copies of the policy cannot drift apart unnoticed.
Part 4 reads engine/Policy.ps1 as text and requires its audit-lint word lists and regular expressions to be identical to
the ones in tools/validate_manifests.py: the vectors only run in PowerShell on Windows, so this is the check that works here.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_engine  # noqa: E402
import validate_manifests as V  # noqa: E402


def test_engine_has_no_static_problems():
    problems = check_engine.run_checks(ROOT)
    assert not problems, "\n" + "\n".join(str(p) for p in problems)


def test_engine_files_are_ascii_and_lf_only():
    for path in check_engine.engine_files(ROOT):
        data = path.read_bytes()
        assert all(b < 128 for b in data), f"{path.name} has a non-ASCII byte"
        assert b"\r" not in data, f"{path.name} has a CR; keep LF so the code fingerprint is the same on every checkout"


def test_pygments_lexer_finds_no_error_tokens():
    pygments = pytest.importorskip("pygments")
    from pygments.lexers import PowerShellLexer
    from pygments.token import Error

    lexer = PowerShellLexer()
    for path in check_engine.engine_files(ROOT):
        bad = [(tok, val) for tok, val in lexer.get_tokens(path.read_text(encoding="utf-8")) if tok is Error]
        assert not bad, f"{path.name}: lexer error tokens {bad[:3]}"


# ---------------------------------------------------------------------------
# Part 2: the checker catches what it claims to catch
# ---------------------------------------------------------------------------
@pytest.fixture()
def copy_of_engine(tmp_path: Path) -> Path:
    shutil.copytree(ROOT / "engine", tmp_path / "engine")
    shutil.copy(ROOT / "winharden.ps1", tmp_path / "winharden.ps1")
    (tmp_path / "schema").mkdir()
    shutil.copy(ROOT / "schema" / "manifest.schema.json", tmp_path / "schema" / "manifest.schema.json")
    return tmp_path


def _inject(root: Path, rel: str, old: str, new: str) -> set[str]:
    path = root / rel
    text = path.read_text(encoding="utf-8")
    assert old in text, f"test setup: {old!r} not found in {rel}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return {p.code for p in check_engine.run_checks(root)}


FAULTS = [
    ("undefined function", "engine/Plan.ps1", "Get-WhSlotVerdict -Op $op -State $before", "Get-WhSlotVerdictX -Op $op -State $before", "CALL"),
    ("unknown parameter", "engine/Plan.ps1", "Get-WhSlotVerdict -Op $op -State $before", "Get-WhSlotVerdict -Op $op -Statee $before", "PARAM"),
    ("misspelled variable", "engine/Plan.ps1", "Get-WhSlotVerdict -Op $op -State $before", "Get-WhSlotVerdict -Op $op -State $befor", "VAR"),
    ("script variable never assigned", "engine/Journal.ps1", "$rec['mac'] = ", "$x = $script:WhNoSuchThing\n    $rec['mac'] = ", "VAR"),
    ("script parameter misspelled in the CLI", "winharden.ps1", "accept_data_loss = [bool]$AcceptDataLoss;", "accept_data_loss = [bool]$AcceptDataLos;", "VAR"),
    ("leaking call", "engine/Apply.ps1", "[void](Add-WhJournalRecord -RunId $RunId -Type 'txn-begin' -Data ([ordered]@{ txn = $txn; entry = $id }))", "Add-WhJournalRecord -RunId $RunId -Type 'txn-begin' -Data ([ordered]@{ txn = $txn; entry = $id })", "LEAK"),
    ("leaking StringBuilder", "engine/Report.ps1", "[void]$h.AppendLine('<!DOCTYPE html>')", "$h.AppendLine('<!DOCTYPE html>')", "LEAK"),
    ("provider call with a wrong argument count", "engine/Apply.ps1", "Invoke-WhProv 'ClearCaches'\n            if (-not $volatile) {", "Invoke-WhProv 'ClearCaches' $item\n            if (-not $volatile) {", "PROVIDER"),
    ("provider tables with different keys", "engine/Provider.ps1", "    Audit          = 'Invoke-WhFakeAudit'\n", "", "PROVIDER"),
    ("fake and real parameters differ", "engine/Provider.Fake.ps1", "param([string]$Name, [bool]$Enabled)\n    Assert-WhFakeNoFault -Operation 'FeatureEnabled'", "param([string]$Name)\n    Assert-WhFakeNoFault -Operation 'FeatureEnabled'", "PROVIDER"),
    ("operation type not handled", "engine/Apply.ps1", "    elseif ($type -eq 'optional_feature') {\n        Invoke-WhProv 'FeatureEnabled' ([string]$ident.name) $false\n    }\n", "", "OPTYPE"),
    ("null-coalescing operator", "engine/Plan.ps1", "return $pe\n    }\n    $opIndex = 0", "return $pe ?? $null\n    }\n    $opIndex = 0", "SYNTAX"),
    ("unbalanced brace", "engine/Plan.ps1", "function New-WhVerdict {", "function New-WhVerdict {{", "BALANCE"),
    ("duplicate function", "engine/Plan.ps1", "function New-WhVerdict {", "function Get-WhProp {\n}\nfunction New-WhVerdict {", "DUP"),
    ("interpolated string", "engine/Verify.ps1", "$actual = [string](Invoke-WhProv 'Audit' $Command)", '$actual = [string](Invoke-WhProv "Audit $Command")', "STYLE"),
    ("dot assignment on an ordered dictionary", "engine/Provider.Real.ps1", "$f['os_64bit'] = [Environment]::Is64BitOperatingSystem", "$f.os_64bit = [Environment]::Is64BitOperatingSystem", "STYLE"),
    # The first run on Windows failed on exactly this: the fake provider keeps the facts in a [pscustomobject].
    ("index assignment on the facts object", "engine/SelfTest.ps1",
     "        $script:WhFake.facts.ui_language = 'el'\n        $res = Test-WhEntry -Entry $e -Facts (Invoke-WhProv 'Facts')",
     "        $facts = Invoke-WhProv 'Facts'\n        $facts['ui_language'] = 'el'\n        $res = Test-WhEntry -Entry $e -Facts $facts", "STYLE"),
    ("index assignment on the fake facts directly", "engine/SelfTest.ps1",
     "        $script:WhFake.facts.ui_language = 'el'\n", "        $script:WhFake.facts['ui_language'] = 'el'\n", "STYLE"),
    ("operation type handled in one dispatcher only", "engine/Rollback.ps1", "    if ($type -eq 'setting') { return (Invoke-WhProv 'SettingGet' ([string]$Ident.kind) ([string]$Ident.name)) }\n", "", "OPTYPE"),
    ("top-level array wrapped in @()", "engine/SelfTest.ps1", "$parsed = ConvertFrom-WhJson -Text (Read-WhFile -Path $path)", "$parsed = @(ConvertFrom-WhJson -Text (Read-WhFile -Path $path))", "SYNTAX"),
]


@pytest.mark.parametrize("name,rel,old,new,code", FAULTS, ids=[f[0] for f in FAULTS])
def test_checker_catches_injected_fault(copy_of_engine, name, rel, old, new, code):
    assert code in _inject(copy_of_engine, rel, old, new)


def test_canonical_text_reads_the_keys_through_psbase():
    """ConvertTo-WhCanonical must not read $Value.Keys. On a dictionary that has an entry called keys, the entry wins over the
    property (about_Hash_Tables), and the self test's snapshot of the fake system has such an entry: on the first run on Windows
    every snapshot came out the same, so a check that the state had changed failed and a check that it was restored proved nothing."""
    text = (ROOT / "engine" / "Core.ps1").read_text(encoding="utf-8")
    body = text[text.index("function ConvertTo-WhCanonical"):text.index("function Get-WhSha256Bytes")]
    code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))  # the comment names $Value.Keys
    assert "$Value.psbase.Keys" in code
    assert "$Value.Keys" not in code


def test_fake_clean_dirs_lists_only_folders_that_exist():
    """The real provider returns only existing folders, so the fake must too (a folder exists when it is in dirs)."""
    text = (ROOT / "engine" / "Provider.Fake.ps1").read_text(encoding="utf-8")
    body = text[text.index("function Get-WhFakeCleanDirs"):text.index("function Get-WhFakeCleanScan")]
    assert "$script:WhFake.dirs.ContainsKey(" in body


def _ps_code(rel: str, name: str) -> str:
    """The code lines of one function (comments dropped), from 'function <name> ' to the next top-level function."""
    text = (ROOT / rel).read_text(encoding="utf-8")
    start = text.index("function " + name + " ")
    end = text.find("\nfunction ", start + 1)
    body = text[start:end if end != -1 else len(text)]
    return "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))


def test_audit_runs_again_in_a_full_language_runspace_when_a_module_cannot_load():
    """The first apply on Windows: 29 entries (Defender, ScheduledTasks, NetSecurity) had audits that came back as errors, 'the command
    was found in the module but the module could not be loaded'. Those modules are CIM-based and do not load into a ConstrainedLanguage
    session. A command that raises CommandNotFoundException there is run again in a FullLanguage runspace, after the lint like every
    other command. This test pins the shape of the code; only a run on Windows proves that the modules load."""
    rel = "engine/Provider.Real.ps1"
    audit = _ps_code(rel, "Invoke-WhRealAudit")
    assert audit.index("Get-WhAuditLintReasons") < audit.index("Get-WhAuditRunspace -Full $false") < audit.index("Get-WhAuditRunspace -Full $true")
    assert "$run.failed -and $run.command_not_found" in audit
    once = _ps_code(rel, "Invoke-WhAuditOnce")
    assert "[System.Management.Automation.CommandNotFoundException]" in once
    assert once.index("$message = [string]$first") < once.index("$ps.Dispose()")  # copied before the object is disposed
    runspace = _ps_code(rel, "Get-WhAuditRunspace")
    full, constrained = runspace.split("if ($null -eq $script:WhAuditRunspace) {")
    assert "ConstrainedLanguage" not in full
    assert "ConstrainedLanguage" in constrained
    close = _ps_code(rel, "Close-WhAuditRunspaces")
    assert "$script:WhAuditRunspace," in close
    assert "$script:WhAuditRunspaceFull)" in close
    assert "Close-WhAuditRunspaces" in _ps_code(rel, "Stop-WhRealSession")


def test_verify_says_when_a_closed_gate_is_why_apply_left_an_entry_alone():
    """After a default apply, appx-006 and appx-007 (Sticky Notes, To Do) were FAIL in verify: the apps are still installed, because
    apply skips entries that delete user data unless -AcceptDataLoss is given. The status stays fail (the system does not match the
    manifest) and the reason now names the gate. This test pins the shape of the code; the selftest runs the behaviour."""
    entry = _ps_code("engine/Verify.ps1", "Test-WhEntry")
    assert "$Gates = $null" in entry
    assert "$result['status'] -eq 'fail'" in entry
    assert entry.index("$result['reason'] = ($reasons.ToArray() -join ' ')") < entry.index("Get-WhEntryGate -Entry $Entry -Facts $Facts -Gates $Gates")
    assert "Apply skips this entry: " in entry
    assert "-Gates $Gates" in _ps_code("engine/Verify.ps1", "Invoke-WhVerify")
    assert "-Gates (Get-WhGates)" in _ps_code("winharden.ps1", "Complete-WhRun")


def test_checker_catches_non_ascii(copy_of_engine):
    path = copy_of_engine / "engine" / "Core.ps1"
    path.write_bytes(path.read_bytes().replace(b"# winharden engine: Core.ps1", b"# winharden engine: Core.ps1 \xc3\xa9", 1))
    assert "ASCII" in {p.code for p in check_engine.run_checks(copy_of_engine)}


# ---------------------------------------------------------------------------
# Part 3: shared vectors against the Python implementation
# ---------------------------------------------------------------------------
def _vectors(name: str):
    return json.loads((ROOT / "tests" / "vectors" / name).read_text(encoding="utf-8"))


NEVER_TOUCH = _vectors("never-touch.json")
AUDIT_LINT = _vectors("audit-lint.json")
POLICY = json.loads((ROOT / "policy" / "never-touch.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("vec", NEVER_TOUCH, ids=[v["name"] for v in NEVER_TOUCH])
def test_never_touch_vectors(vec):
    assert bool(V.op_violations(vec["op"], POLICY)) is vec["blocked"]
    assert V.servicing_adjacent(vec["op"], POLICY) is vec["servicing_adjacent"]


@pytest.mark.parametrize("vec", AUDIT_LINT, ids=[f"{i}-{v['name']}" for i, v in enumerate(AUDIT_LINT)])
def test_audit_lint_vectors(vec):
    assert (not V.lint_audit(vec["command"])) is vec["ok"]


def test_every_manifest_audit_command_is_in_the_lint_vectors():
    """The vectors must contain the real commands, otherwise the PowerShell lint is only tested on toy input."""
    in_vectors = {v["command"] for v in AUDIT_LINT}
    used = set()
    for path in (ROOT / "manifests").glob("*.json"):
        for entry in json.loads(path.read_text(encoding="utf-8"))["entries"]:
            for check in entry["audit"].get("checks", []):
                used.add(check["command"])
    missing = sorted(used - in_vectors)
    assert not missing, f"{len(missing)} manifest audit commands are not in tests/vectors/audit-lint.json, e.g. {missing[:2]}"


# ---------------------------------------------------------------------------
# Part 4: the PowerShell lint in engine/Policy.ps1 keeps the same lists and patterns as tools/validate_manifests.py
# ---------------------------------------------------------------------------
POLICY_PS1 = (ROOT / "engine" / "Policy.ps1").read_text(encoding="utf-8")


def _ps_list(variable: str) -> set[str]:
    """The quoted names of `$script:<variable> = @('a', 'b')` in engine/Policy.ps1."""
    m = re.search(rf"^\$script:{variable} = @\((.*)\)\s*$", POLICY_PS1, re.M)
    assert m, f"{variable} is not defined in engine/Policy.ps1"
    return set(re.findall(r"'([^']+)'", m.group(1)))


def _ps_pattern(variable: str) -> str:
    """The text of `$script:<variable> = '...'` (or a double-quoted string) in engine/Policy.ps1."""
    m = re.search(rf"^\$script:{variable} = (?:'(.*)'|\"(.*)\")\s*$", POLICY_PS1, re.M)
    assert m, f"{variable} is not a plain string in engine/Policy.ps1"
    return m.group(1) if m.group(1) is not None else m.group(2)


@pytest.mark.parametrize("variable, python_set", [
    ("WhAllowedVerbs", V.ALLOWED_VERBS), ("WhAllowedOut", V.ALLOWED_OUT), ("WhAllowedExact", V.ALLOWED_EXACT),
    ("WhAllowedMethods", V.ALLOWED_METHODS), ("WhDeniedCmdlets", V.DENIED_CMDLETS),
])
def test_the_powershell_lint_lists_equal_the_python_lists(variable, python_set):
    assert _ps_list(variable) == python_set


@pytest.mark.parametrize("variable, python_regex", [
    ("WhReStr", V._STR), ("WhReCmdlet", V._CMDLET), ("WhReMethod", V._METHOD), ("WhReNetwork", V._NETWORK),
    ("WhReAuditpol", V._AUDITPOL), ("WhReAuditpolGet", V._AUDITPOL_GET), ("WhReAuditpolWrite", V._AUDITPOL_WRITE),
])
def test_the_powershell_lint_patterns_equal_the_python_patterns(variable, python_regex):
    assert _ps_pattern(variable) == python_regex.pattern


def test_the_powershell_alias_list_equals_the_python_alias_list():
    group = re.compile(r"\((iex\|[^)]*)\)")
    ps, py = group.search(POLICY_PS1), group.search(V._ALIAS.pattern)
    assert ps and py, "the alias alternation was not found"
    assert set(ps.group(1).split("|")) == set(py.group(1).split("|"))


def test_a_name_allowed_by_exact_match_is_not_denied_and_is_not_already_allowed_by_its_verb():
    assert not V.ALLOWED_EXACT & V.DENIED_CMDLETS, "the order of the two checks must not decide anything"
    verbs = {name.split("-")[0] for name in V.ALLOWED_EXACT}
    assert not verbs & V.ALLOWED_VERBS, "an exact-name exception for a verb that is already allowed is redundant"
