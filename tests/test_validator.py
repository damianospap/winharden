"""Tests for tools/validate_manifests.py: the clean path plus one failing case per rule.

Run from the project root:  python3 -I -m unittest discover -s tests -v
"""
import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import validate_manifests as V  # noqa: E402

SCHEMA = json.loads((ROOT / "schema" / "manifest.schema.json").read_text(encoding="utf-8"))
POLICY = json.loads((ROOT / "policy" / "never-touch.json").read_text(encoding="utf-8"))

AUDIT = (
    "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' "
    "-Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry"
)


def reg_op(**over):
    op = {
        "type": "registry", "hive": "HKLM",
        "path": "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        "name": "AllowTelemetry", "kind": "DWord", "data": 1, "scope": "machine",
    }
    op.update(over)
    return op


def entry(**over):
    """A valid T0 entry. Tests mutate one thing at a time."""
    e = {
        "id": "tel-001-diagnostic-data-required",
        "module": "m1-telemetry",
        "title": "Cap diagnostic data at Required",
        "tier": "T0", "min_profile": 1, "mode": "enforce",
        "home_effective": "expected", "channel_class": "policy",
        "applicability": {"editions": ["Home"], "min_build": 26200},
        "rationale": "Home cannot turn diagnostic data off; Required is the lowest level it honours.",
        "impact": "Optional diagnostic data control in Settings becomes locked.",
        "apply": [reg_op()],
        "audit": {"checks": [{"command": AUDIT, "expected": "1"}]},
        "rollback": {"strategy": "journal", "reversibility": "full"},
        "risk": "low",
        "evidence": [{"grade": "ms-doc", "source": "learn.microsoft.com privacy page",
                      "claim": "Required is the minimum diagnostic level on Home."}],
        "references": [{"title": "Configure Windows diagnostic data",
                        "url": "https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization"}],
    }
    e.update(copy.deepcopy(over))
    return e


def t1_entry(**over):
    base = dict(
        tier="T1", home_effective="unverified",
        evidence=[{"grade": "community", "source": "forum thread", "claim": "Reported to work on Home builds."}],
    )
    base.update(over)
    return entry(**base)


APPX = {"type": "appx", "package_name": "Microsoft.Copilot", "action": "remove",
        "deprovision": True, "all_users": True}
APPRAISER = {"type": "scheduled_task", "path": "\\Microsoft\\Windows\\Application Experience\\",
             "name": "Microsoft Compatibility Appraiser", "state": "Disabled", "if_missing": "skip"}


class Base(unittest.TestCase):
    def run_entries(self, *entries, module="m1-telemetry"):
        doc = {"module": module, "schema_version": 1, "entries": list(entries)}
        return V.validate_all([("t.json", doc)], SCHEMA, POLICY)

    def assertFinds(self, errs, code, text=""):
        self.assertTrue(any(f"[{code}]" in e and text in e for e in errs), f"{code} {text!r} not in {errs}")

    def assertNoFinding(self, errs, code):
        self.assertFalse(any(f"[{code}]" in e for e in errs), f"unexpected {code} in {errs}")


class CleanAndSchema(Base):
    def test_schema_itself_is_valid(self):
        V.jsonschema.Draft202012Validator.check_schema(SCHEMA)

    def test_good_entry_is_clean(self):
        self.assertEqual(self.run_entries(entry()), [])

    def test_missing_required_field(self):
        e = entry()
        del e["rationale"]
        self.assertFinds(self.run_entries(e), "SCHEMA", "rationale")

    def test_unknown_field_rejected(self):
        self.assertFinds(self.run_entries(entry(tpyo=1)), "SCHEMA", "tpyo")

    def test_short_rationale_rejected(self):
        self.assertFinds(self.run_entries(entry(rationale="too short")), "SCHEMA")

    def test_bad_id_rejected(self):
        self.assertFinds(self.run_entries(entry(id="Tel_1")), "SCHEMA")

    def test_registry_op_missing_field_is_precise(self):
        op = reg_op()
        del op["hive"]
        self.assertFinds(self.run_entries(entry(apply=[op])), "SCHEMA", "hive")

    def test_powershell_drive_prefix_rejected(self):
        self.assertFinds(self.run_entries(entry(apply=[reg_op(path="HKLM:\\SOFTWARE\\X")])), "SCHEMA")

    def test_leading_backslash_rejected(self):
        self.assertFinds(self.run_entries(entry(apply=[reg_op(path="\\SOFTWARE\\X")])), "SCHEMA")

    def test_appx_wildcard_rejected(self):
        op = dict(APPX, package_name="Microsoft.*")
        self.assertFinds(self.run_entries(t1_entry(apply=[op], rollback=_partial())), "SCHEMA")

    def test_http_reference_rejected(self):
        refs = [{"title": "plain http", "url": "http://example.com/x"}]
        self.assertFinds(self.run_entries(entry(references=refs)), "SCHEMA")

    def test_pre_26200_build_rejected(self):
        self.assertFinds(self.run_entries(entry(applicability={"editions": ["Home"], "min_build": 26100})), "SCHEMA")

    def test_non_home_edition_rejected(self):
        self.assertFinds(self.run_entries(entry(applicability={"editions": ["Pro"]})), "SCHEMA")

    def test_task_path_must_be_a_folder(self):
        op = dict(APPRAISER, path="\\Microsoft\\Windows\\Application Experience")
        self.assertFinds(self.run_entries(t1_entry(min_profile=3, risk="high", apply=[op])), "SCHEMA")


def _partial(limitation="Reinstall from the Microsoft Store; local app data is lost."):
    return {"strategy": "store-reinstall", "reversibility": "partial", "limitation": limitation}


class CrossFieldRules(Base):
    def test_r01_duplicate_id_across_files(self):
        d1 = ("a.json", {"module": "m1-telemetry", "schema_version": 1, "entries": [entry()]})
        d2 = ("b.json", {"module": "m1-telemetry", "schema_version": 1, "entries": [entry()]})
        self.assertFinds(V.validate_all([d1, d2], SCHEMA, POLICY), "R01")

    def test_r02_t2_needs_profile_3(self):
        e = t1_entry(tier="T2", min_profile=2, risk="medium")
        self.assertFinds(self.run_entries(e), "R02")
        self.assertNoFinding(self.run_entries(dict(e, min_profile=3)), "R02")

    def test_r03_t0_needs_trusted_evidence(self):
        ev = [{"grade": "community", "source": "forum", "claim": "Someone said it works."}]
        self.assertFinds(self.run_entries(entry(evidence=ev)), "R03", "ms-doc")

    def test_r03_t0_needs_home_effect(self):
        self.assertFinds(self.run_entries(entry(home_effective="unverified")), "R03", "home_effective")

    def test_r03_t0_cannot_be_unsupported(self):
        self.assertFinds(self.run_entries(entry(channel_class="unsupported")), "R03", "unsupported")

    def test_r04_unsupported_needs_t2_and_justification(self):
        errs = self.run_entries(t1_entry(channel_class="unsupported"))
        self.assertFinds(errs, "R04", "tier T2")
        self.assertFinds(errs, "R04", "unsupported_justification")
        ok = t1_entry(channel_class="unsupported", tier="T2", min_profile=3, risk="high",
                      unsupported_justification="No supported channel exists for this setting on Home builds.")
        self.assertNoFinding(self.run_entries(ok), "R04")

    def test_r05_verified_needs_record(self):
        self.assertFinds(self.run_entries(entry(home_effective="verified")), "R05")
        rec = {"build": "10.0.26200.1000", "date": "2026-11-10", "vm": "VirtualBox 25H2"}
        self.assertEqual(self.run_entries(entry(home_effective="verified", verified=rec)), [])

    def test_r06_enforce_needs_apply(self):
        e = entry()
        del e["apply"]
        self.assertFinds(self.run_entries(e), "R06", "enforce")

    def test_r06_attest_must_not_apply(self):
        self.assertFinds(self.run_entries(entry(mode="attest")), "R06", "must not have apply")

    def test_r06_manual_needs_steps(self):
        e = entry(mode="manual")
        del e["apply"]
        self.assertFinds(self.run_entries(e), "R06", "manual_steps")
        ok = dict(e, manual_steps=["Open Settings and switch the toggle off."],
                  audit={"manual_check": "Open Settings and confirm the toggle reads Off."})
        self.assertEqual(self.run_entries(ok), [])

    def test_r17_manual_needs_manual_check(self):
        e = entry(mode="manual", manual_steps=["Open Settings and switch the toggle off."])
        del e["apply"]
        self.assertFinds(self.run_entries(e), "R17", "manual_check")

    def test_r17_enforce_needs_machine_checks(self):
        e = entry(audit={"manual_check": "Open Settings and confirm the toggle reads Off."})
        self.assertFinds(self.run_entries(e), "R17", "audit.checks")

    def test_r17_attest_needs_machine_checks(self):
        e = entry(mode="attest", audit={})
        del e["apply"]
        self.assertFinds(self.run_entries(e), "R17", "audit.checks")

    def test_r17_attest_may_add_a_manual_check(self):
        e = entry(mode="attest", audit={"checks": [{"command": AUDIT, "expected": "1"}],
                                        "manual_check": "Open Settings and confirm the toggle reads Off."})
        del e["apply"]
        self.assertEqual(self.run_entries(e), [])

    def test_manual_check_must_be_substantive(self):
        e = entry(mode="attest", audit={"checks": [{"command": AUDIT, "expected": "1"}], "manual_check": "look"})
        del e["apply"]
        self.assertFinds(self.run_entries(e), "SCHEMA", "manual_check")

    def test_r08_partial_needs_limitation(self):
        rb = {"strategy": "journal", "reversibility": "partial"}
        self.assertFinds(self.run_entries(entry(rollback=rb)), "R08", "limitation")

    def test_r08_appx_must_be_partial(self):
        self.assertFinds(self.run_entries(t1_entry(apply=[APPX])), "R08", "AppX")
        self.assertEqual(self.run_entries(t1_entry(apply=[APPX], rollback=_partial())), [])

    def test_r09_duplicate_reference_urls(self):
        ref = entry()["references"][0]
        self.assertFinds(self.run_entries(entry(references=[ref, dict(ref)])), "R09")

    def test_r11_hive_scope_mismatch(self):
        self.assertFinds(self.run_entries(entry(apply=[reg_op(scope="user")])), "R11")
        self.assertFinds(self.run_entries(entry(apply=[reg_op(hive="HKCU", scope="machine")])), "R11")

    def test_r13_module_mismatch(self):
        self.assertFinds(self.run_entries(entry(), module="m2-consumer"), "R13")

    def test_r14_na_cannot_be_enforced(self):
        self.assertFinds(self.run_entries(t1_entry(home_effective="na")), "R14")

    def test_r15_data_must_fit_kind(self):
        self.assertFinds(self.run_entries(entry(apply=[reg_op(data="1")])), "R15")
        self.assertFinds(self.run_entries(entry(apply=[reg_op(data=-1)])), "R15")
        self.assertFinds(self.run_entries(entry(apply=[reg_op(data=2 ** 32)])), "R15")
        self.assertFinds(self.run_entries(entry(apply=[reg_op(kind="String", data=1)])), "R15")

    def test_r15_merge_needs_hide_string(self):
        self.assertFinds(self.run_entries(entry(apply=[reg_op(merge="hide-list")])), "R15")
        op = reg_op(hive="HKLM", kind="String", data="hide:home", name="SettingsPageVisibility", merge="hide-list",
                    path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")
        self.assertEqual(self.run_entries(entry(apply=[op])), [])

    def test_r16_risk_sets_minimum_profile(self):
        self.assertFinds(self.run_entries(entry(risk="medium")), "R16")
        self.assertFinds(self.run_entries(entry(risk="high", min_profile=2)), "R16")
        self.assertNoFinding(self.run_entries(entry(risk="medium", min_profile=2)), "R16")


class DeletesUserData(Base):
    """R18: an entry that deletes user data must say so, be enforce-mode and be at best partially reversible."""

    FLAGS = {"deletes_user_data": True}

    def test_flagged_partial_enforce_entry_is_clean(self):
        e = t1_entry(flags=self.FLAGS, apply=[APPX], rollback=_partial())
        self.assertEqual(self.run_entries(e), [])

    def test_r18_flagged_entry_cannot_claim_full_reversibility(self):
        self.assertFinds(self.run_entries(entry(flags=self.FLAGS)), "R18", "fully reversible")

    def test_r18_only_for_enforce_mode(self):
        e = entry(mode="attest", flags=self.FLAGS, rollback=_partial())
        del e["apply"]
        self.assertFinds(self.run_entries(e), "R18", "mode=enforce")

    def test_flag_must_be_boolean(self):
        self.assertFinds(self.run_entries(entry(flags={"deletes_user_data": "yes"}, rollback=_partial())), "SCHEMA")


class NeverTouch(Base):
    def r07(self, op, **over):
        self.assertFinds(self.run_entries(entry(apply=[op], **over)), "R07")

    def test_service(self):
        self.r07({"type": "service", "name": "WUAUSERV", "startup": "Disabled", "stop": True})

    def test_registry_prefix(self):
        self.r07(reg_op(path="SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", name="X"))

    def test_registry_prefix_is_case_insensitive(self):
        self.r07(reg_op(path="system\\currentcontrolset\\control\\secureboot", name="X"))

    def test_registry_prefix_has_a_boundary(self):
        errs = self.run_entries(entry(apply=[reg_op(path="SYSTEM\\CurrentControlSet\\Control\\SecureBootX", name="X")]))
        self.assertNoFinding(errs, "R07")

    def test_registry_defender_value(self):
        self.r07(reg_op(path="SOFTWARE\\Policies\\Microsoft\\Windows Defender", name="DisableAntiSpyware"))

    def test_defender_hardening_value_is_allowed(self):
        errs = self.run_entries(entry(apply=[reg_op(path="SOFTWARE\\Policies\\Microsoft\\Windows Defender", name="PUAProtection")]))
        self.assertNoFinding(errs, "R07")

    def test_smartscreen_value(self):
        self.r07(reg_op(path="SOFTWARE\\Policies\\Microsoft\\Windows\\System", name="EnableSmartScreen", data=0))

    def test_service_key_of_never_touch_service(self):
        self.r07(reg_op(path="SYSTEM\\CurrentControlSet\\Services\\wuauserv", name="Start", data=4))

    def test_service_start_must_use_service_op(self):
        self.r07(reg_op(path="SYSTEM\\CurrentControlSet\\Services\\DiagTrack", name="Start", data=4))

    def test_appx(self):
        self.r07(dict(APPX, package_name="Microsoft.WindowsStore"), rollback=_partial())
        self.r07(dict(APPX, package_name="Microsoft.UI.Xaml.2.8"), rollback=_partial())

    def test_security_app_is_protected_under_both_names(self):
        # Windows 11 ships the Windows Security app as Microsoft.SecHealthUI, Windows 10 as
        # Microsoft.Windows.SecHealthUI (winhelponline.com, read 2026-11-12). Both must stay protected.
        for name in ("Microsoft.SecHealthUI", "Microsoft.Windows.SecHealthUI"):
            self.r07(dict(APPX, package_name=name), rollback=_partial())

    def test_scheduled_task(self):
        op = {"type": "scheduled_task", "path": "\\Microsoft\\Windows\\WindowsUpdate\\", "name": "Scheduled Start",
              "state": "Disabled", "if_missing": "skip"}
        self.r07(op)
        self.r07(dict(op, path="\\Microsoft\\Windows\\PI\\", name="Secure-Boot-Update"))

    def test_optional_feature(self):
        self.r07({"type": "optional_feature", "name": "Windows-Defender-Default-Definitions", "state": "Disabled"})

    def test_planned_targets_are_not_blocked(self):
        for op in (
            {"type": "service", "name": "DiagTrack", "startup": "Disabled", "stop": True},
            {"type": "service", "name": "whesvc", "startup": "Disabled", "stop": True},
            dict(APPX, package_name="Microsoft.Copilot"),
            dict(APPX, package_name="Microsoft.MicrosoftOfficeHub"),
            {"type": "optional_feature", "name": "Recall", "state": "Disabled"},
        ):
            self.assertEqual(V.op_violations(op, POLICY), [], op)

    def test_r12_servicing_adjacent_needs_flag_and_profile_3(self):
        errs = self.run_entries(t1_entry(min_profile=3, risk="high", apply=[APPRAISER]))
        self.assertFinds(errs, "R12")
        errs = self.run_entries(t1_entry(min_profile=2, risk="medium", apply=[APPRAISER],
                                         flags={"servicing_adjacent": True}))
        self.assertFinds(errs, "R12")
        ok = t1_entry(min_profile=3, risk="high", apply=[APPRAISER], flags={"servicing_adjacent": True})
        self.assertEqual(self.run_entries(ok), [])

    def test_policy_file_shape(self):
        for key in ("services", "registry_prefixes", "registry_values", "appx_names", "scheduled_tasks",
                    "optional_features"):
            self.assertTrue(POLICY[key], key)
        for rule in POLICY["registry_prefixes"]:
            self.assertEqual(set(rule), {"hive", "path", "reason"})
        for rule in POLICY["registry_values"]:
            self.assertEqual(set(rule), {"hive", "path_prefix", "names", "reason"})
            self.assertTrue(rule["names"])
        names = [s.lower() for s in POLICY["services"]]
        self.assertEqual(len(names), len(set(names)), "duplicate service in never-touch list")
        for must in ("wuauserv", "UsoSvc", "WaaSMedicSvc", "WinDefend", "BITS", "ClipSVC", "TBS", "BDESVC"):
            self.assertIn(must.lower(), names)


class AuditLint(Base):
    GOOD = [
        AUDIT,
        "Get-WindowsOptionalFeature -Online -FeatureName 'Recall' | Select-Object -ExpandProperty State",
        "(Get-Service -Name DiagTrack -ErrorAction SilentlyContinue).StartType",
        "(Get-AppxPackage -AllUsers -Name 'Microsoft.Copilot' | Measure-Object).Count",
        "Get-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Feedback\\Siuf\\' -ErrorAction SilentlyContinue "
        "| Where-Object State -ne 'Disabled' | Measure-Object | Select-Object -ExpandProperty Count",
        "(Get-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Application Experience\\' "
        "-TaskName 'Microsoft Compatibility Appraiser').Actions.Execute",
        "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\DiagTrack').Start",
        "Get-Content -Path 'C:\\ProgramData\\x.txt' | Out-String",
        "(Get-MpComputerStatus).RealTimeProtectionEnabled",
        "auditpol /get /category:*",
        "(auditpol /get /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /r | ConvertFrom-Csv).'Inclusion Setting'",
        "Confirm-SecureBootUEFI -ErrorAction SilentlyContinue",
        "(confirm-securebootuefi)",
    ]
    BAD = [
        "Confirm-SomethingElse -Name 'x'", "Confirm-SecureBootUEFIX", "Get-Item 'x' | Confirm-Bogus",
        "Set-ItemProperty -Path 'x' -Name y -Value 1", "SET-ITEMPROPERTY x", "Remove-Item 'x'",
        "Get-Item 'x' | Out-File 'y'", "Invoke-Expression 'x'", "iex 'x'", "$a = iwr 'x'", "Get-Item 'x'; del 'y'",
        "Get-Item 'x' | sc 'y'", "sc.exe config x", "reg add 'x'", "& 'cmd.exe' /c dir", "Get-Item 'x' > 'y'",
        "Get-Item \"x\"", "[IO.File]::Delete('x')", "(Get-Process x).Kill()", "Test-NetConnection x",
        "Get-WindowsUpdateLog", "Get-Item `x", "Get-Item 'x'\nRemove-Item 'y'", "Get-Item 'http://x'",
        "powershell -enc AAAA", "Stop-Service x", "New-Item 'x'",
        "auditpol /set /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /success:disable", "auditpol /clear /y",
        "auditpol /backup /file:'C:\\x.csv'", "AUDITPOL /SET /category:* /failure:disable", "auditpol",
        "auditpol /get /category:* ; auditpol /remove /allusers", "auditpol /get /category:* /backup",
        "Get-Date | ForEach-Object { auditpol /set /category:* /success:disable }",
    ]

    def test_good_commands_pass(self):
        for cmd in self.GOOD:
            self.assertEqual(V.lint_audit(cmd), [], cmd)

    def test_bad_commands_fail(self):
        for cmd in self.BAD:
            self.assertTrue(V.lint_audit(cmd), cmd)

    def test_r10_reported_per_entry(self):
        e = entry(audit={"checks": [{"command": "Remove-Item 'x'", "expected": "1"}]})
        self.assertFinds(self.run_entries(e), "R10", "audit.checks[0]")


class CommandLine(unittest.TestCase):
    def run_main(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            for name, doc in files.items():
                Path(tmp, name).write_text(json.dumps(doc), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = V.main(["--manifests", tmp])
            return code, out.getvalue(), err.getvalue()

    def test_exit_0_on_clean(self):
        code, out, _ = self.run_main({"a.json": {"module": "m1-telemetry", "schema_version": 1, "entries": [entry()]}})
        self.assertEqual(code, 0)
        self.assertIn("OK: 1 entries", out)

    def test_exit_1_on_findings(self):
        bad = entry(apply=[{"type": "service", "name": "wuauserv", "startup": "Disabled", "stop": True}])
        code, out, _ = self.run_main({"a.json": {"module": "m1-telemetry", "schema_version": 1, "entries": [bad]}})
        self.assertEqual(code, 1)
        self.assertIn("[R07]", out)

    def test_exit_2_on_empty_dir(self):
        code, _, err = self.run_main({})
        self.assertEqual(code, 2)
        self.assertIn("no manifest files", err)

    def test_exit_2_on_broken_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.json").write_text("{not json", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(V.main(["--manifests", tmp]), 2)


SETTING = {"type": "setting", "kind": "defender_pref", "name": "MAPSReporting", "value": 2}
CLEAN = {"type": "file_cleanup", "scope": "machine", "root": "%SystemRoot%\\Temp", "pattern": "*", "min_age_days": 7, "recurse": True}
NETBT = reg_op(path="SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_*", name="NetbiosOptions", data=2)


def once_entry(**over):
    base = dict(
        tier="T1", home_effective="expected", channel_class="cmdlet", mode="once", apply=[CLEAN],
        evidence=[{"grade": "community", "source": "Windows documentation", "claim": "Temporary files are recreated by Windows."}],
        rollback={"strategy": "manual", "reversibility": "partial", "limitation": "Deleted files are not restored; Windows recreates them."},
        audit={"manual_check": "Open Settings, System, Storage, Temporary files and check the size."},
    )
    base.update(over)
    return entry(**base)


class SettingsAndCleanup(Base):
    """R19 (mode once and file_cleanup go together), R20 (wildcard paths), R21 (setting value type), the allow-lists."""

    def test_setting_entry_is_clean(self):
        self.assertEqual(self.run_entries(t1_entry(channel_class="cmdlet", apply=[SETTING])), [])

    def test_setting_value_outside_the_allow_list_is_refused(self):
        self.assertFinds(self.run_entries(t1_entry(apply=[dict(SETTING, value=0)])), "R07", "not allowed")

    def test_setting_name_outside_the_allow_list_is_refused(self):
        self.assertFinds(self.run_entries(t1_entry(apply=[dict(SETTING, name="ExclusionPath", value="C:\\x")])), "R07", "allow-list")

    def test_nothing_can_switch_protection_off(self):
        off = dict(SETTING, name="DisableRealtimeMonitoring", value=True)
        self.assertFinds(self.run_entries(t1_entry(apply=[off])), "R07")
        asr_off = {"type": "setting", "kind": "defender_asr", "name": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "value": "disabled"}
        self.assertFinds(self.run_entries(t1_entry(apply=[asr_off])), "R07")
        audit_off = {"type": "setting", "kind": "audit_policy", "name": "0CCE9215-69AE-11D9-BED3-505054503030", "value": "none"}
        self.assertFinds(self.run_entries(t1_entry(apply=[audit_off])), "R07")

    def test_r21_setting_value_has_the_json_type_of_the_policy_list(self):
        self.assertFinds(self.run_entries(t1_entry(apply=[dict(SETTING, value="2")])), "R21")

    def test_once_entry_is_clean(self):
        self.assertEqual(self.run_entries(once_entry()), [])

    def test_r19_once_is_only_for_cleanup_operations(self):
        self.assertFinds(self.run_entries(once_entry(apply=[SETTING])), "R19", "file_cleanup")

    def test_r19_cleanup_needs_mode_once(self):
        e = t1_entry(apply=[CLEAN], rollback={"strategy": "manual", "reversibility": "partial", "limitation": "Deleted files are not restored; Windows recreates them."})
        self.assertFinds(self.run_entries(e), "R19", "mode=once")

    def test_r19_once_cannot_claim_to_be_reversible(self):
        self.assertFinds(self.run_entries(once_entry(rollback={"strategy": "journal", "reversibility": "full"})), "R19", "partial")

    def test_r17_once_needs_a_check_or_a_manual_check(self):
        self.assertFinds(self.run_entries(once_entry(audit={"notes": "none"})), "R17")

    def test_cleanup_folder_outside_the_allow_list_is_refused(self):
        wu = dict(CLEAN, root="%SystemRoot%\\SoftwareDistribution\\Download")
        self.assertFinds(self.run_entries(once_entry(apply=[wu])), "R07", "cleanup allow-list")

    def test_cleanup_scope_must_match_the_allow_list(self):
        self.assertFinds(self.run_entries(once_entry(apply=[dict(CLEAN, scope="user")])), "R07", "cleanup allow-list")

    def test_wildcard_below_a_fixed_parent_is_clean(self):
        self.assertEqual(self.run_entries(t1_entry(apply=[NETBT])), [])

    def test_a_wildcard_that_cannot_reach_a_protected_key_is_clean(self):
        self.assertEqual(self.run_entries(t1_entry(apply=[reg_op(path="SOFTWARE\\Policies\\Microsoft\\Q*", name="X")])), [])

    def test_r20_wildcard_only_in_the_last_segment(self):
        self.assertFinds(self.run_entries(t1_entry(apply=[reg_op(path="SOFTWARE\\Acme\\*\\Sub")])), "R20")
        self.assertFinds(self.run_entries(t1_entry(apply=[reg_op(path="SOFTWARE\\Acme*\\Tcpip_*")])), "R20")

    def test_r20_wildcard_needs_a_fixed_parent_and_no_merge(self):
        self.assertFinds(self.run_entries(t1_entry(apply=[reg_op(path="Tcpip_*")])), "R20")
        merged = reg_op(path="SOFTWARE\\Acme\\K*", name="SettingsPageVisibility", kind="String", data="hide:home", merge="hide-list")
        self.assertFinds(self.run_entries(t1_entry(apply=[merged])), "R20", "merge")

    def test_a_wildcard_that_could_reach_a_protected_key_is_refused(self):
        self.assertFinds(self.run_entries(t1_entry(apply=[reg_op(path="SOFTWARE\\Policies\\Microsoft\\F*", name="X")])), "R07")
        svc = reg_op(path="SYSTEM\\CurrentControlSet\\Services\\*", name="Foo")
        self.assertFinds(self.run_entries(t1_entry(apply=[svc])), "R07", "never-touch service")

    def test_policy_sections_are_well_formed(self):
        import re
        for kind, table in POLICY["settings"].items():
            if kind == "notice":
                continue
            self.assertIn(kind, ("defender_pref", "defender_asr", "audit_policy"))
            for name, values in table.items():
                self.assertTrue(values, f"{kind} {name}: empty list")
                self.assertEqual(len({type(v) for v in values}), 1, f"{kind} {name}: mixed value types")
                if kind != "defender_pref":
                    self.assertTrue(all(isinstance(v, str) for v in values))
                if kind == "defender_asr":
                    self.assertRegex(name, r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
                    self.assertNotIn("disabled", values)
                if kind == "audit_policy":
                    self.assertRegex(name, r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$")
                    self.assertNotIn("none", values)
                if kind == "defender_pref" and name.startswith("Disable"):
                    self.assertEqual(values, [False], f"{name}: a Disable* preference may only be set to false")
        scopes = {"machine": ("%systemroot%", "%windir%", "%programdata%", "%systemdrive%"),
                  "user": ("%userprofile%", "%localappdata%", "%appdata%")}
        for root in POLICY["cleanup"]["roots"]:
            self.assertTrue(root["path"].lower().startswith(scopes[root["scope"]]), root)
            self.assertIsNone(re.search(r"softwaredistribution|winsxs|servicing|\\logs\\winevt|\\installer\\|windowsapps|windows defender", root["path"].lower()), root)


if __name__ == "__main__":
    unittest.main()
