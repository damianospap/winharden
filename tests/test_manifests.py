"""Tests over the real manifests: they must validate, and the project's own rules must stay encoded in them.

Run from the project root:  python3 -I -m unittest discover -s tests -v
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import gen_reference as G  # noqa: E402
import validate_manifests as V  # noqa: E402

SCHEMA = V.load_json(ROOT / "schema" / "manifest.schema.json")
POLICY = V.load_json(ROOT / "policy" / "never-touch.json")
FILES = sorted((ROOT / "manifests").glob("*.json"))
DOCS = [(f.name, V.load_json(f)) for f in FILES]
ENTRIES = {e["id"]: e for _, d in DOCS for e in d["entries"]}


class RealManifests(unittest.TestCase):
    def test_manifest_files_exist(self):
        self.assertGreaterEqual(len(FILES), 1)

    def test_all_manifests_validate(self):
        self.assertEqual(V.validate_all(DOCS, SCHEMA, POLICY), [])

    def test_file_name_matches_module(self):
        for name, doc in DOCS:
            self.assertEqual(name, doc["module"] + ".json")

    def test_each_module_uses_one_id_prefix_and_no_prefix_is_shared(self):
        owner = {}
        for name, doc in DOCS:
            prefixes = {e["id"].split("-")[0] for e in doc["entries"]}
            self.assertEqual(len(prefixes), 1, f"{name} mixes id prefixes {sorted(prefixes)}")
            (prefix,) = prefixes
            self.assertNotIn(prefix, owner, f"prefix {prefix} is used by {owner.get(prefix)} and {name}")
            owner[prefix] = name

    def test_unverified_entries_say_how_to_verify(self):
        for eid, e in ENTRIES.items():
            if e["home_effective"] == "unverified":
                self.assertIn("VM", e.get("notes", ""), f"{eid}: an unverified entry must say how it will be verified")

    def test_no_evidence_rests_on_a_search_snippet(self):
        for eid, e in ENTRIES.items():
            for ev in e["evidence"]:
                self.assertNotIn("snippet", ev["source"].lower(), f"{eid}: read the page instead of citing a search snippet")


class AppxModule(unittest.TestCase):
    """Module m4-appx: the decisions of docs/DECISIONS.md (D1-D3) and docs/M4-CATALOG.md section 6 as tests."""

    APPX = {eid: e for eid, e in ENTRIES.items() if eid.startswith("appx-")}

    def test_module_is_present_and_ids_are_numbered_without_gaps(self):
        numbers = sorted(int(eid.split("-")[1]) for eid in self.APPX)
        self.assertEqual(numbers, list(range(1, len(numbers) + 1)))
        self.assertGreaterEqual(len(numbers), 30)

    def test_each_entry_removes_one_package_for_all_users_and_deprovisions_it(self):
        for eid, e in self.APPX.items():
            self.assertEqual(len(e["apply"]), 1, eid)
            op = e["apply"][0]
            self.assertEqual(op["type"], "appx", eid)
            self.assertTrue(op["deprovision"] and op["all_users"], f"{eid}: removal needs the installed and the provisioned copy")

    def test_a_package_is_handled_by_exactly_one_entry_across_all_manifests(self):
        seen = {}
        for eid, e in ENTRIES.items():
            for op in e.get("apply", []):
                if op["type"] == "appx":
                    key = op["package_name"].lower()
                    self.assertNotIn(key, seen, f"{eid} repeats {op['package_name']} already handled by {seen.get(key)}")
                    seen[key] = eid

    def test_audit_checks_use_the_package_name_of_the_operation(self):
        for eid, e in self.APPX.items():
            name = e["apply"][0]["package_name"]
            self.assertEqual(len(e["audit"]["checks"]), 2, eid)
            for check in e["audit"]["checks"]:
                self.assertIn(f"'{name}'", check["command"], eid)
                self.assertEqual(check["expected"], "0", eid)

    def test_entries_that_hold_user_data_are_flagged_and_partial(self):
        for eid in ("appx-006-sticky-notes", "appx-007-microsoft-todo"):
            e = ENTRIES[eid]
            self.assertTrue(e["flags"]["deletes_user_data"], eid)
            self.assertEqual(e["rollback"]["reversibility"], "partial", eid)

    def test_xbox_packages_that_other_components_may_need_stay_out(self):
        # D2: Xbox.TCUI is reported as required by the Store (never-touch intent); XboxSpeechToTextOverlay is
        # reported as impossible to reinstall (the project promises reversibility); XboxIdentityProvider is the
        # sign-in framework of the Xbox stack. All three are Microsoft-listed removable but are not offered.
        out = {"microsoft.xbox.tcui", "microsoft.xboxidentityprovider", "microsoft.xboxspeechtotextoverlay"}
        for eid, e in ENTRIES.items():
            for op in e.get("apply", []):
                if op["type"] == "appx":
                    self.assertNotIn(op["package_name"].lower(), out, eid)

    def test_basic_tools_are_never_offered(self):
        keep = {"microsoft.windows.photos", "microsoft.windowscalculator", "microsoft.windowscamera",
                "microsoft.windowsnotepad", "microsoft.paint", "microsoft.screensketch", "microsoft.windowsterminal",
                "microsoft.zunemusic", "microsoft.gethelp", "microsoft.mspaint"}
        for eid, e in ENTRIES.items():
            for op in e.get("apply", []):
                if op["type"] == "appx":
                    self.assertNotIn(op["package_name"].lower(), keep, eid)

    def test_profile_1_is_limited_to_packages_microsoft_marks_for_removal_by_default(self):
        # D1: the classic tier only takes apps that Microsoft's own sample selects (default true) and that have no
        # documented dependency or user data. Copilot (ai-006) is the only other profile-1 AppX entry.
        for eid, e in self.APPX.items():
            if e["min_profile"] == 1:
                claims = " ".join(ev["claim"] for ev in e["evidence"] if ev["grade"] == "ms-doc-nonhome")
                self.assertIn("default value true", claims, eid)
                self.assertEqual(e["risk"], "low", eid)
                self.assertNotIn("flags", e, eid)


class PolicyIsMinimal(unittest.TestCase):
    """The allow-lists of the policy file hold exactly what the manifests use, with nothing kept in reserve."""

    USED = {}
    ROOTS = set()
    for _e in ENTRIES.values():
        for _op in _e.get("apply", []):
            if _op["type"] == "setting":
                USED.setdefault((_op["kind"], _op["name"].lower()), set()).add(V.canon_value(_op["value"]))
            elif _op["type"] == "file_cleanup":
                ROOTS.add((_op["scope"], _op["root"].lower()))

    def test_every_setting_value_in_the_policy_is_used_by_a_manifest(self):
        for kind, table in POLICY["settings"].items():
            if kind == "notice":
                continue
            for name, values in table.items():
                for v in values:
                    self.assertIn(V.canon_value(v), self.USED.get((kind, name.lower()), set()),
                                  f"{kind} {name} {v}: the policy allows it but no manifest uses it")

    def test_every_cleanup_root_in_the_policy_is_used_by_a_manifest(self):
        for root in POLICY["cleanup"]["roots"]:
            self.assertIn((root["scope"], root["path"].lower()), self.ROOTS, f"{root}: the policy allows it but no manifest uses it")

    def test_audit_policy_is_only_ever_widened(self):
        for guid, values in POLICY["settings"]["audit_policy"].items():
            self.assertEqual(values, ["success_failure"], f"{guid}: the tool may only write Success and Failure")

    def test_hardware_requirements_are_implemented_by_the_engine(self):
        engine = (ROOT / "engine" / "Plan.ps1").read_text(encoding="utf-8")
        implemented = set(re.findall(r"\$Requirement -eq '([a-z0-9_]+)'", engine))
        for eid, e in ENTRIES.items():
            if "requires_hardware" in e:
                self.assertIn(e["requires_hardware"], implemented, f"{eid}: the engine does not implement this requirement")


class DefenderModule(unittest.TestCase):
    ENTRIES = [e for e in ENTRIES.values() if e["module"] == "m7-defender"]

    def test_every_entry_needs_defender_to_be_the_active_antivirus(self):
        for e in self.ENTRIES:
            self.assertEqual(e.get("requires_hardware"), "defender_active", e["id"])

    def test_nothing_in_the_module_turns_protection_off(self):
        for e in self.ENTRIES:
            for op in e.get("apply", []):
                if op["type"] == "setting" and op["kind"] == "defender_pref" and op["name"].startswith("Disable"):
                    self.assertIs(op["value"], False, f"{e['id']}: {op['name']} may only be set to false")
                if op["type"] == "setting" and op["kind"] == "defender_asr":
                    self.assertIn(op["value"], ("block", "warn"), e["id"])

    def test_asr_audit_checks_read_the_rule_the_operation_writes(self):
        for e in self.ENTRIES:
            for op in e.get("apply", []):
                if op["type"] == "setting" and op["kind"] == "defender_asr":
                    commands = [c["command"].lower() for c in e["audit"]["checks"]]
                    self.assertTrue(any(op["name"].lower() in c for c in commands), f"{e['id']}: no check reads {op['name']}")
                    expected = {"block": "1", "warn": "6"}[op["value"]]
                    self.assertEqual([c["expected"] for c in e["audit"]["checks"]], [expected], e["id"])

    def test_the_three_standard_protection_rules_are_in_profile_2(self):
        standard = {"56a863a9-875e-4185-98a7-b882c64b5ce5", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "e6db77e5-3df2-4cf1-b95a-636979351e5b"}
        found = {op["name"].lower(): e["min_profile"] for e in self.ENTRIES for op in e.get("apply", [])
                 if op["type"] == "setting" and op["kind"] == "defender_asr"}
        for guid in standard:
            self.assertEqual(found.get(guid), 2, guid)

    def test_sample_submission_is_left_to_the_user(self):
        names = {op["name"] for e in ENTRIES.values() for op in e.get("apply", []) if op["type"] == "setting"}
        self.assertNotIn("SubmitSamplesConsent", names)


class AuditModule(unittest.TestCase):
    ENTRIES = [e for e in ENTRIES.values() if e["module"] == "m9-audit"]

    def test_audit_checks_read_the_subcategory_the_operation_writes(self):
        for e in self.ENTRIES:
            for op in e.get("apply", []):
                if op["type"] == "setting" and op["kind"] == "audit_policy":
                    hits = [c for c in e["audit"]["checks"] if op["name"].lower() in c["command"].lower()]
                    self.assertEqual(len(hits), 1, f"{e['id']}: expected exactly one check for {op['name']}")
                    self.assertTrue(hits[0].get("locale_dependent"), f"{e['id']}: the output of auditpol is translated")

    def test_the_command_line_is_only_recorded_together_with_process_creation_auditing(self):
        e = ENTRIES["aud-003-process-creation-command-line"]
        kinds = sorted(op["type"] for op in e["apply"])
        self.assertEqual(kinds, ["registry", "setting"])


class CleanupModule(unittest.TestCase):
    ENTRIES = [e for e in ENTRIES.values() if e["module"] == "m8-cleanup"]

    def test_the_module_holds_every_one_time_entry_and_nothing_else(self):
        self.assertEqual({e["mode"] for e in self.ENTRIES}, {"once"})
        self.assertEqual({e["id"] for e in ENTRIES.values() if e["mode"] == "once"}, {e["id"] for e in self.ENTRIES})

    def test_nothing_is_deleted_that_is_not_older_than_a_day(self):
        for e in self.ENTRIES:
            for op in e["apply"]:
                self.assertGreaterEqual(op["min_age_days"], 1, f"{e['id']}: files that changed today may be in use")


class NetworkModule(unittest.TestCase):
    ENTRIES = [e for e in ENTRIES.values() if e["module"] == "m6-network"]

    # (key path, value name) -> the only value the module may write there. Lower case, as the registry compares.
    SECURE = {
        ("system\\currentcontrolset\\services\\lanmanworkstation\\parameters", "requiresecuritysignature"): 1,
        ("system\\currentcontrolset\\services\\lanmanserver\\parameters", "requiresecuritysignature"): 1,
        ("system\\currentcontrolset\\services\\lanmanworkstation\\parameters", "allowinsecureguestauth"): 0,
        ("software\\policies\\microsoft\\windows\\lanmanworkstation", "allowinsecureguestauth"): 0,
        ("system\\currentcontrolset\\control\\securityproviders\\wdigest", "uselogoncredential"): 0,
        ("system\\currentcontrolset\\control\\lsa", "lmcompatibilitylevel"): 5,
        ("system\\currentcontrolset\\control\\lsa", "restrictanonymous"): 1,
        ("system\\currentcontrolset\\control\\lsa", "restrictanonymoussam"): 1,
        ("software\\policies\\microsoft\\windows nt\\dnsclient", "enablemulticast"): 0,
        ("system\\currentcontrolset\\services\\dnscache\\parameters", "enablemdns"): 0,
        ("system\\currentcontrolset\\services\\netbt\\parameters\\interfaces\\tcpip_*", "netbiosoptions"): 2,
        ("software\\microsoft\\windows\\currentversion\\policies\\explorer", "nodrivetypeautorun"): 255,
        ("software\\microsoft\\windows script host\\settings", "enabled"): 0,
    }

    def test_ids_are_numbered_without_gaps(self):
        self.assertEqual([e["id"][:7] for e in self.ENTRIES], [f"net-{n:03d}" for n in range(1, len(self.ENTRIES) + 1)])

    def test_every_registry_value_is_a_known_secure_value_and_every_secure_value_is_used(self):
        used = set()
        for e in self.ENTRIES:
            for op in e.get("apply", []):
                if op["type"] != "registry":
                    continue
                key = (op["path"].lower(), op["name"].lower())
                self.assertIn(key, self.SECURE, f"{e['id']}: {op['path']} {op['name']} is not a value this module is meant to write")
                self.assertEqual((op["kind"], op["data"]), ("DWord", self.SECURE[key]), e["id"])
                used.add(key)
        self.assertEqual(used, set(self.SECURE))

    def test_services_are_only_disabled_and_stopped_and_features_only_disabled(self):
        for e in self.ENTRIES:
            for op in e.get("apply", []):
                if op["type"] == "service":
                    self.assertEqual((op["startup"], op["stop"]), ("Disabled", True), e["id"])
                elif op["type"] == "optional_feature":
                    self.assertEqual(op["state"], "Disabled", e["id"])
                else:
                    self.assertEqual(op["type"], "registry", f"{e['id']}: the module does not use {op['type']} operations")

    def test_signing_is_required_in_both_documented_keys(self):
        for eid, key in (("net-006-smb-client-signing", "lanmanworkstation"), ("net-012-smb-server-signing", "lanmanserver")):
            (op,) = ENTRIES[eid]["apply"]
            self.assertTrue(op["path"].lower().endswith(f"services\\{key}\\parameters"), eid)
            self.assertEqual((op["name"], op["data"]), ("RequireSecuritySignature", 1), eid)

    def test_netbios_has_one_wildcard_in_the_last_segment_and_the_audit_reads_the_same_keys(self):
        e = ENTRIES["net-005-netbios-off"]
        (op,) = e["apply"]
        self.assertEqual(op["path"].count("*"), 1)
        self.assertTrue(op["path"].endswith("\\Tcpip_*"))
        (check,) = e["audit"]["checks"]
        self.assertIn(op["path"].rsplit("\\", 1)[0].lower(), check["command"].lower())
        self.assertIn("'tcpip_*'", check["command"].lower())
        self.assertEqual(check["expected"], "0", "the check counts adapters that are not set to 2")

    def test_the_dependent_service_is_stopped_before_the_one_it_depends_on(self):
        names = [op["name"] for op in ENTRIES["net-015-ssdp-upnp-off"]["apply"]]
        self.assertEqual(names, ["upnphost", "SSDPSRV"], "upnphost depends on SSDPSRV")

    def test_only_the_two_opt_in_entries_are_opt_in_and_they_are_the_risky_ones(self):
        opt_in = {e["id"]: e for e in ENTRIES.values() if "opt_in" in e}
        self.assertEqual({k: v["opt_in"] for k, v in opt_in.items() if v["module"] == "m6-network"},
                         {"net-017-print-spooler-off": "no-printing", "net-018-server-service-off": "no-file-sharing"})
        for e in opt_in.values():
            if e["module"] == "m6-network":
                self.assertEqual((e["min_profile"], e["risk"]), (3, "high"), e["id"])

    def test_profile_1_stays_classic_and_harmless(self):
        self.assertEqual(sorted(e["id"][:7] for e in self.ENTRIES if e["min_profile"] == 1), ["net-001", "net-002", "net-003"])
        for e in self.ENTRIES:
            if e["min_profile"] == 1:
                self.assertEqual(e["risk"], "low", e["id"])

    def test_the_firewall_entry_only_reads_and_covers_all_three_profiles(self):
        e = ENTRIES["net-003-firewall-profiles-attest"]
        self.assertEqual(e["mode"], "attest")
        self.assertNotIn("apply", e)
        commands = " ".join(c["command"] for c in e["audit"]["checks"])
        for profile in ("Domain", "Private", "Public"):
            self.assertIn(f"-Name {profile}", commands)
        self.assertEqual({c["expected"] for c in e["audit"]["checks"]}, {"True"})

    def test_audit_checks_read_what_the_operations_write(self):
        for e in self.ENTRIES:
            if e["mode"] != "enforce":
                continue
            commands = " ".join(c["command"] for c in e["audit"]["checks"]).lower()
            families = re.findall(r"-like '([a-z0-9_]+)\*'", commands)  # a check may read a whole family of feature names
            for op in e["apply"]:
                name = op["name"].lower()
                self.assertTrue(name in commands or any(name.startswith(f) for f in families),
                                f"{e['id']}: no check reads {op['name']}")

    def test_entries_that_rest_on_a_policy_key_say_that_home_may_ignore_it(self):
        for e in self.ENTRIES:
            if e["channel_class"] == "policy":
                self.assertEqual(e["home_effective"], "unverified", e["id"])
                self.assertTrue(any(x["grade"] == "ms-doc-nonhome" or x["grade"] == "third-party" for x in e["evidence"]), e["id"])

    def test_features_that_have_children_are_partial_to_roll_back_and_say_so(self):
        for eid in ("net-001-smb1-feature-off", "net-011-powershell-v2-off"):
            r = ENTRIES[eid]["rollback"]
            self.assertEqual((r["strategy"], r["reversibility"]), ("journal", "partial"), eid)
            self.assertRegex(r["limitation"], r"sub-features|child feature", eid)


class PlatformModule(unittest.TestCase):
    ENTRIES = [e for e in ENTRIES.values() if e["module"] == "m5-platform"]
    # Entries that only read or only list steps: the firmware, the TPM, BitLocker, the boot configuration and the driver
    # blocklist are on the never-touch list or outside what the tool edits.
    READ_ONLY = ["plt-001-secure-boot-attest", "plt-002-tpm2-attest", "plt-003-secure-boot-certificates-attest",
                 "plt-004-device-encryption-attest", "plt-005-builtin-accounts-attest", "plt-006-test-signing-manual",
                 "plt-009-vulnerable-driver-blocklist-attest"]
    # (key path, value name) -> the only value the module may write there. Lower case, as the registry compares.
    SECURE = {
        ("software\\microsoft\\windows\\currentversion\\policies\\system", "enablelua"): 1,
        ("software\\microsoft\\windows\\currentversion\\policies\\system", "promptonsecuredesktop"): 1,
        ("software\\microsoft\\windows\\currentversion\\policies\\system", "consentpromptbehavioradmin"): 2,
        ("system\\currentcontrolset\\control\\lsa", "runasppl"): 2,
        ("system\\currentcontrolset\\control\\deviceguard\\scenarios\\hypervisorenforcedcodeintegrity", "enabled"): 1,
        ("software\\policies\\microsoft\\windows\\kernel dma protection", "deviceenumerationpolicy"): 0,
    }

    def test_ids_are_numbered_without_gaps(self):
        self.assertEqual([e["id"][:7] for e in self.ENTRIES], [f"plt-{n:03d}" for n in range(1, len(self.ENTRIES) + 1)])

    def test_the_read_only_entries_are_exactly_the_profile_1_entries_and_change_nothing(self):
        self.assertEqual(sorted(e["id"] for e in self.ENTRIES if e["min_profile"] == 1), self.READ_ONLY)
        for eid in self.READ_ONLY:
            e = ENTRIES[eid]
            self.assertIn(e["mode"], ("attest", "manual"), eid)
            self.assertNotIn("apply", e, eid)
            self.assertEqual(e["risk"], "low", eid)
        for e in self.ENTRIES:
            if e["id"] not in self.READ_ONLY:
                self.assertEqual(e["mode"], "enforce", e["id"])
                self.assertGreaterEqual(e["min_profile"], 2, e["id"])

    def test_every_registry_value_is_a_known_secure_value_and_every_secure_value_is_used(self):
        used = set()
        for e in self.ENTRIES:
            for op in e.get("apply", []):
                self.assertEqual((op["type"], op["hive"], op["scope"]), ("registry", "HKLM", "machine"), e["id"])
                key = (op["path"].lower(), op["name"].lower())
                self.assertIn(key, self.SECURE, f"{e['id']}: {op['path']} {op['name']} is not a value this module is meant to write")
                self.assertEqual((op["kind"], op["data"]), ("DWord", self.SECURE[key]), e["id"])
                used.add(key)
        self.assertEqual(used, set(self.SECURE))

    def test_lsa_protection_is_written_without_the_uefi_lock(self):
        (op,) = ENTRIES["plt-008-lsa-protection"]["apply"]
        self.assertEqual((op["name"], op["data"]), ("RunAsPPL", 2), "value 1 stores a UEFI variable, so rolling back the registry value would not undo it")
        self.assertIn("UEFI lock", ENTRIES["plt-008-lsa-protection"]["rationale"])

    def test_memory_integrity_needs_virtualization_and_writes_only_the_enabled_value(self):
        e = ENTRIES["plt-011-memory-integrity"]
        self.assertEqual(e["requires_hardware"], "virtualization")
        self.assertEqual([op["name"] for op in e["apply"]], ["Enabled"])
        self.assertEqual((e["min_profile"], e["risk"]), (3, "high"))
        self.assertTrue(e["flags"]["requires_reboot"])
        self.assertIn("virtualization", e["notes"].lower(), "the notes must say that the second check needs hardware virtualization")
        gated = [other["id"] for other in self.ENTRIES if "requires_hardware" in other]
        self.assertEqual(gated, [e["id"]], "no other entry of the module needs special hardware")

    def test_audit_checks_read_what_the_operations_write(self):
        for e in self.ENTRIES:
            for op in e.get("apply", []):
                matching = [c for c in e["audit"]["checks"]
                            if op["path"].lower() in c["command"].lower() and op["name"].lower() in c["command"].lower()]
                self.assertEqual([c["expected"] for c in matching], [str(op["data"])], f"{e['id']}: no single check reads {op['name']}")

    def test_the_secure_boot_check_uses_the_documented_cmdlet_and_expects_true(self):
        (check,) = ENTRIES["plt-001-secure-boot-attest"]["audit"]["checks"]
        self.assertEqual(check, {"command": "Confirm-SecureBootUEFI -ErrorAction SilentlyContinue", "expected": "True"})

    def test_the_tpm_check_uses_the_same_version_test_as_the_engine_gate(self):
        (check,) = ENTRIES["plt-002-tpm2-attest"]["audit"]["checks"]
        self.assertIn("Win32_Tpm", check["command"])
        self.assertIn("-like '2.0*'", check["command"])
        engine = (ROOT / "engine" / "Plan.ps1").read_text(encoding="utf-8")
        self.assertIn("$spec.StartsWith('2.0')", engine)

    def test_certificate_attestation_reads_the_documented_value_and_never_writes_secure_boot_data(self):
        e = ENTRIES["plt-003-secure-boot-certificates-attest"]
        (check,) = e["audit"]["checks"]
        self.assertEqual(check["expected"], "Updated")
        self.assertIn("UEFICA2023Status", check["command"])
        self.assertNotIn("apply", e)
        protected = [rule["path"].lower() for rule in POLICY["registry_prefixes"]]
        self.assertIn("system\\currentcontrolset\\control\\secureboot", protected,
                      "the entry reads under the Secure Boot key, which has to stay on the never-touch list")

    def test_the_driver_blocklist_stays_on_the_never_touch_list_so_its_entry_can_only_read(self):
        rules = [r for r in POLICY["registry_values"] if r["path_prefix"].lower().endswith("control\\ci\\config")]
        self.assertEqual([r["names"] for r in rules], [["VulnerableDriverBlocklistEnable"]])
        e = ENTRIES["plt-009-vulnerable-driver-blocklist-attest"]
        self.assertEqual((e["mode"], e["home_effective"]), ("attest", "unverified"))
        (check,) = e["audit"]["checks"]
        self.assertTrue(check["command"].endswith("-ne 0"), "a missing value is the default, which is on")
        self.assertEqual(check["expected"], "True")

    def test_both_built_in_accounts_are_checked_by_the_well_known_sid_ending(self):
        checks = ENTRIES["plt-005-builtin-accounts-attest"]["audit"]["checks"]
        self.assertEqual(len(checks), 2)
        self.assertEqual(sorted(re.search(r"-(\d{3})'", c["command"]).group(1) for c in checks), ["500", "501"])
        self.assertEqual({c["expected"] for c in checks}, {"False"})

    def test_the_boot_configuration_is_only_ever_read_by_the_tool(self):
        e = ENTRIES["plt-006-test-signing-manual"]
        self.assertEqual((e["mode"], e["rollback"]["strategy"]), ("manual", "manual"))
        steps = " ".join(e["manual_steps"]).lower()
        for word in ("bcdedit /enum {current}", "testsigning", "nointegritychecks"):
            self.assertIn(word, steps)

    def test_policy_and_unverified_entries_say_how_the_edition_is_covered(self):
        e = ENTRIES["plt-012-kernel-dma-block-all"]
        self.assertEqual((e["channel_class"], e["home_effective"]), ("policy", "unverified"))
        self.assertIn("ms-doc-nonhome", {x["grade"] for x in e["evidence"]})
        self.assertIn("physical", e["notes"].lower())
        for eid in ("plt-004-device-encryption-attest", "plt-008-lsa-protection", "plt-011-memory-integrity"):
            self.assertIn("ms-doc-nonhome", {x["grade"] for x in ENTRIES[eid]["evidence"]}, eid)

    def test_uac_entries_use_the_values_the_settings_slider_writes(self):
        self.assertEqual(ENTRIES["plt-007-uac-secure-desktop"]["home_effective"], "expected")
        self.assertEqual(ENTRIES["plt-010-uac-always-notify"]["home_effective"], "expected")
        self.assertEqual([op["name"] for op in ENTRIES["plt-007-uac-secure-desktop"]["apply"]], ["EnableLUA", "PromptOnSecureDesktop"])
        self.assertEqual([op["name"] for op in ENTRIES["plt-010-uac-always-notify"]["apply"]], ["ConsentPromptBehaviorAdmin"])


class OneDriveModule(unittest.TestCase):
    ENTRIES = [e for e in ENTRIES.values() if e["module"] == "m10-onedrive"]
    # (hive, key path, value name) -> the only value the module may write there. Lower case, as the registry compares.
    SECURE = {
        ("HKLM", "software\\policies\\microsoft\\onedrive", "kfmblockoptin"): 1,
        ("HKLM", "software\\policies\\microsoft\\windows\\onedrive", "disablefilesyncngsc"): 1,
        ("HKCU", "software\\policies\\microsoft\\onedrive", "disablepersonalsync"): 1,
    }

    def test_ids_are_numbered_without_gaps(self):
        self.assertEqual([e["id"][:7] for e in self.ENTRIES], [f"one-{n:03d}" for n in range(1, len(self.ENTRIES) + 1)])

    def test_every_registry_value_is_a_known_secure_value_and_every_secure_value_is_used(self):
        used = set()
        for e in self.ENTRIES:
            for op in e.get("apply", []):
                key = (op["hive"], op["path"].lower(), op["name"].lower())
                self.assertIn(key, self.SECURE, f"{e['id']}: {op['hive']}\\{op['path']} {op['name']} is not a value this module is meant to write")
                self.assertEqual((op["type"], op["kind"], op["data"]), ("registry", "DWord", self.SECURE[key]), e["id"])
                self.assertEqual(op["scope"], "user" if op["hive"] == "HKCU" else "machine", e["id"])
                used.add(key)
        self.assertEqual(used, set(self.SECURE))

    def test_only_the_folder_block_is_outside_the_opt_in_tier_and_it_does_not_remove_or_stop_onedrive(self):
        plain = [e for e in self.ENTRIES if "opt_in" not in e]
        self.assertEqual([(e["id"], e["min_profile"]) for e in plain], [("one-001-kfm-block", 2)])
        for e in self.ENTRIES:
            if "opt_in" in e:
                self.assertEqual((e["opt_in"], e["min_profile"]), ("no-onedrive", 3), e["id"])
                self.assertIn(e["risk"], ("medium", "high"), e["id"])

    def test_every_automatic_entry_rests_on_a_policy_key_and_says_that_home_may_ignore_it(self):
        for e in self.ENTRIES:
            if e["mode"] == "enforce":
                self.assertEqual((e["channel_class"], e["home_effective"]), ("policy", "unverified"), e["id"])
                self.assertIn("ms-doc-nonhome", {x["grade"] for x in e["evidence"]}, e["id"])

    def test_the_known_folder_block_never_uses_the_value_that_redirects_the_folders_back(self):
        (op,) = ENTRIES["one-001-kfm-block"]["apply"]
        self.assertEqual((op["name"], op["data"]), ("KFMBlockOptIn", 1))

    def test_audit_checks_read_what_the_operations_write(self):
        for e in self.ENTRIES:
            for op in e.get("apply", []):
                (check,) = e["audit"]["checks"]
                self.assertIn(f"{op['hive']}:\\{op['path']}".lower(), check["command"].lower(), e["id"])
                self.assertIn(f"-Name {op['name']}", check["command"], e["id"])
                self.assertEqual(check["expected"], str(op["data"]), e["id"])

    def test_the_uninstall_is_manual_and_protects_the_files_before_it_removes_the_program(self):
        e = ENTRIES["one-004-onedrive-uninstall-manual"]
        self.assertEqual((e["mode"], e["rollback"]["strategy"]), ("manual", "manual"))
        self.assertNotIn("apply", e)
        steps = [s.lower() for s in e["manual_steps"]]
        uninstall = next(i for i, s in enumerate(steps) if "uninstall" in s)
        backup = next(i for i, s in enumerate(steps) if "backup" in s)
        self.assertLess(backup, uninstall, "folder backup is stopped before the uninstall")
        self.assertTrue(any("microsoft onedrive" in s for s in steps))
        claims = " ".join(x["claim"] for x in e["evidence"])
        self.assertIn("You won't lose files or data by uninstalling OneDrive", claims)


class Reference(unittest.TestCase):
    def test_generated_reference_is_current(self):
        committed = (ROOT / "docs" / "REFERENCE.md").read_bytes().decode("utf-8")
        self.assertEqual(G.render(DOCS), committed, "docs/REFERENCE.md is stale: run python3 -I tools/gen_reference.py")


class RecallRule(unittest.TestCase):
    """Project rule: Recall is explicitly off in every profile and the report attests it."""

    def test_attestation_is_a_read_only_profile_1_entry(self):
        e = ENTRIES["ai-004-recall-attestation"]
        self.assertEqual((e["mode"], e["min_profile"]), ("attest", 1))
        self.assertNotIn("apply", e)

    def test_attestation_reads_the_component_and_both_policies(self):
        commands = " ".join(c["command"] for c in ENTRIES["ai-004-recall-attestation"]["audit"]["checks"])
        for needle in ("'Recall'", "AllowRecallEnablement", "DisableAIDataAnalysis"):
            self.assertIn(needle, commands)

    def test_attestation_keeps_the_manual_check_for_the_user_opt_in(self):
        self.assertIn("Save snapshots", ENTRIES["ai-004-recall-attestation"]["audit"]["manual_check"])

    def test_entries_that_delete_snapshots_are_partial_and_say_so(self):
        # Microsoft documents that saved snapshots are deleted when AllowRecallEnablement is disabled,
        # when DisableAIDataAnalysis is enabled and when Recall is removed. No journal can bring them back.
        for eid in ("ai-001-recall-availability-policy", "ai-002-recall-snapshots-policy", "ai-003-recall-feature-disabled"):
            e = ENTRIES[eid]
            self.assertEqual(e["rollback"]["reversibility"], "partial", eid)
            self.assertIn("snapshots", e["rollback"].get("limitation", ""), eid)
            self.assertIn("deleted", e["impact"], eid)

    def test_profile_1_writes_both_policies_and_disables_the_feature(self):
        applied = set()
        for e in ENTRIES.values():
            if e["mode"] != "enforce" or e["min_profile"] != 1:
                continue
            for op in e.get("apply", []):
                if op["type"] == "registry":
                    applied.add((op["name"], op["data"]))
                elif op["type"] == "optional_feature":
                    applied.add((op["name"], op["state"]))
        for want in (("AllowRecallEnablement", 0), ("DisableAIDataAnalysis", 1), ("Recall", "Disabled")):
            self.assertIn(want, applied)


if __name__ == "__main__":
    unittest.main()
