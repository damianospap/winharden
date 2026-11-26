# winharden

Debloating and hardening for **Windows 11 Home**: plan before every change, rollback through a journal, and verification using independent checks.

Each setting is an entry in a JSON manifest, with its rationale, user impact, verification command, rollback method, and sources with evidence grades. The engine reads the manifests, shows what will change, requests approval, records every change before making it, and verifies the result. It does not use the network or download anything: there is no `irm | iex`.

|  |  |
| --- | --- |
| Platform | Windows 11 Home 25H2 (build 26200) through build 26999 |
| Runtime | Windows PowerShell 5.1, 64-bit, running as Administrator. No dependencies |
| Contents | 133 entries across 10 modules, 3 profiles, and 5 entries available only with `-OptIn` |
| Version | 0.1.0 |
| Status | **Early-stage.** Tested on one VM, not yet on a physical machine |

> Read the Status section before running it, and test it first in a VM with a snapshot.

## Table of Contents

- Status
- Principles and Limitations
- Requirements
- Quick Start
- Profiles and Modules
- Commands and Options
- Security Model
- Verification and Reports
- Files Written by the Tool
- Drift Monitoring
- Manifests
- Architecture
- Development and Testing
- Troubleshooting
- Security and Vulnerability Reporting
- Documentation
- License and Liability

## Status

Early-stage release. This table describes what has and has not been demonstrated so far.

| Topic | Current Status |
| --- | --- |
| Where it has run | On **one** Windows 11 Home VM with PowerShell 5.1. Not yet on a physical machine |
| What was run | `selftest`, `plan`, `apply -Profile 3`, `verify -Profile 3`, and the `rollback` of the first apply. The tester reported that the rollback was correct; its output was not recorded |
| What the VM revealed | Three false failures in `selftest` (D20) and `ERROR` on 29 entries because their audits could not run (D21). These were fixed and confirmed on the VM. Change D22 (`verify` explaining why an entry was not applied) has not yet been run on Windows |
| Entries that passed the verification protocol | **0 out of 133.** 90 are `expected` and 43 are `unverified`: policies that Home may ignore |
| Not yet tested | The drift task (`install-drift`) and physical hardware: TPM, Secure Boot, BitLocker, memory integrity |
| Independent review | Not performed |
| Open items | `docs/BACKLOG.md`, together with the ownership exceptions from the first `apply` reported by the tester, which have not yet been documented |
| Automated checks | Hundreds of Python tests covering the manifests, the shared vectors used by both linters, and the PowerShell code as text. PowerShell is not executed in the development environment, so these checks do not prove its behavior on Windows |

> **Before any****`apply`****:** create a Windows 11 Home VM with a snapshot and follow `docs/VERIFY-PROTOCOL.md`. Profile 3 may break legacy applications and drivers. Do not run it first on the machine you use.

## Principles and Limitations

| Principle | Implementation |
| --- | --- |
| Plan before making changes | `plan` reads the system and shows the "before → after" state for every target. `apply` requires approval bound to the plan hash |
| Record before writing | Every target is first written to the journal (HMAC-SHA256 chain) and only then changed. Every change is read back |
| Transaction per entry | If a step fails, the targets within the same entry that were changed are restored before the next entry begins |
| Rollback with declared limitations | `rollback` restores state from the journal. Anything that cannot be restored (removed applications, deleted files) is declared `partial` in the entry and the plan before the change |
| Independent verification | `verify` checks twice: the engine reads the targets, and the manifest's read-only verification commands are executed |
| Honesty about Home | Policies documented by Microsoft only for Pro and above are marked `unverified`, with instructions for verification in a VM. No entry becomes `verified` without an observation on Home, including the build and date (R05) |
| Never-touch list | `policy/never-touch.json`: Windows Update, Store, Defender engine, Secure Boot, TPM, and BitLocker. The validator checks it, and the engine checks it again when loading the manifests |
| No network access | The engine makes no network calls, and manifest verification commands containing network access are rejected by the linter |
| Idempotent | A second `apply` on a system that is already compliant reports "Nothing to change" and creates no checkpoint |

Limitations, i.e. what the tool **does not** do:

- It does not disable diagnostic data collection. Home does not allow Level 0: the tool retains Required (`tel-001`).
- It never disables Windows Update, SmartScreen, the firewall, or Defender. It only hardens Defender.
- It does not modify Secure Boot, TPM, or BitLocker: it only checks them (`attest`).
- It does not uninstall OneDrive: it blocks startup and sign-in with a personal account (opt-in) and provides manual uninstallation steps (D18).
- It does not support any edition other than Home, or any build earlier than 25H2.
- It is a local, single-machine tool: there is no central management and it does not send reports anywhere.
- XCCDF export is an output format: it is not a benchmark compliance certification and has not been validated with NIST tools.
- Also out of scope: WDAC and App Control, outbound default-deny, schannel configuration, ETW, and LAPS (`docs/THREAT-MODEL.md`, §1).

## Requirements

|  |  |
| --- | --- |
| Operating System | Windows 11 **Home**, build 26200 through 26999 |
| Shell | Windows PowerShell 5.1 (`powershell.exe`) only, 64-bit |
| Permissions | Administrator |
| Platform | Secure Boot enabled and TPM 2.0 enabled. Without these, `apply` stops unless `-AllowPlatformGaps` is specified |
| System State | No pending reboot |
| Network | Not required |

The preflight check covers permissions, 64-bit architecture, Windows edition and build, pending reboot status, Secure Boot, and TPM before making any changes. Each check has a code and a diagnostic message (see the table in Security Model). It does not check the PowerShell version: always launch the tool using `powershell.exe`.

## Quick Start

Use a Windows 11 Home VM with a snapshot. Open Windows PowerShell using "Run as administrator", navigate to the project directory, and run:

powershell

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 selftest
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 plan -Profile 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 apply -Profile 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 verify -Profile 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 checkpoints
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 rollback -To latest
```

`-ExecutionPolicy Bypass` applies only to this process and does not change the system's execution policy.

1. **`selftest`** runs the engine tests against an in-memory system. It changes nothing. `apply` runs it again before making any changes and refuses to continue if it fails.
2. **`plan`** reads the system and shows what will change and why. It changes nothing. It saves the plan and prints the command that applies exactly that plan.
3. **`apply`** displays the plan and asks you to type `APPLY`. It then creates a restore point (best effort) and a checkpoint, applies changes entry by entry, runs `verify`, and generates reports. If a reboot is required, it says so at the end. Non-interactive usage: `apply -Profile 1 -Yes -PlanId <id>`.
4. **`verify`** compares the system against the manifests (Verification and Reports). Use the same `-Profile` as the one used with `apply`.
5. **`checkpoints`** verifies the journal and prints the checkpoints. **`rollback -To latest`** undoes the changes from the most recent `apply` and asks you to type `ROLLBACK`.

The plan has the following format (`<…>` represents values populated by the engine):

text

```text
Plan <id>  profile <N>  engine <version>
  to change: <n> entries (<m> targets)   already compliant: <n>   not applicable: <n>   blocked: <n>

[CHANGE] <entry id>  (profile <p>, risk <low|medium|high>, Home effect: <home_effective>)
    <title>
    <target>:  <before>  ->  <after>
    needs a restart to take effect
[BLOCKED] <entry id>  (profile <p>, risk <…>, Home effect: <…>)
    <title>
    <reason>
```

| Plan Status | Meaning |
| --- | --- |
| `CHANGE` | Will be changed. Each target is displayed with its before and after values |
| `SKIP` | Not applicable here: the service, task, feature, or directory is missing, or the build or edition does not match |
| `BLOCKED` | Will not be changed: a closed gate, missing hardware, or something the engine cannot safely modify (e.g. a value with an unsupported type or an unreadable state) |

Entries that are already compliant are counted ("already compliant") but are not displayed. At the end, the plan lists entries that were not selected and require `-OptIn`, entries that are read-only checks (`attest`), and entries that require manual action.

## Profiles and Modules

Each profile includes all lower-numbered profiles: profile N includes every entry with `min_profile` up to N. Risk increases the minimum required profile: `medium` starts at profile 2, while `high` is restricted to profile 3 (R16).

| Profile | Name | New Entries | Total | Contents |
| --- | --- | --- | --- | --- |
| 1 | Classic | 36 | 36 | Everything a WinUtil-style tool would do: telemetry, ads, basic bloat, temporary files, SMB1 and WDigest off, and read-only platform checks. Goal: break nothing |
| 2 | Private | 46 | 82 | Privacy and attack surface: Defender hardening, legacy protocols, LSA protection, UAC, and more applications |
| 3 | Deep | 46 | 128 | Deep changes: most ASR rules, Controlled Folder Access, auditing, memory integrity, Kernel DMA, and full application removal. May break legacy applications and drivers |

Five entries are outside all profiles and are included only with `-OptIn <name>`:

| `-OptIn` | Entries | What It Does |
| --- | --- | --- |
| `no-printing` | 1 | Disables the Print Spooler service (`net-017`): no printers, including virtual printers such as Microsoft Print to PDF |
| `no-file-sharing` | 1 | Disables the Server service (`net-018`): no other machine can connect to this machine's shared folders or printers |
| `no-onedrive` | 3 | Prevents OneDrive from starting (`one-002`) and blocks sign-in with a personal Microsoft account (`one-003`). `one-004` is manual: it provides uninstallation steps, and the engine changes nothing |

| Module | Prefix | Contents | Entries |
| --- | --- | --- | --- |
| M1 telemetry | `tel` | Diagnostics, feedback, advertising ID, CEIP, DiagTrack, Error Reporting, online speech | 11 |
| M2 consumer | `ads` | Ads and suggestions in Start, lock screen, Settings, search, widgets | 11 |
| M3 AI | `ai` | Recall (disabled and attested in every profile), Copilot, Click to Do, Paint AI | 9 |
| M4 AppX | `appx` | Removal of preinstalled applications (exact names, provisioned and `-AllUsers` pairs) | 30 |
| M5 platform | `plt` | Secure Boot, TPM 2.0, system encryption (checks), UAC, LSA protection, memory integrity, Kernel DMA | 12 |
| M6 network | `net` | SMB1, WDigest, LLMNR, NetBIOS, SMB signing, NTLM, mDNS, SSDP, Script Host, spooler | 18 |
| M7 Defender | `def` | Hardening only: cloud protection, ASR rules, Network Protection, Controlled Folder Access | 28 |
| M8 cleanup | `cln` | Temporary files and junk (only sourced paths, only files older than one day) | 4 |
| M9 audit | `aud` | Advanced Audit Policy and PowerShell script block logging | 6 |
| M10 OneDrive | `one` | Blocking folder redirection to OneDrive, opt-in blocking, and manual uninstallation | 4 |

The prefix can be used with `-Only` and `-Exclude` (`-Only 'tel-*'`). The complete list is available in `docs/REFERENCE.md` (generated from the manifests, with profile, risk, and channel for each entry) and through the `list -Profile 3` command.

## Commands and Options

In the examples, `<ps>` means `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1`.

| Command | Description | Changes Settings |
| --- | --- | --- |
| `help` | Displays help | No |
| `list` | Lists entries with id, profile, tier, mode, risk, and `home_effective` (`-Profile` and `-Only` filter the results) | No |
| `plan` | Shows what will change and why, and saves the plan | No |
| `apply` | Plan, approval, application, `verify`, and reports | **Yes** |
| `verify` | Checks the system against the manifests and generates reports | No |
| `rollback` | Restores everything changed after a checkpoint | **Yes** |
| `checkpoints` | Verifies the journal and prints the checkpoints | No |
| `status` | Displays platform information, preflight status, journal status, and drift task status | No |
| `selftest` | Runs the engine tests against an in-memory system | No |
| `install-drift` | Installs the drift task and a protected copy of the tool | **Yes** |
| `remove-drift` | Removes the drift task (and the copy with `-RemoveFiles`) | **Yes** |
| `drift` | The command executed by the drift task: `verify` and reporting. With `-Reapply`, it reapplies changes | Only with `-Reapply` |

Commands that do not change settings may still write to the state directory (logs, plans, reports): see Files Written by the Tool.

| Option | Applies To | Description |
| --- | --- | --- |
| `-Profile N` | `list`, `plan`, `apply`, `verify`, `drift`, `install-drift` | Selects profile 1, 2, or 3 (default: 1). Each profile includes all lower-numbered profiles |
| `-Only <pattern>` | `list`, `plan`, `apply`, `verify`, `drift` | Includes only entries whose IDs match (wildcards: `tel-*`). `install-drift` does not pass this option to the task |
| `-Exclude <patterns>` | `plan`, `apply`, `verify`, `drift`, `install-drift` | Excludes entries. Comma-separated list: `'appx-*,def-020*'` |
| `-OptIn <name>` | `plan`, `apply`, `verify`, `drift`, `install-drift` | Includes entries requiring explicit opt-in (`no-printing`, `no-file-sharing`, `no-onedrive`) |
| `-PlanId <id>` | `apply` | The ID of the plan you reviewed, as displayed by `plan` or `apply` |
| `-Yes` | `apply`, `rollback` | `apply`: approves without prompting, only when used with the correct `-PlanId`. `rollback`: skips the `ROLLBACK` confirmation prompt |
| `-To <checkpoint>` | `rollback` | The checkpoint (see `checkpoints`) or `latest` for the most recent one |
| `-AcceptDataLoss` | `plan`, `apply`, `verify`, `drift` | Opens the gate for entries that delete user data that no rollback can restore. `verify` uses it only to indicate which gates are closed. `install-drift` never passes it to the task |
| `-AllowServicingAdjacent` | `plan`, `apply`, `verify`, `drift`, `install-drift` | Opens the gate for entries that affect components adjacent to Windows servicing. `install-drift` also passes it to the task |
| `-AllowPlatformGaps` | All commands that perform preflight checks | Continues without Secure Boot or TPM 2.0. Entries that require them remain blocked |
| `-AllowUntestedBuild` | Same as above | A build newer than 26999 becomes a warning instead of a blocker |
| `-AllowOtherEdition` | Same as above | A non-Home edition becomes a warning. The manifests' Home-specific notes do not describe it |
| `-IgnorePendingReboot` | Same as above | A pending reboot becomes a warning |
| `-NoRestorePoint` | `apply` | Does not create a system restore point |
| `-SkipSelfTest` | `apply`, `drift`, `install-drift` | Skips `selftest`. Not recommended |
| `-TrustJournal` | `apply`, `rollback`, `drift` | Continues even if journal verification fails. Use only if you are certain nobody has modified it |
| `-Quick` | `verify` | Checks status only, without running audit commands |
| `-OutDir <directory>` | `apply`, `verify`, `drift` | Writes reports there instead of `reports\<run>` |
| `-Reapply` | `install-drift`, `drift` | Reapplies changes that have drifted (for `install-drift`: configures the task to do so). The task never receives `-AcceptDataLoss`, so it never touches entries that delete data |
| `-RemoveFiles` | `remove-drift` | Also deletes the installed copy |

Examples:

powershell

```powershell
<ps> list -Profile 3                               # what profile 3 contains
<ps> plan -Profile 2 -Exclude 'appx-*'             # profile 2 without application removal
<ps> plan -Profile 1 -OptIn no-printing            # profile 1 and disabling the spooler
<ps> apply -Profile 2 -Yes -PlanId <id>            # applies exactly the plan you reviewed
<ps> verify -Profile 3 -OutDir C:\winharden-reports
<ps> rollback -To cp-<run>                         # restore to a specific checkpoint
```

| Exit Code | Meaning |
| --- | --- |
| 0 | Completed without failures |
| 1 | Completed with failures: reverted entry, `fail` or `error` in `verify`, rollback failure, or `selftest` failure |
| 2 | Refused to start: preflight failure, incorrect usage (e.g. `rollback` without `-To`), or approval not provided |
| 3 | Integrity error or internal error: `selftest` failure before `apply`, journal verification failure, or rejected manifests |

## Security Model

Security protections are layered: each layer covers what the previous one could miss. The complete threat model is available in `docs/THREAT-MODEL.md`.

### Before Making Changes

**Preflight.** Every check has a code and a diagnostic message that a human can act on. `apply` stops on any blocker. Other commands that perform preflight (`plan`, `verify`, `rollback`, `drift`, `install-drift`, `remove-drift`) stop only on PF01 through PF04, so they can also work on VMs without Secure Boot or TPM.

| Code | Check | If It Fails |
| --- | --- | --- |
| PF01 | Running as Administrator | Open Windows PowerShell using "Run as administrator" |
| PF02 | 64-bit Windows and 64-bit PowerShell (in 32-bit PowerShell, registry writes would go to Wow6432Node) | Launch 64-bit Windows PowerShell. 32-bit Windows is not supported |
| PF03 | Build between 26200 and 26999 | Update Windows. For a newer build: `-AllowUntestedBuild`, at your own risk |
| PF04 | Home edition | `-AllowOtherEdition`, at your own risk |
| PF05 | No pending reboot | Restart and run again, or use `-IgnorePendingReboot` |
| PF06 | Secure Boot enabled | Enable it in UEFI (the tool never changes it), or use `-AllowPlatformGaps` |
| PF07 | TPM 2.0 enabled | Enable fTPM or PTT in UEFI, or use `-AllowPlatformGaps` |
| PF08 | Warning: BitLocker or Device Encryption is enabled on the system drive | Make sure you have the recovery key |
| PF09 | Warning: running as SYSTEM | Audits that read HKCU are skipped; the status check covers every profile |

**Never-touch list.** `policy/never-touch.json` is code: any entry that touches something on this list is rejected by the validator (R07) and again by the engine when loading the manifests. A manifest set containing any problem is rejected in its entirety. The shared vectors in `tests/vectors/never-touch.json` run against both implementations (Python and PowerShell).

| Category | Protected Components |
| --- | --- |
| Services (34) | Windows Update, servicing and installation (`wuauserv`, `UsoSvc`, `WaaSMedicSvc`, `BITS`, `TrustedInstaller`, `CryptSvc`, `msiserver`), Store (`ClipSVC`, `AppXSvc`, `InstallService`, `LicenseManager`), Edge updater, Defender and Security Center, firewall (`mpssvc`, `BFE`), BitLocker (`BDESVC`), identity and TPM (`wlidsvc`, `TokenBroker`, `TBS`), core infrastructure (`EventLog`, `RpcSs`, `Winmgmt`, `Schedule`, `gpsvc`, and others) |
| AppX applications (21 patterns) | Store, App Installer, runtime packages (`WindowsAppRuntime`, `UI.Xaml`, `VCLibs`, `NET.Native`), sign-in and accounts (`CloudExperienceHost`, `AAD.BrokerPlugin`, `AccountsControl`), shells (Shell, Start, Search, `Client.*`), and Security Health UI |
| Scheduled tasks (13 patterns) | `WindowsUpdate`, `UpdateOrchestrator`, `WaaSMedic`, `Servicing`, `InstallService`, `Windows Defender`, `BitLocker`, `TPM`, `PI`, `SoftwareProtectionPlatform`, `Clip`, `License Manager`, and the Edge update task |
| Registry | 10 keys (Secure Boot, Windows Update, BitLocker, TPM, Store, EdgeUpdate) and 7 groups of values that would disable Defender (and Tamper Protection), SmartScreen, or the vulnerable driver blocklist |
| Optional features (1) | `Windows-Defender-Default-Definitions` |

Defender settings (10 preferences, 16 ASR rules) and audit policy subcategories (13) work in the opposite direction, as allow-lists: only explicitly listed settings are permitted, and only when they strengthen protection or provide a richer audit trail. File cleanup is permitted only in the 7 directories listed in the `cleanup` allow-list.

**Gates.** Entries with risks that should not be decided silently remain excluded from `apply` until a gate is explicitly opened. `plan` displays them as `BLOCKED` with the reason.

| Gate | What It Excludes | Entries | How to Open |
| --- | --- | --- | --- |
| `deletes_user_data` | Entries that delete user data that no rollback can restore | `appx-006` (Sticky Notes), `appx-007` (Microsoft To Do) | `-AcceptDataLoss` |
| `servicing_adjacent` | Entries that affect components adjacent to Windows servicing | `tel-008` (Compatibility Appraiser task) | `-AllowServicingAdjacent` |
| `requires_hardware` | Entries requiring hardware: virtualization for `plt-011`, active Defender for `def-001` through `def-028` | 29 | No flag: remain blocked while the required hardware or capability is unavailable |

Additionally, 14 entries have `requires_reboot`: the plan indicates that their effects become visible after a restart.

### During Changes

- **Self-test.** `apply`, `drift`, and `install-drift` run `selftest` first. If it fails, the engine does not modify the system (exit code 3).
- **Approval.** The plan ID consists of the first 12 digits of a hash covering the profile, manifests, gates, and, for every entry being changed, every target with its before and after values. If any of these changes, the ID changes, and `-Yes` with the old ID refuses to modify anything. Interactive approval requires typing `APPLY`.
- **Transaction and journal.** Each entry is a transaction group: the previous state of every target is written to the journal before the change, the change is read back, and if a step fails, all targets within that entry are restored before the next entry begins. Each journal record carries an HMAC-SHA256 over its contents and the previous record's MAC: deletion, reordering, or modification of a record becomes detectable. If journal verification fails, the engine neither writes to it nor performs a rollback.
- **Restore point.** Created before `apply`, on a best-effort basis. The actual rollback mechanism is the journal.
- **One execution at a time.** Machine-wide mutex (`Global\winharden-engine`). The state directory is writable only by SYSTEM and Administrators.

### After Changes

- **Verification.** `apply` finishes by running `verify` (Verification and Reports).
- **Rollback.** Restores every target recorded after the checkpoint to the state it had at that time, starting with the most recent record. Restoring a recorded state is idempotent, so transaction records that have already been reverted do not cause problems. It then reads every target again and reports any that differ.

### What It Does Not Guarantee

- The journal provides tamper evidence against anyone who is not an administrator. An administrator can rewrite both the key and the journal.
- Removed applications are not restored by the engine: they must be reinstalled from the Store. Deleted files are not restored. Both are declared `partial`.
- `selftest` checks the engine's logic against an in-memory system. It does not prove that Windows accepts every write: that is what `verify` and `docs/VERIFY-PROTOCOL.md` are for.
- Manifests are code executed as Administrator. The audit linter and never-touch list catch mistakes, but they do not replace a review, and the manifests are not signed.
- Microsoft may restore or ignore settings through an update. The drift task detects this; it does not prevent it.

## Verification and Reports

`verify` checks every entry in the specified profile using two independent methods:

1. **State check.** The engine reads every target (for `scope: user`, every user profile) and compares it against the manifest.
2. **Audit.** The manifest's read-only commands are executed and their output is compared against the expected value. Each command first passes through the linter (single line, single quotes only, allow-listed verbs, no aliases, native executables, redirections, or network access; `auditpol /get` is the exception) and runs in a ConstrainedLanguage runspace. If the command's cmdlet is not available there, as observed in the VM with modules relying on CIM (Defender, ScheduledTasks, NetSecurity), the command is retried once in a FullLanguage runspace after passing the linter. In that case, the linter is the only barrier (D21).

| Entry Status | Meaning |
| --- | --- |
| `pass` | All checks agree with the manifest |
| `fail` | A target is not in the desired state, or an audit returns a different value. The reason is recorded in the report |
| `error` | A target cannot be read, or an audit could not run |
| `na` | Not applicable here: different build or edition, missing hardware, or no target exists on the system (missing service or task) |
| `manual` | Requires human intervention: the tool neither changes nor verifies the setting. The steps are included in the report |

What you should know when reading the results:

- `verify` checks only the profile you specify and, without `-Profile`, checks only profile 1. After `apply -Profile 3`, run `verify -Profile 3`.
- `verify` always compares the system against the manifest, not against what `apply` did. An entry skipped by `apply` because a gate is closed is reported as `fail`, and the reason identifies the gate (`Apply skips this entry: …`, D22).
- An audit may be skipped (`skipped`) without changing the entry's status: when the command is language-dependent and Windows is not running in English (13 of the 203 audits), and when the tool runs as SYSTEM and the command reads HKCU. In these cases, the entry is judged based on the state check.
- `attest` entries (9) are checked through audits only and are never modified. `once` entries (cleanup) have no state to verify: `apply` prints what it did.
- The exit code is 1 if there is at least one `fail` or `error`.

`verify` (and `apply` at the end of its run) generates four files in `%ProgramData%\winharden\reports\<run>`, or in the directory specified by `-OutDir`:

| File | Contents |
| --- | --- |
| `winharden-report.json` | Complete results, for machine-readable processing |
| `winharden-report.html` | The same results in human-readable format |
| `winharden-poam.csv` | POA&M template for exceptions, i.e. anything that does not comply |
| `winharden-xccdf.xml` | Minimal XCCDF 1.2 results export |

Reports are local files and are not uploaded anywhere. Each report includes the engine version and code fingerprint, computer name, a list of its limitations (for example, for `unverified` entries, `pass` means "the value was written and read back", not "Windows enforces it"), and, for every profile, a Recall status line: `attested-off`, `not-attested`, or `not-checked` when `ai-004` was not part of the run.

## Files Written by the Tool

text

```text
%ProgramData%\winharden\            SYSTEM and Administrators only
  journal\journal.jsonl             HMAC-SHA256 chain: before-states, checkpoints
  journal\journal.key               chain key
  plans\plan-<id>.json              every plan that was displayed
  reports\<run>\                    winharden-report.json|html, winharden-poam.csv, winharden-xccdf.xml
  logs\winharden.jsonl              structured log, one JSON object per line
  drift-state.json                  result of the most recent drift task execution
%ProgramFiles%\winharden\           copy of the tool for the drift task (only after install-drift)
```

Access control uses well-known SIDs so that it works on every Windows language.

## Drift Monitoring

After an update, Windows may restore settings and applications. `install-drift` installs a task that detects this.

- **What runs.** Task `\winharden\winharden-drift`, running as SYSTEM, every Sunday at 03:00 and at every startup, for the profile (and the `-Exclude` and `-OptIn` options) specified during `install-drift`. It executes `drift`: `verify`, reporting, and saving the result to `drift-state.json`. If the build has changed since the previous run (feature update), it reports this.
- **Verification only.** Unless installation was performed with `-Reapply`: in that case, it reapplies changes that have drifted, but never entries that delete data (the task never receives `-AcceptDataLoss`). `-AllowServicingAdjacent` is passed to the task only if specified during installation.
- **Protection.** A SYSTEM task that runs scripts is a privilege-escalation path if an unprivileged user can modify those scripts. Files are copied to a Program Files directory, and if anyone other than SYSTEM, Administrators, TrustedInstaller, and CREATOR OWNER can write there, installation fails before the task is registered.
- **Same behavior as****`verify`****.** Entries excluded from `apply` by a closed gate are reported as failures.
- **Checking.** `status` shows whether the task exists and its last execution. `remove-drift` removes it.

The drift task has not been tested on Windows (Status).

## Manifests

One file per module in `manifests/`. Each setting is exactly one entry, with an ID that never changes and is never reused: `<prefix>-<3 digits>-<name>`.

### Entry Fields

| Field | Required | Description |
| --- | --- | --- |
| `id`, `module`, `title` | yes | Entry identity |
| `tier` | yes | Trust tier of the mechanism (see below) |
| `min_profile` | yes | The minimum profile from which the entry is included (1, 2, or 3) |
| `opt_in` | no | If present, the entry is included only with `-OptIn <name>` |
| `mode` | yes | What the engine does (see below) |
| `home_effective` | yes | Whether the result has been observed on Home (see below) |
| `verified` | no | Build, date, VM, and observation. Required when `home_effective` is `verified` (R05) |
| `channel_class` | yes | Change channel: `csp`, `policy`, `cmdlet`, `settings-backing`, `unsupported` |
| `unsupported_justification` | no | Justification if the channel is `unsupported` (R04) |
| `applicability` | no | Editions and minimum build |
| `requires_hardware` | no | Hardware that must be present; otherwise, the entry remains blocked |
| `rationale`, `impact` | yes | Why the change is made and what it changes for the user |
| `apply` | no | List of operations (see below) |
| `audit` | yes | Read-only commands with expected values (`checks`), or `manual_check` |
| `rollback` | yes | Strategy and `reversibility` (`full` or `partial`, with limitation) |
| `manual_steps` | no | Instructions for the user (`manual` mode) |
| `flags` | no | `servicing_adjacent`, `requires_reboot`, `deletes_user_data` |
| `risk` | yes | `low`, `medium`, or `high` |
| `evidence`, `references` | yes | Every claim with an evidence grade, and the corresponding links |
| `notes` | no | For `unverified` entries: how to verify them in a VM |

### Values and Distribution

| `mode` | Entries | Meaning |
| --- | --- | --- |
| `enforce` | 115 | The engine applies and verifies |
| `once` | 4 | One-time operation (file cleanup): there is no state to verify |
| `attest` | 9 | Verification and reporting only, never modification |
| `manual` | 5 | Instructions for the user; the engine reports them |

| `home_effective` | Entries | Meaning |
| --- | --- | --- |
| `verified` | 0 | Observed on Home (with build and date) |
| `expected` | 90 | Version-independent mechanism: service, task, AppX, feature, or a value written by Settings itself |
| `unverified` | 43 | Policy that Home may ignore. `notes` explains how to verify it |
| `na` | 0 | Not applicable to Home, so it is not applied (R14) |

| `tier` | Entries | Meaning |
| --- | --- | --- |
| `T0` | 23 | Supported mechanism, with the result on Home expected or observed. Requires an `ms-doc` or `ms-statement` source (R03) |
| `T1` | 110 | Documented or widely used, reversible. The result on Home may be `unverified` |
| `T2` | 0 | Unsupported channel or servicing-adjacent, profile 3 only (R02, R04) |

| `risk` | Entries | Meaning |
| --- | --- | --- |
| `low` | 92 | From profile 1 |
| `medium` | 32 | From profile 2 |
| `high` | 9 | Profile 3 only |

Evidence grades (`evidence[].grade`) indicate how much confidence to place in each claim:

| Grade | Meaning |
| --- | --- |
| `ms-doc` | Microsoft documentation for the setting |
| `ms-doc-nonhome` | Microsoft documentation that does not mention Home (e.g. Pro, Enterprise, Education only). The entry is therefore `unverified` |
| `ms-statement` | Microsoft statement outside the setting's documentation: blog post, announcement, or response |
| `third-party` | Third-party source with a methodology, e.g. an audit item from a benchmark |
| `community` | Forum, tutorial, list, or script from another tool |
| `background` | Previous knowledge that has not been rechecked. Explicitly declared as such |

### Operations

| Type | Operations | What It Changes |
| --- | --- | --- |
| `registry` | 66 | Registry value in HKLM or HKCU (for HKCU: every existing user profile and the Default user hive) |
| `setting` | 39 | Defender preference, ASR rule, or audit policy subcategory (allow-list) |
| `appx` | 31 | Package removal for all users: both installed and provisioned packages |
| `service` | 7 | Service startup type and state |
| `scheduled_task` | 7 | Disables a task |
| `file_cleanup` | 7 | Cleans files older than one day, only in allow-listed directories |
| `optional_feature` | 3 | Disables a Windows optional feature |

### Example

\<details\> \<summary\>The \<code\>tel-001-diagnostic-data-required\</code\> entry, with one source and one link instead of all of them\</summary\>

json

```json
{
  "id": "tel-001-diagnostic-data-required",
  "module": "m1-telemetry",
  "title": "Pin diagnostic data to Required",
  "tier": "T1",
  "min_profile": 1,
  "mode": "enforce",
  "home_effective": "unverified",
  "channel_class": "policy",
  "applicability": {
    "editions": [
      "Home"
    ],
    "min_build": 26200
  },
  "rationale": "Windows 11 Home offers only Required and Optional diagnostic data and cannot switch collection off. Pinning the Allow Diagnostic Data policy to 1 (Required) keeps Optional data off. Level 0 is not used: Microsoft documents it as honoured only on Enterprise, Education and Server editions and equal to 1 elsewhere.",
  "impact": "The Optional diagnostic data switch in Settings becomes locked and may show a managed-by-your-organization notice. Windows Insider enrollment, which needs Optional data, is blocked.",
  "apply": [
    {
      "type": "registry",
      "hive": "HKLM",
      "path": "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
      "name": "AllowTelemetry",
      "kind": "DWord",
      "data": 1,
      "scope": "machine"
    }
  ],
  "audit": {
    "checks": [
      {
        "command": "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry",
        "expected": "1"
      }
    ]
  },
  "rollback": {
    "strategy": "journal",
    "reversibility": "full"
  },
  "risk": "low",
  "evidence": [
    {
      "grade": "ms-doc-nonhome",
      "source": "learn.microsoft.com Policy CSP System, AllowTelemetry (read 2026-11-10)",
      "claim": "Documented for Pro, Enterprise, Education and IoT only; Home is not listed. Level 0 applies only to Enterprise, Education, IoT and Server and is equivalent to 1 on other devices."
    }
  ],
  "references": [
    {
      "title": "Policy CSP - System (AllowTelemetry)",
      "url": "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system"
    }
  ]
}
```

\</details\>

### Validator Rules

`tools/validate_manifests.py` enforces the schema (`schema/manifest.schema.json`) and 21 additional rules.

\<details\> \<summary\>Rules R01 through R21\</summary\>

| Rule | What It Enforces |
| --- | --- |
| R01 | The ID is unique |
| R02 | Tier T2 is allowed only in profile 3 |
| R03 | T0 requires an `ms-doc` or `ms-statement` source, `home_effective` of `verified` or `expected`, and a supported channel |
| R04 | An unsupported channel requires T2 and a justification of at least 40 characters |
| R05 | `home_effective: verified` requires the `verified` object with build and date |
| R06 | `enforce` and `once` must have `apply`; `attest` and `manual` must not, and `manual` must have `manual_steps` |
| R07 | No operation may touch the never-touch list or go outside the allow-lists (settings, cleanup directories) |
| R08 | Partial reversibility must declare a limitation (at least 20 characters), and AppX removal must always be `partial` |
| R09 | No duplicate source links |
| R10 | Every audit command must pass the linter (single line, single quotes, read-only verbs only, no aliases or network access) |
| R11 | The hive must match the `scope` (HKLM with machine, HKCU with user) |
| R12 | A servicing-adjacent component requires `flags.servicing_adjacent` and profile 3 |
| R13 | The entry's `module` must match the file it belongs to |
| R14 | `home_effective: na` must not be applied |
| R15 | Data must match `kind` (and `merge: hide-list` requires a String beginning with `hide:`) |
| R16 | Risk determines the minimum profile: `medium` from profile 2, `high` from profile 3 |
| R17 | `enforce` and `attest` require `audit.checks`; `once` requires checks or `manual_check`; `manual` requires `manual_check` |
| R18 | `deletes_user_data` applies only to `enforce` and `once` and cannot be `full` |
| R19 | `once` applies only to file cleanup, with `partial` reversibility, and cleanup must use `once` |
| R20 | Wildcards are allowed only in the final path segment, under a fixed parent key, and not together with `merge` |
| R21 | A `setting` value must have the correct JSON type for `kind` |

\</details\>

## Architecture

text

```text
winharden.ps1      CLI: commands, approval, exit codes
engine/            the engine: Windows PowerShell 5.1, ASCII only, no dependencies
manifests/         10 JSON files, one per module
schema/            manifest.schema.json
policy/            never-touch.json
tools/             validator, static engine checker, generators
tests/             Python tests and shared vectors
docs/              documentation
```

Execution flow:

text

```text
manifests/*.json + policy/never-touch.json
        |   loading: schema, never-touch, audit lint (any error = entire set rejected)
        v
   entry selection (profile, -Only, -Exclude, -OptIn, applicability, gates)
        |
        v
      plan  ---- approval (APPLY or -Yes -PlanId) ---->  apply: journal, change, read-back
        |                                                |
        +--------------------> verify <------------------+
                                  |
                                reports
```

The engine communicates with the system only through a function table called the provider. `Provider.Real.ps1` is the only file that touches the registry, services, tasks, AppX, features, user hives, and the audit runspace. `Provider.Fake.ps1` is an in-memory system: `selftest` runs the same engine code against it and never modifies the machine.

| File | Role |
| --- | --- |
| `Core.ps1` | Shared utilities: logging, state directory and ACL, code fingerprint |
| `Policy.ps1` | Never-touch list and runtime audit linter |
| `Manifest.ps1` | Manifest loading and rechecking of the validator's rules |
| `Provider.ps1` | Boundary between the engine and the system: the function table |
| `Provider.Real.ps1` | The real system (and the audit runspace) |
| `Provider.Fake.ps1` | In-memory system for `selftest`, with fault injection |
| `Journal.ps1` | Append-only HMAC journal and mutex |
| `Plan.ps1` | Builds the plan: reads, changes nothing |
| `Apply.ps1` | Applies the plan entry by entry and creates the restore point |
| `Rollback.ps1` | Restores to a checkpoint |
| `Verify.ps1` | State checks and audits |
| `Report.ps1` | JSON, HTML, CSV, and XCCDF reports |
| `Preflight.ps1` | PF01 through PF09 checks |
| `Drift.ps1` | Drift task installation and execution |
| `SelfTest.ps1` | Engine tests using the fake provider |

## Development and Testing

Python 3 is required (tested with 3.13), along with `jsonschema` and `pytest`. The engine's PowerShell code is not executed in the development environment.

text

```text
pip install -r tools/requirements.txt pytest
python3 -I tools/validate_manifests.py
python3 -I tools/check_engine.py
python3 -I tools/gen_reference.py --check
python3 -I tools/sync_lint_vectors.py --check
python3 -m pytest -q
```

| Tool | What It Checks |
| --- | --- |
| `tools/validate_manifests.py` | Schema, rules R01 through R21, never-touch, and audit lint across all manifests |
| `tools/check_engine.py` | PowerShell code as text: ASCII, 5.1 syntax, bracket balance, calls to nonexistent functions and parameters, variables read without being defined, values leaking to output, and disagreements between provider tables |
| `tools/gen_reference.py` | Generates `docs/REFERENCE.md` from the manifests (`--check` to verify it) |
| `tools/sync_lint_vectors.py` | Ensures the shared audit lint vectors are complete: every audit command in the manifests must be present there (`--check`) |
| `python3 -m pytest` | Runs all of the above as tests. Additionally: tests that deliberately break a valid entry or a copy of the engine and require the checker to catch it, shared vectors, and equivalence between the two linters |

Static checks are a safety net, not proof. The `selftest` on Windows provides evidence for the engine's logic, while `docs/VERIFY-PROTOCOL.md` covers actual system writes.

**Conventions**

- Every behavior change must include the corresponding manifest entry (or its modification) and the test that demonstrates it.
- Engine files: Windows PowerShell 5.1 syntax, ASCII only (5.1 reads scripts without a BOM as ANSI), LF only, no tabs. The code fingerprint is a hash of the file bytes, and `.gitattributes` preserves LF in Windows checkouts.
- Calls to the system must go exclusively through the provider (`Invoke-WhProv 'Name' …`). Every call that may return a collection must be wrapped in `@( )`.
- Code in `SelfTest.ps1`: a false failure there blocks `apply` on every machine (D20), so additions must be made with particular care.
- Every decision made without consulting the owner is recorded in `docs/DECISIONS.md`, together with the reason and how to change it.

**Adding a New Entry**

1. Choose a module and the next available ID. Write the entry with its rationale, impact, sources and evidence grades, and `notes` if it is `unverified`.
2. Write the audit as a single-line, read-only command using single quotes.
3. Run `python3 -I tools/validate_manifests.py`, then `python3 -I tools/sync_lint_vectors.py` and `python3 -I tools/gen_reference.py`.
4. Run `python3 -m pytest -q`. The numbers in this README (totals, profiles, distributions) are maintained manually: update them if the new entry changes them.
5. Test it in a VM using `docs/VERIFY-PROTOCOL.md` before marking it `verified`.

## Troubleshooting

| Symptom | Cause | What to Do |
| --- | --- | --- |
| `Stopped before doing anything. Nothing was changed.` | A preflight check failed | Check the PF code in the Security Model table |
| `Self test FAILED (… checks). The engine will not change this system.` | The engine tests failed on this machine | Run `selftest` for the full list and provide its output together with the code fingerprint. `-SkipSelfTest` is not recommended |
| `The journal failed verification…` | The journal was modified outside the tool or is corrupted | Keep a copy of `%ProgramData%\winharden`. Use `-TrustJournal` only if you are certain nobody has modified it |
| `Another winharden run is in progress on this machine.` | A run is already in progress, possibly the drift task | Wait for it to finish |
| `-Yes needs -PlanId …` | `-PlanId` is missing or does not match the current plan: the system or options have changed | Run `plan` again, review it, and provide the new ID |
| `Nothing to change: …` | All selected entries are already compliant, not applicable, or blocked | Normal behavior. `apply` only runs `verify` and does not create a checkpoint |
| `verify` displays only a few entries | Without `-Profile`, it checks only profile 1 | Run `verify -Profile N`, using the same N as the profile you applied |
| `FAIL` with `Apply skips this entry: …` (e.g. `appx-006`, `appx-007`, `tel-008`) | A gate is closed: `apply` does not touch the entry | Use `-AcceptDataLoss` or `-AllowServicingAdjacent` with both `plan` and `apply`, or accept the FAIL |
| `ERROR` or `FAIL` on `plt-001` through `plt-004` in a VM (e.g. `Cmdlet not supported on this platform`) | These entries are `attest`: they report platform status. The VM may not use UEFI, may lack TPM 2.0, or may not have encryption enabled | VM limitation, not an `apply` failure. These checks are performed on physical hardware |
| `FAIL` on `plt-011` (memory integrity) after the value was written | The value was written, but the feature is not running yet: the result becomes visible after a reboot | Restart and run `verify` again. If it persists, check the entry's `impact`: incompatible drivers or unsupported hardware |
| `FAILED    <entry>: … (reverted)` in `apply` | A step within the entry failed and the entire entry was rolled back | The reason is on the same line and in `logs\winharden.jsonl` |
| Audits marked `skipped` | The command is language-dependent and Windows is not running in English, or the tool is running as SYSTEM | Normal behavior: the entry is evaluated using the state check |

## Security and Vulnerability Reporting

The tool runs as Administrator and modifies the system, so a mistake or vulnerability can have real consequences. `docs/THREAT-MODEL.md` describes what is protected, the risks introduced by the tool itself, and the residual risk.

The project has not yet established a dedicated reporting channel: reports should be sent to the repository owner. For every issue, include:

- The code fingerprint (displayed in the banner of every command except `help`, `list`, and `selftest`, and in every report).
- The Windows build and whether the system was a VM.
- The command output and, if available, the relevant portion of `logs\winharden.jsonl`.

Reports and logs are local files containing machine information, such as the computer name: review them before sending them to third parties. For a vulnerability in the tool itself, e.g. a way to execute unauthorized code as SYSTEM, send the details privately to the owner rather than opening a public issue.

## Documentation

| Document | Contents |
| --- | --- |
| `docs/REFERENCE.md` | Complete table of all entries. Generated from the manifests; do not edit manually |
| `docs/DECISIONS.md` | Decisions D1 through D22 made without consulting the owner, with their rationale and how to change them |
| `docs/THREAT-MODEL.md` | What is protected, risks introduced by the tool itself, and residual risk |
| `docs/VERIFY-PROTOCOL.md` | How to test in a VM and how an entry becomes `verified` |
| `docs/BACKLOG.md` | What was not implemented, what remains open, what was omitted, and why |
| `docs/M4-CATALOG.md` | AppX application catalog and selection rules |

## License and Liability

This project is licensed under the BSD 3-Clause License. See [LICENSE](LICENSE).

**Liability.** The tool modifies system settings as Administrator and provides no guarantee of a particular outcome. Profile 3 changes may break legacy applications and drivers, and some changes (application removal, file cleanup) cannot be fully rolled back. Test it first in a VM with a snapshot and keep a backup of your data.