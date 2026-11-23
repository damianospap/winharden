# winharden

**A policy-driven Windows 11 hardening and debloating tool**

winharden provides a reproducible, auditable, and reversible workflow for reducing telemetry, unwanted applications and attack surface on Windows 11.

It is implemented in Windows PowerShell 5.1 and is designed for Windows 11 Home, build 26200 and later.

> [!IMPORTANT]
> This project is experimental. The engine has been exercised in Windows 11 virtual machines, but it has not been validated across every supported edition, hardware configuration or firmware combination.
>
> Use a virtual machine or disposable Windows installation with a snapshot before using winharden on a production system.

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

---

## Table of contents

- [Overview](#overview)
- [Safety model](#safety-model)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Profiles](#profiles)
- [Command reference](#command-reference)
- [Workflow](#workflow)
- [Manifest model](#manifest-model)
- [Reports](#reports)
- [Rollback and recovery](#rollback-and-recovery)
- [Drift monitoring](#drift-monitoring)
- [State and journal](#state-and-journal)
- [Development](#development)
- [Repository structure](#repository-structure)
- [Limitations](#limitations)
- [Security considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

winharden separates **declaring**, **planning**, **applying**, **verifying** and **rolling back** system changes.

A manifest entry describes:

- A supported profile and risk level
- An expected Windows build or edition
- The operation to apply
- The method used to verify it
- A rollback or reversibility policy
- The rationale, impact and evidence for the change
- Any explicit opt-in or administrative gate required

Operations may include:

- Registry values
- Windows services
- Scheduled tasks
- Provisioned and installed AppX packages
- Optional Windows features
- Defender preferences and attack-surface rules
- Audit policy
- File cleanup

No operation is performed merely by displaying or saving a plan. Applying a plan requires a separate approval step and is journaled before the change is made.

---

## Safety model

winharden uses a defense-in-depth safety model.

### Plan before change

Every apply operation begins with a plan:

- Reads the current system state
- Identifies applicable entries
- Classifies targets as compliant, changeable, skipped or blocked
- Shows before-and-after values
- Reports blocked operations and the reason
- Generates a stable plan identifier

### Explicit approval

Interactive apply requires typing `APPLY`.

Non-interactive apply requires both:

- `-Yes`
- `-PlanId` matching the exact plan identifier

The plan identifier is derived from the manifests, selected entries, plan-level gates and relevant system state.

If a plan changes after review, a new approval is required.

### Runtime policy validation

Before execution, the engine revalidates the complete manifest set:

- Manifest structure
- Operation fields and types
- Registry operation constraints
- Never-touch policies
- Read-only audit command rules
- Service, task, feature and AppX restrictions
- Cleanup allow-lists
- Duplicate entry identifiers
- Servicing-adjacent operation rules

A broken manifest set is rejected as a unit. The engine does not execute a partial manifest set.

### Never-touch protections

The repository contains an explicit `policy/never-touch.json` policy.

It protects:

- Critical services
- Protected registry prefixes and values
- Protected AppX package patterns
- Protected scheduled tasks
- Protected optional features
- Non-approved settings
- Non-approved cleanup locations
- Servicing-adjacent components

The runtime policy check is independent of the manifest and can prevent an entry from applying an operation that is not allowed.

### Write-ahead journal

Before each reversible target is changed, the engine writes its before-state to disk.

The journal is designed to support rollback to a named checkpoint.

A journal-integrity failure:

- Prevents normal journal writes
- Prevents rollback
- Requires `-TrustJournal` to deliberately continue after the failure

This switch exists for recovery scenarios and must not be used automatically or as routine operation.

### Privilege boundaries

State and operational data is stored below `%ProgramData%\winharden`.

The default directory ACL permits writes only by:

- `SYSTEM`
- The local Administrators group

The tool itself requires an elevated Windows PowerShell session for apply, rollback and drift installation.

### Restricted audit commands

Manifest audit commands are constrained to read-only operations.

Native commands are restricted, and audit policy reads are limited to approved `auditpol /get` forms.

Network primitives, redirection, encoded commands, call operators and arbitrary dot-sourcing are not permitted in audit commands.

---

## Requirements

- Windows 11
- Windows 11 build **26200 or later**
- Windows PowerShell **5.1**, 64-bit
- Administrator privileges
- Python 3.10 or later for repository development and validation
- Network access only if required for installing development dependencies

For default apply and verification behavior:

```powershell
powershell.exe -Version
```

The PowerShell executable must be 64-bit:

```powershell
[Environment]::Is64BitProcess
```

The command should return `True`.

---

## Quick start

Open an elevated Windows PowerShell terminal in the repository directory.

### 1. Run the built-in self-test

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 selftest
```

The self-test exercises the engine against an in-memory fake provider. It does not modify Windows.

### 2. Create and inspect a plan

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 plan -Profile 1
```

The plan command:

- Performs no system changes
- Loads and validates all manifests
- Checks platform facts
- Displays every proposed change
- Saves a JSON copy of the plan
- Prints the plan identifier

### 3. Apply the reviewed plan

Interactive:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 apply -Profile 1
```

Non-interactive:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 apply `
  -Profile 1 `
  -Yes `
  -PlanId <plan-id>
```

Use non-interactive approval only after reviewing the plan through a trusted process.

### 4. Verify the result

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 verify
```

### 5. Inspect checkpoints

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 checkpoints
```

### 6. Roll back

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 rollback `
  -To latest
```

Rollback requires approval unless `-Yes` is supplied.

---

## Profiles

Profiles are cumulative. Selecting Profile 2 includes Profile 1 entries. Selecting Profile 3 includes both lower profiles.

| Profile | Name | Purpose |
|---:|---|---|
| 1 | Classic | Baseline telemetry, consumer and debloating changes |
| 2 | Private | Privacy, legacy protocol and attack-surface reductions |
| 3 | Deep | Deep system hardening and broad AppX removal |

Profiles are recommendations, not assurance levels. Individual entries may be skipped or blocked based on:

- Windows build
- Edition
- Hardware
- Existing configuration
- Required administrative gates
- Explicit opt-in selection
- Service, feature or package availability
- Pending reboot state

Use `list` to inspect profile membership:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 list -Profile 3
```

---

## Command reference

### `plan`

Performs a read-only planning operation.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 plan `
  -Profile 2
```

### `apply`

Plans, approves and applies changes.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 apply `
  -Profile 2 `
  -Exclude "privacy-*"
```

### `verify`

Checks selected entries and optionally runs read-only audit commands.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 verify -Profile 3
```

Quick verification skips audit commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 verify -Quick
```

### `rollback`

Restores changes made after a named checkpoint.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 rollback -To latest
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 rollback -To <checkpoint-name>
```

### `checkpoints`

Lists checkpoints and verifies journal integrity.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 checkpoints
```

### `status`

Displays platform facts, preflight findings and drift-task state.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 status
```

### `list`

Lists manifest entries.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 list -Profile 3
```

### `selftest`

Runs the in-memory engine test suite.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 selftest
```

### `install-drift`

Installs a protected SYSTEM scheduled task that verifies configuration drift.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 install-drift -Profile 2
```

### `remove-drift`

Removes the scheduled task.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 remove-drift
```

---

## Selection options

### `-Profile`

Selects cumulative profile 1, 2 or 3.

```powershell
-Profile 2
```

### `-Only`

Includes entries matching one or more wildcard patterns.

```powershell
-Only "telemetry-*","diag-*"
```

### `-Exclude`

Excludes entries matching wildcard patterns.

```powershell
-Exclude "appx-*","cleanup-*"
```

### `-OptIn`

Includes entries that require explicit opt-in.

```powershell
-OptIn no-printing,no-file-sharing
```

Opt-in entries are omitted unless named explicitly.

---

## Administrative gates

Administrative switches must not be used without understanding their consequences.

### `-AcceptDataLoss`

Allows entries marked as deleting user data.

```powershell
-AcceptDataLoss
```

Rollback cannot restore deleted user data.

### `-AllowServicingAdjacent`

Allows Profile 3 entries that affect servicing-adjacent components.

```powershell
-AllowServicingAdjacent
```

These entries are gated because a change may affect Windows updates or servicing.

### `-AllowPlatformGaps`

Allows apply to proceed despite missing Secure Boot or TPM 2.0 checks.

Entries that require the affected hardware remain blocked.

### `-AllowUntestedBuild`

Turns an unsupported Windows build from a blocker into a warning.

### `-AllowOtherEdition`

Turns a non-Home edition warning or blocker into a warning.

### `-IgnorePendingReboot`

Allows execution while Windows reports pending reboot state.

### `-NoRestorePoint`

Prevents best-effort System Restore point creation.

### `-SkipSelfTest`

Skips the pre-apply engine self-test.

This switch is not recommended.

### `-TrustJournal`

Allows continuing after a journal integrity failure.

Use only after independently inspecting the journal and confirming that it was not altered.

---

## Workflow

### 1. Load

The engine loads:

- `policy/never-touch.json`
- `manifests/*.json`
- The platform facts provider
- The real or fake system provider

### 2. Validate

The complete manifest set is validated before the engine executes.

Validation failures stop all selected operations.

### 3. Preflight

Platform facts are compared with the minimum preflight requirements.

A strict apply preflight rejects:

- Non-administrator execution
- 32-bit PowerShell
- Unsupported platform facts
- Unsupported editions or builds, unless explicitly allowed
- Pending reboot state, unless explicitly ignored

### 4. Plan

The engine computes the target state for every selected entry.

Plan entries are classified as:

- `change`: one or more targets differ
- `ok`: all applicable targets already match
- `skip`: not applicable or not present
- `blocked`: cannot be safely changed
- `manual`: requires manual user action
- `attest`: verification only

### 5. Approve

The complete plan and plan identifier must be reviewed.

An approval is valid only for the exact plan captured by the plan hash.

### 6. Apply

The engine:

- Creates a journaled checkpoint
- Records before-state
- Applies reversible operations
- Records applied operations
- Reverts failed operations where possible
- Runs post-change verification
- Writes reports

### 7. Verify

Verification compares current state against the selected manifest entries.

Read-only audit commands may run unless quick verification is requested.

### 8. Recover

The journal can restore reversible changes to a named checkpoint.

Not every operation is reversible:

- AppX removal
- Data deletion
- Cleanup
- Firmware or physical-hardware changes
- Third-party software modifications

---

## Manifest model

Manifest entries are JSON documents in `manifests/`.

Example structure:

```json
{
  "schema_version": 1,
  "entries": [
    {
      "id": "example-entry",
      "module": "example",
      "title": "Example setting",
      "tier": "T0",
      "min_profile": 1,
      "mode": "enforce",
      "risk": "low",
      "rationale": "Reduces the configured attack surface.",
      "impact": "Changes the selected system setting.",
      "apply": [
        {
          "type": "registry",
          "hive": "HKLM",
          "scope": "machine",
          "path": "Software\\Example",
          "name": "ExampleValue",
          "kind": "DWord",
          "data": 1
        }
      ],
      "audit": {
        "checks": []
      },
      "rollback": {
        "reversibility": "full"
      }
    }
  ]
}
```

The actual repository schema should be treated as authoritative:

- `schema/manifest.schema.json`
- `tools/validate_manifests.py`
- `engine/Manifest.ps1`

---

## Entry fields

| Field | Purpose |
|---|---|
| `id` | Stable unique entry identifier |
| `module` | Functional grouping |
| `title` | Human-readable description |
| `tier` | Confidence or evidence tier |
| `min_profile` | Lowest profile containing the entry |
| `mode` | `enforce`, `once`, `attest`, or `manual` |
| `risk` | Low, medium or high |
| `rationale` | Why the change is recommended |
| `impact` | User-visible or system-visible effect |
| `apply` | Operations performed |
| `audit` | Read-only verification commands |
| `rollback` | Reversibility and rollback metadata |
| `flags` | Administrative and risk gates |
| `applicability` | Build and edition requirements |
| `evidence` | Supporting evidence |
| `references` | External references |

---

## Operation types

### Registry

Writes a registry value at a fixed or wildcard-expanded path.

Supported registry types:

- `DWord`
- `QWord`
- `String`
- `ExpandString`
- `MultiString`

### Service

Changes service startup type and optionally stops the service.

Protected, boot, system and unknown startup types are not managed.

### Scheduled task

Disables a scheduled task.

### AppX

Removes an installed or provisioned AppX package.

Removal can require Microsoft Store or source media for reinstallation.

### Optional feature

Disables an optional Windows feature.

### Setting

Changes a provider setting belonging to a controlled allow-list:

- Defender preferences
- Defender ASR rules
- Audit policy

### File cleanup

Deletes matching files older than an approved minimum age.

Cleanup operations are one-time operations and are documented as only partially reversible.

---

## Reports

The verification workflow produces four report formats:

- JSON
- HTML
- POA&M CSV
- XCCDF

By default, reports are written to:

```text
%ProgramData%\winharden\reports\<run-id>
```

Use `-OutDir` to select another location:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\winharden.ps1 verify `
  -OutDir C:\Temp\winharden-reports
```

The report model includes:

- Platform facts
- Manifest fingerprint
- Engine fingerprint
- Selected profile
- Entry status
- Audit result
- Excluded entries
- Plan identifier
- Apply result
- Reboot requirement

A failed or errored verification produces exit code `1`.

---

## Rollback and recovery

### Checkpoints

Every apply run creates a checkpoint in the journal.

```powershell
checkpoints
```

Checkpoints identify:

- Name
- Timestamp
- Profile
- Plan identifier
- Entry count
- User-provided label

### Rollback target

```text
rollback -To latest
rollback -To <checkpoint-name>
rollback -To <checkpoint-guid>
```

The exact accepted checkpoint syntax is defined in `engine/Journal.ps1`.

### Limitations

Rollback can restore journaled state only when:

- The original before-state was captured
- The target still exists and is writable
- The state can be recreated through a supported provider
- Windows did not remove or replace the target in the meantime
- The journal remains intact

Some operations are explicitly marked partial or manual.

The following are not guaranteed to be reversible:

- Data-loss cleanup
- AppX removal
- Third-party package changes
- Changes made outside the tool after application
- Firmware configuration
- Windows servicing operations

A verified journal does not prove that the journaled before-state came from Windows without external modification. Protect the state directory and machine accordingly.

---

## State and journal

Default state directory:

```text
%ProgramData%\winharden
```

Directory layout:

```text
winharden\
├── journal\
├── plans\
├── reports\
└── logs\
```

### ACL protection

New state directories are protected to allow writes only by:

- `SYSTEM`
- Local Administrators

This protection is implemented with well-known Windows security identifiers so it does not depend on localized group names.

### Structured logging

Logs are written as JSON Lines to:

```text
%ProgramData%\winharden\logs\winharden.jsonl
```

A logging failure disables logging for the current process but does not stop the engine.

---

## Drift monitoring

winharden can install a scheduled task that runs:

- At system startup
- Every Sunday at 03:00

The task runs as `SYSTEM` and performs verification.

### Verify-only mode

```powershell
install-drift -Profile 2
```

The installed task verifies configuration and writes reports. It does not apply changes.

### Reapply mode

```powershell
install-drift -Profile 2 -Reapply
```

Reapply mode creates a plan and reapplies drifted reversible settings.

Data-loss entries are never re-applied.

Remove the task with:

```powershell
remove-drift
```

Remove the protected installed copy as well:

```powershell
remove-drift -RemoveFiles
```

---

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Completed successfully |
| `1` | Verification or operation failures completed with errors |
| `2` | Refused by preflight or approval |
| `3` | Internal or integrity error |

---

## Development

The repository is portable for validation on Linux or Windows.

### Install development dependencies

```text
python3 -m pip install jsonschema pytest
```

### Validate manifests

```text
python3 -I tools/validate_manifests.py
```

This validates:

- JSON schema
- Never-touch policy
- Manifest rules R01 through R21
- Audit command lint
- Shared lint vectors

### Run tests

```text
python3 -m pytest -q
```

### Run static engine checks

```text
python3 -I tools/check_engine.py
```

The static checker inspects PowerShell source. It does not execute Windows APIs.

### Generate reference documentation

```text
python3 -I tools/gen_reference.py
```

Check whether documentation is current:

```text
python3 -I tools/gen_reference.py --check
```

### Synchronize audit vectors

```text
python3 -I tools/sync_lint_vectors.py
python3 -I tools/sync_lint_vectors.py --check
```

---

## Development workflow

When a manifest changes, run:

```text
python3 -I tools/validate_manifests.py
python3 -I tools/gen_reference.py
python3 -I tools/sync_lint_vectors.py
python3 -m pytest -q
python3 -I tools/check_engine.py
```

Then run an actual VM test sequence:

1. Snapshot the VM
2. Run `selftest`
3. Run `plan -Profile 1`
4. Apply and verify
5. Roll back to the pre-apply checkpoint
6. Repeat with the required higher profile
7. Repeat for each pending reboot, hardware gap and edition case

---

## Repository structure

```text
.
├── winharden.ps1              Windows entry point
├── engine/                    Engine implementation
├── manifests/                 Policy manifests
├── policy/                    Never-touch and allow-list policy
├── schema/                    JSON manifest schema
├── tools/                     Validators and generators
├── tests/                     Python test suite and lint vectors
└── docs/
    ├── REFERENCE.md           Generated entry reference
    ├── DECISIONS.md           Design decisions
    ├── THREAT-MODEL.md        Threat model
    ├── VERIFY-PROTOCOL.md     VM verification protocol
    ├── BACKLOG.md             Known work and limitations
    └── M4-CATALOG.md          AppX catalog
```

---

## Limitations

winharden is not a Windows security baseline or a replacement for enterprise configuration management.

Known limitations include:

- It is designed primarily for Windows 11 Home
- Windows behavior varies across builds and OEM configurations
- Third-party software may override Defender or network settings
- Provisioned packages may return after upgrades or feature updates
- Registry and service state can change concurrently
- Pending reboot state can prevent immediate verification
- Cleanup operations are intentionally not fully reversible
- AppX removal may require Store or package source access for restoration
- Physical TPM, Secure Boot and virtualization settings cannot be changed
- System Restore points are not a substitute for a journaled rollback
- A VM test does not demonstrate correctness on every physical system
- No single tool can guarantee a safe Windows state or prevent all drift

---

## Security considerations

### Run from a trusted copy

A local copy of the repository should be treated as executable trusted code.

Verify the code fingerprint printed at startup and published in reports.

### Protect administrative machines

A compromised administrative account can modify:

- The engine
- The manifests
- The never-touch policy
- The plans
- The journal
- The drift task
- Stored reports and logs

### Protect state directories

Do not remove ACL protection from `%ProgramData%\winharden` without understanding the implications.

### Review plans manually

Do not approve a plan solely because it has no displayed failures.

Review:

- Entry IDs
- Risk levels
- Before/after values
- Blocked targets
- Reboot requirements
- Data-loss implications
- Servicing-adjacent components

### Use a snapshot

Before applying a new Profile or manifest set:

- Take a full VM or system snapshot
- Export important user data
- Confirm backup and recovery procedures
- Verify Store and recovery access
- Record the Windows build and edition
- Record firmware and hardware settings

---

## Not changed

winharden intentionally leaves protected infrastructure out of scope:

- Windows Update
- Windows servicing stack
- Microsoft Store
- App Installer
- `winget`
- WebView2 Runtime
- Secure Boot certificates
- TPM ownership and configuration
- Core platform boot infrastructure
- Identity and user credentials
- Microsoft account state

Do not interpret absence from this list as proof that a future Windows update will remain compatible.

---

## Contributing

Contributions should include:

- A concise problem statement
- The affected manifest, engine file or provider
- Windows build and edition
- VM or hardware configuration
- Before and after system state
- Reproduction steps
- Relevant journal or report output
- An entry or unit test proving the corrected behavior
- A rollback test when changing apply or restore logic

Do not submit a manifest entry that:

- Uses an unverified operation without evidence
- Targets a never-touch service or registry location
- Uses wildcard AppX names
- Uses arbitrary audit commands
- Deletes user data without an explicit gate
- Touches servicing infrastructure without Profile 3 and the required gate
- Claims a Home behavior that has not been tested on Windows 11 Home

---

## Documentation

- `docs/REFERENCE.md` — generated catalog of entries
- `docs/DECISIONS.md` — design decisions and alternatives
- `docs/THREAT-MODEL.md` — threat model and residual risks
- `docs/VERIFY-PROTOCOL.md` — VM validation protocol
- `docs/BACKLOG.md` — known limitations and future work
- `docs/M4-CATALOG.md` — AppX package catalog
- `LICENSE` — BSD 3-Clause license

---

## License

This project is licensed under the BSD 3-Clause License. See [LICENSE](LICENSE).
