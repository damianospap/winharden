# winharden engine: Verify.ps1
# Two independent checks per entry:
#   1. state check: the engine reads every target (all user profiles for scope=user) and compares it with the manifest;
#   2. audit checks: the manifest's own read-only commands, linted and run in a ConstrainedLanguage runspace
#      (a command that needs a CIM-based module such as Defender is run again in a FullLanguage runspace, see D21).
# Status per entry: pass | fail | error | na | manual. An audit that cannot run is an error, never a pass.
# The comparison is with the manifest whatever the gates say. A failing entry that apply skips because a gate is closed
# (-AcceptDataLoss, -AllowServicingAdjacent) stays a fail and says so in its reason (D22).
# Windows PowerShell 5.1, ASCII only.

function Test-WhAuditCheck {
    param([string]$Command, [string]$Expected, $Facts, [bool]$LocaleDependent = $false)
    if ($LocaleDependent -and ([string](Get-WhProp -Object $Facts -Name 'ui_language' -Default 'en') -ne 'en')) {
        return [pscustomobject]@{ status = 'skipped'; actual = ''; expected = $Expected; command = $Command; reason = 'The command prints text that Windows translates, and this system does not display English, so the text cannot be compared. The state check covers the same setting.' }
    }
    if ([bool](Get-WhProp -Object $Facts -Name 'is_system' -Default $false) -and $Command.Contains('HKCU:')) {
        return [pscustomobject]@{ status = 'skipped'; actual = ''; expected = $Expected; command = $Command; reason = 'HKCU is the SYSTEM profile when the tool runs as SYSTEM, so this command says nothing about the users. The state check covers every profile.' }
    }
    try {
        $actual = [string](Invoke-WhProv 'Audit' $Command)
        if ($actual -ieq $Expected) {
            return [pscustomobject]@{ status = 'pass'; actual = $actual; expected = $Expected; command = $Command; reason = '' }
        }
        return [pscustomobject]@{ status = 'fail'; actual = $actual; expected = $Expected; command = $Command; reason = ('Expected ' + $Expected + ' but the command returned ' + $actual + '.') }
    }
    catch {
        return [pscustomobject]@{ status = 'error'; actual = ''; expected = $Expected; command = $Command; reason = ('The audit command could not run: ' + $_.Exception.Message) }
    }
}

function New-WhEntryResult {
    param($Entry, [string]$Status, [string]$Reason)
    return [ordered]@{
        id             = [string]$Entry.id
        title          = [string]$Entry.title
        module         = [string]$Entry.module
        mode           = [string]$Entry.mode
        tier           = [string]$Entry.tier
        min_profile    = [int]$Entry.min_profile
        risk           = [string]$Entry.risk
        home_effective = [string]$Entry.home_effective
        status         = $Status
        reason         = $Reason
        state_checks   = @()
        audit_checks   = @()
        manual_check   = [string](Get-WhProp -Object $Entry.audit -Name 'manual_check' -Default '')
        manual_steps   = @(Get-WhProp -Object $Entry -Name 'manual_steps' -Default @())
        rationale      = [string]$Entry.rationale
        impact         = [string]$Entry.impact
        evidence       = @(@($Entry.evidence) | ForEach-Object { [string]$_.grade })
        references     = @(@($Entry.references) | ForEach-Object { [string]$_.url })
    }
}

function Test-WhEntry {
    param($Entry, $Facts, [bool]$RunAudits = $true, $Gates = $null)
    $mode = [string]$Entry.mode
    if ($mode -eq 'manual') {
        return (New-WhEntryResult -Entry $Entry -Status 'manual' -Reason 'Needs a person: the tool does not change or check this setting. See manual_check.')
    }
    $gate = Get-WhEntryGate -Entry $Entry -Facts $Facts -Gates ([pscustomobject]@{ accept_data_loss = $true; allow_servicing_adjacent = $true })
    if ($null -ne $gate) {
        return (New-WhEntryResult -Entry $Entry -Status 'na' -Reason ([string]$gate.reason))
    }
    $result = New-WhEntryResult -Entry $Entry -Status 'pass' -Reason ''
    $stateChecks = New-Object System.Collections.Generic.List[object]
    $reasons = New-Object System.Collections.Generic.List[string]
    $failed = $false
    $errored = $false
    $present = $false
    if ($mode -eq 'enforce') {
        foreach ($op in @($Entry.apply)) {
            foreach ($slot in @(Get-WhOpSlots -Op $op)) {
                $detail = ''
                $status = 'ok'
                try {
                    $state = Read-WhSlotState -Slot $slot
                    $verdict = Get-WhSlotVerdict -Op $op -State $state
                    $status = [string]$verdict.status
                    $detail = (Format-WhState -Type ([string]$op.type) -State $state) + ' (wanted: ' + [string]$verdict.desired + ')'
                    if ($verdict.reason -ne '') { $detail = $detail + ' ' + $verdict.reason }
                }
                catch {
                    $status = 'blocked'
                    $detail = 'Cannot read the state: ' + $_.Exception.Message
                }
                $stateChecks.Add([ordered]@{ label = [string]$slot.label; status = $status; detail = $detail })
                if ($status -ne 'skip') { $present = $true }
                if ($status -eq 'change') { $failed = $true; $reasons.Add($slot.label + ' is not in the desired state.') }
                if ($status -eq 'blocked') { $errored = $true; $reasons.Add($slot.label + ': ' + $detail) }
            }
        }
        if (-not $present) {
            $result['state_checks'] = $stateChecks.ToArray()
            $result['status'] = 'na'
            $result['reason'] = 'None of the targets exists on this system, so there is nothing to enforce.'
            return $result
        }
    }
    $auditChecks = New-Object System.Collections.Generic.List[object]
    if ($RunAudits) {
        foreach ($check in @($Entry.audit.checks)) {
            $a = Test-WhAuditCheck -Command ([string]$check.command) -Expected ([string]$check.expected) -Facts $Facts -LocaleDependent ([bool](Get-WhProp -Object $check -Name 'locale_dependent' -Default $false))
            $auditChecks.Add([ordered]@{ status = $a.status; actual = $a.actual; expected = $a.expected; command = $a.command; reason = $a.reason })
            if ($a.status -eq 'fail') { $failed = $true; $reasons.Add($a.reason) }
            if ($a.status -eq 'error') { $errored = $true; $reasons.Add($a.reason) }
        }
    }
    $result['state_checks'] = $stateChecks.ToArray()
    $result['audit_checks'] = $auditChecks.ToArray()
    if ($errored) { $result['status'] = 'error' }
    elseif ($failed) { $result['status'] = 'fail' }
    $result['reason'] = ($reasons.ToArray() -join ' ')
    if (($result['status'] -eq 'fail') -and ($null -ne $Gates)) {
        # The platform gates returned above, so only the caller's gates (data loss, servicing) can still keep apply away.
        $closed = Get-WhEntryGate -Entry $Entry -Facts $Facts -Gates $Gates
        if ($null -ne $closed) { $result['reason'] = $result['reason'] + ' Apply skips this entry: ' + [string]$closed.reason }
    }
    return $result
}

function Invoke-WhVerify {
    param($Entries, $Facts, [bool]$RunAudits = $true, $Gates = $null)
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Entries)) {
        # A one-time action (mode once) leaves no state to check; the apply summary says what it did.
        if ([string]$e.mode -eq 'once') { continue }
        $results.Add((Test-WhEntry -Entry $e -Facts $Facts -RunAudits $RunAudits -Gates $Gates))
    }
    return $results.ToArray()
}

function Get-WhResultCounts {
    param($Results)
    $c = [ordered]@{ pass = 0; fail = 0; error = 0; na = 0; manual = 0 }
    foreach ($r in @($Results)) { $c[[string]$r.status] = [int]$c[[string]$r.status] + 1 }
    return $c
}
