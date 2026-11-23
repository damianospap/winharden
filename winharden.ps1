# winharden - debloat and hardening for Windows 11 Home.
# Windows PowerShell 5.1, run as Administrator:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 <command> [options]
# Nothing is changed until a plan has been shown and approved. Run `help` for the commands.
# ASCII only: Windows PowerShell 5.1 reads a script file without a BOM as ANSI.
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'list', 'plan', 'apply', 'verify', 'rollback', 'checkpoints', 'status', 'selftest', 'drift', 'install-drift', 'remove-drift')]
    [string]$Command = 'help',

    # 1 = classic (what a WinUtil-style tweak list does), 2 = privacy and attack surface, 3 = deep system changes.
    # Each profile contains the lower ones. Named Level because $Profile is a PowerShell automatic variable.
    [Alias('Profile')]
    [ValidateRange(1, 3)]
    [int]$Level = 1,

    [string[]]$Exclude = @(),
    [string[]]$Only = @(),
    [string[]]$OptIn = @(),

    [string]$PlanId = '',
    [switch]$Yes,

    [string]$To = '',
    [switch]$TrustJournal,

    [switch]$AcceptDataLoss,
    [switch]$AllowServicingAdjacent,
    [switch]$AllowPlatformGaps,
    [switch]$AllowUntestedBuild,
    [switch]$AllowOtherEdition,
    [switch]$IgnorePendingReboot,
    [switch]$NoRestorePoint,
    [switch]$SkipSelfTest,

    [switch]$Quick,
    [string]$OutDir = '',
    [switch]$Reapply,
    [switch]$RemoveFiles
)

$ErrorActionPreference = 'Stop'
$script:WhHome = $PSScriptRoot
$script:WhExit = 0
$script:WhSessionOpen = $false

if ([string]::IsNullOrWhiteSpace($script:WhHome)) {
    Write-Host 'winharden must be started as a script file: powershell.exe -File .\winharden.ps1 <command>' -ForegroundColor Red
    exit 2
}

# Dependency order: later files call functions of earlier ones only when they run, so the order matters little, but
# the variables that files initialise at load time (provider tables, constants) must exist before the first call.
try {
    foreach ($part in @('Core', 'Policy', 'Manifest', 'Provider', 'Provider.Real', 'Provider.Fake', 'Journal', 'Plan', 'Apply', 'Rollback', 'Verify', 'Report', 'Preflight', 'Drift', 'SelfTest')) {
        . (Join-Path (Join-Path $script:WhHome 'engine') ($part + '.ps1'))
    }
}
catch {
    Write-Host ('Cannot load the engine: ' + $_.Exception.Message) -ForegroundColor Red
    exit 3
}
$script:WhFingerprint = Get-WhFingerprint -Root $script:WhHome

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function Set-WhExit {
    param([int]$Code)
    $script:WhExit = $Code
}

function ConvertTo-WhPatternList {
    # Accepts 'a,b' and 'a','b': a script started with -File receives a comma list as one string.
    param([string[]]$Values)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Values)) {
        if ($null -eq $v) { continue }
        foreach ($piece in ([string]$v).Split(',')) {
            $t = $piece.Trim()
            if ($t -ne '') { $out.Add($t) }
        }
    }
    return $out.ToArray()
}

function Get-WhPreflightOptions {
    return @{
        allow_untested_build  = [bool]$AllowUntestedBuild
        allow_other_edition   = [bool]$AllowOtherEdition
        ignore_pending_reboot = [bool]$IgnorePendingReboot
        allow_platform_gaps   = [bool]$AllowPlatformGaps
    }
}

function Get-WhGates {
    return [pscustomobject]@{ accept_data_loss = [bool]$AcceptDataLoss; allow_servicing_adjacent = [bool]$AllowServicingAdjacent }
}

function Resolve-WhOutDirectory {
    param([string]$RunId)
    if ($OutDir -ne '') {
        return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
    }
    return (Join-Path (Join-Path (Get-WhStateDir) 'reports') $RunId)
}

function Show-WhBanner {
    Write-WhLine ('winharden ' + $script:WhEngineVersion + '  (code fingerprint ' + $script:WhFingerprint.Substring(0, 16) + ')')
}

function Show-WhHelp {
    $text = @'
winharden - debloat and hardening for Windows 11 Home (Windows PowerShell 5.1, run as Administrator)

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 <command> [options]

Commands
  plan          Dry run: read the system, show exactly what would change and why. Changes nothing.
  apply         Plan, show the plan, ask for approval, apply, verify, write the reports.
  verify        Check the system against the manifests; write JSON, HTML, POA&M CSV and XCCDF reports.
  rollback      Put back everything changed after a checkpoint:  rollback -To <checkpoint|latest>
  checkpoints   List the checkpoints in the journal and verify the journal.
  list          List the manifest entries (use -Profile to filter).
  status        Platform facts, journal state and the drift task.
  selftest      Run the engine's own tests against an in-memory system. Changes nothing.
  install-drift Install a SYSTEM task (weekly and at start-up) that verifies and writes a report.
  remove-drift  Remove that task (add -RemoveFiles to delete its installed copy too).

Options
  -Profile 1|2|3          1 classic, 2 privacy and attack surface, 3 deep system changes. Each includes the lower ones. Default 1.
  -Exclude a*,b           Leave out entries whose id matches (wildcards allowed).
  -Only a*                Select only entries whose id matches.
  -OptIn name             Include entries that need an explicit opt-in (named in the plan).
  -Yes -PlanId <id>       Non-interactive approval of exactly the plan with this id (shown by plan and apply).
  -AcceptDataLoss         Allow entries that delete user data that no rollback can restore. Off by default.
  -AllowServicingAdjacent Allow entries that touch servicing-adjacent components. Off by default.
  -AllowPlatformGaps      Go on without Secure Boot or TPM 2.0; entries that need them stay blocked.
  -AllowUntestedBuild  -AllowOtherEdition  -IgnorePendingReboot   Turn the matching blocker into a warning.
  -NoRestorePoint         Do not try to create a System Restore point before apply.
  -SkipSelfTest           Do not run the self test before apply (not recommended).
  -Quick                  verify: state check only, no audit commands.
  -OutDir <folder>        Write the reports here instead of the state folder.
  -TrustJournal           Go on although journal verification failed (only if you are sure nobody changed it).
  -To <name|latest>       rollback: the checkpoint to go back to.
  -Reapply                install-drift: the task also re-applies drifted settings (never data-loss entries).

Exit codes: 0 ok, 1 finished with failures, 2 refused (preflight or approval), 3 internal or integrity error.
State (journal, plans, reports, logs): %ProgramData%\winharden  (only SYSTEM and Administrators can write there).
'@
    Write-Host $text
}

# ---------------------------------------------------------------------------
# Shared steps
# ---------------------------------------------------------------------------
function Test-WhRunStart {
    # Prints the platform and the preflight findings. Returns the facts, or $null when the run must stop.
    # With -Strict (apply) every blocker stops the run; otherwise only the basics (PF01-PF04: not admin, not 64-bit,
    # not Windows 11 25H2+, not Home), so plan, verify and rollback still work on a machine without Secure Boot.
    param([switch]$Strict)
    $facts = Invoke-WhProv 'Facts'
    Write-WhLine (Format-WhFacts -Facts $facts)
    $pf = Test-WhPreflight -Facts $facts -Options (Get-WhPreflightOptions)
    Write-WhPreflight -Result $pf
    $stop = @($pf.blockers | Where-Object { $Strict -or (@('PF01', 'PF02', 'PF03', 'PF04') -contains $_.code) })
    if ($stop.Count -gt 0) {
        Write-WhLine 'Stopped before doing anything. Nothing was changed.' 'Red'
        Set-WhExit 2
        return $null
    }
    return $facts
}

function Test-WhJournalReady {
    $j = Read-WhJournal
    if ($j.problems.Count -eq 0) { return $true }
    foreach ($p in @($j.problems | Select-Object -First 5)) { Write-WhLine ('  journal: ' + $p) 'Red' }
    if (-not $TrustJournal) {
        Write-WhLine 'The journal failed verification, so the tool will not write to it or roll back from it. Keep a copy of the folder for inspection; use -TrustJournal only if you are sure.' 'Red'
        return $false
    }
    $script:WhJournalTrust = $true
    Write-WhLine 'Continuing because -TrustJournal was given.' 'Yellow'
    return $true
}

function Test-WhSelfTestGate {
    # The engine tests itself against the in-memory system before it is allowed to touch the real one.
    if ($SkipSelfTest) {
        Write-WhLine 'Self test skipped (-SkipSelfTest).' 'Yellow'
        return $true
    }
    $t = Invoke-WhSelfTest -Root $script:WhHome -Quiet
    if ($t.failed -gt 0) {
        Write-WhLine ('Self test FAILED (' + $t.failed + ' of ' + ($t.passed + $t.failed) + ' checks). The engine will not change this system.') 'Red'
        foreach ($f in @($t.failures | Select-Object -First 10)) { Write-WhLine ('  ' + $f.name + ' ' + $f.detail) 'Red' }
        Write-WhLine 'Run `selftest` for the full list. Please report the output with the code fingerprint.' 'Red'
        return $false
    }
    Write-WhLine ('Self test: ' + $t.passed + ' checks passed.')
    return $true
}

function Import-WhContext {
    # Loads the policy and the manifests, re-checks them, selects the entries. $null when the set is broken.
    $policy = Import-WhPolicy -Path (Join-Path (Join-Path $script:WhHome 'policy') 'never-touch.json')
    $m = Import-WhManifests -Directory (Join-Path $script:WhHome 'manifests') -Policy $policy
    if ($m.errors.Count -gt 0) {
        Write-WhLine 'The manifests failed the runtime checks. Nothing is run from a broken set:' 'Red'
        foreach ($e in @($m.errors | Select-Object -First 20)) { Write-WhLine ('  ' + $e) 'Red' }
        if ($m.errors.Count -gt 20) { Write-WhLine ('  ... and ' + ($m.errors.Count - 20) + ' more') 'Red' }
        return $null
    }
    $optIns = @(ConvertTo-WhPatternList -Values $OptIn)
    $known = @($m.entries | ForEach-Object { [string](Get-WhProp -Object $_ -Name 'opt_in' -Default '') } | Where-Object { $_ -ne '' } | Select-Object -Unique)
    foreach ($o in $optIns) {
        if ($known -notcontains $o.ToLowerInvariant()) { Write-WhLine ('Warning: no entry uses the opt-in name ' + $o + '. Known names: ' + ($known -join ', ')) 'Yellow' }
    }
    $sel = Select-WhEntries -Entries $m.entries -Level $Level -Exclude (ConvertTo-WhPatternList -Values $Exclude) -Only (ConvertTo-WhPatternList -Values $Only) -OptIn $optIns
    Write-WhLine ('Manifests: ' + @($m.entries).Count + ' entries in ' + @($m.files.Keys).Count + ' files; profile ' + $Level + ' selects ' + @($sel.selected).Count + ' (' + @($sel.excluded).Count + ' excluded, ' + @($sel.optional).Count + ' need an opt-in).')
    return [pscustomobject]@{ policy = $policy; manifests = $m; selection = $sel; hash = [string]$m.hash }
}

function New-WhRunPlan {
    param($Context, $Facts)
    return (New-WhPlan -Entries $Context.selection.selected -Facts $Facts -Level $Level -Gates (Get-WhGates) -ManifestHash $Context.hash -Excluded $Context.selection.excluded -Optional $Context.selection.optional)
}

function Save-WhPlanFile {
    param($Plan)
    $dir = Join-Path (Get-WhStateDir) 'plans'
    [void](Initialize-WhDirectory -Path $dir -Protect)
    $path = Join-Path $dir ('plan-' + $Plan.id + '.json')
    Export-WhPlan -Plan $Plan -Path $path
    return $path
}

function Complete-WhRun {
    # Verifies the selected entries, writes the four reports, prints the summary and returns the report model.
    param($Context, $Facts, [string]$Kind, [string]$PlanId, $ApplyResult, [string]$RunId, [bool]$RunAudits)
    Invoke-WhProv 'ClearCaches'
    $results = @(Invoke-WhVerify -Entries $Context.selection.selected -Facts $Facts -RunAudits $RunAudits -Gates (Get-WhGates))
    $model = New-WhReportModel -Results $results -Facts $Facts -Level $Level -ManifestHash $Context.hash -Kind $Kind -Excluded $Context.selection.excluded -ApplyResult $ApplyResult -PlanId $PlanId
    $dir = Resolve-WhOutDirectory -RunId $RunId
    [void](Write-WhReports -Model $model -Directory $dir)
    Format-WhVerifySummary -Model $model
    Write-WhLine ('Reports (JSON, HTML, POA&M CSV, XCCDF): ' + $dir)
    return $model
}

function Read-WhApproval {
    param([string]$Word, [string]$Prompt)
    Write-WhLine ''
    Write-WhLine ($Prompt + ' Type ' + $Word + ' and press Enter; anything else cancels.') 'Cyan'
    $answer = $null
    try { $answer = Read-Host 'Approve' }
    catch {
        Write-WhLog -Level 'info' -EventName 'approval-unavailable' -Data $_.Exception.Message
        return $false
    }
    if ($null -eq $answer) { return $false }
    return ([string]$answer).Trim().Equals($Word, [System.StringComparison]::Ordinal)
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
function Invoke-WhCmdSelfTest {
    $t = Invoke-WhSelfTest -Root $script:WhHome
    Write-WhLine ('Self test: ' + $t.passed + ' passed, ' + $t.failed + ' failed.')
    if ($t.failed -gt 0) { Set-WhExit 1 }
}

function Invoke-WhCmdList {
    $policy = Import-WhPolicy -Path (Join-Path (Join-Path $script:WhHome 'policy') 'never-touch.json')
    $m = Import-WhManifests -Directory (Join-Path $script:WhHome 'manifests') -Policy $policy
    if ($m.errors.Count -gt 0) {
        foreach ($e in @($m.errors | Select-Object -First 20)) { Write-WhLine ('  ' + $e) 'Red' }
        Set-WhExit 3
        return
    }
    $sel = Select-WhEntries -Entries $m.entries -Level $Level -Exclude @() -Only (ConvertTo-WhPatternList -Values $Only)
    $rows = @($sel.selected) + @($sel.optional)
    foreach ($e in @($rows | Sort-Object -Property @{ Expression = { [string]$_.id } })) {
        $gate = [string](Get-WhProp -Object $e -Name 'opt_in' -Default '')
        $mark = ''
        if ($gate -ne '') { $mark = ' [opt-in ' + $gate + ']' }
        Write-WhLine (('{0,-44} p{1} {2,-2} {3,-7} {4,-6} {5,-10} {6}{7}' -f $e.id, $e.min_profile, $e.tier, $e.mode, $e.risk, $e.home_effective, $e.title, $mark))
    }
    Write-WhLine ('')
    Write-WhLine ('Profile ' + $Level + ': ' + $rows.Count + ' of ' + @($m.entries).Count + ' entries.')
}

function Invoke-WhCmdPlan {
    $facts = Test-WhRunStart
    if ($null -eq $facts) { return }
    $ctx = Import-WhContext
    if ($null -eq $ctx) { Set-WhExit 3; return }
    [void](Initialize-WhStateDirectory)
    Enter-WhLock
    $plan = New-WhRunPlan -Context $ctx -Facts $facts
    Write-WhLine ''
    Format-WhPlan -Plan $plan
    $file = Save-WhPlanFile -Plan $plan
    Write-WhLine ''
    Write-WhLine ('Plan saved: ' + $file)
    $summary = Get-WhPlanSummary -Plan $plan
    if ($summary.entries_change -gt 0) {
        Write-WhLine ('To apply exactly this plan: apply -Profile ' + $Level + ' -Yes -PlanId ' + $plan.id + '   (or run apply and approve it interactively)')
    }
}

function Invoke-WhCmdApply {
    $facts = Test-WhRunStart -Strict
    if ($null -eq $facts) { return }
    if (-not (Test-WhJournalReady)) { Set-WhExit 3; return }
    if (-not (Test-WhSelfTestGate)) { Set-WhExit 3; return }
    $ctx = Import-WhContext
    if ($null -eq $ctx) { Set-WhExit 3; return }
    [void](Initialize-WhStateDirectory)
    Enter-WhLock
    $plan = New-WhRunPlan -Context $ctx -Facts $facts
    Write-WhLine ''
    Format-WhPlan -Plan $plan
    $planFile = Save-WhPlanFile -Plan $plan
    $summary = Get-WhPlanSummary -Plan $plan
    $run = New-WhRunId
    $applyResult = $null
    if ($summary.entries_change -eq 0) {
        Write-WhLine ''
        Write-WhLine 'Nothing to change: every selected entry is already compliant, not applicable or blocked. Verifying only.'
    }
    else {
        $high = @(@($plan.entries) | Where-Object { ($_.status -eq 'change') -and ($_.risk -eq 'high') }).Count
        Write-WhLine ''
        Write-WhLine ('Plan ' + $plan.id + ' saved to ' + $planFile)
        if ($high -gt 0) { Write-WhLine ([string]$high + ' entries in this plan have risk "high". Read them above before you approve.') 'Yellow' }
        if ($summary.reboot) { Write-WhLine 'Some changes need a restart to take effect.' }
        Write-WhLine 'Every change is journaled first. Undo later with: rollback -To latest   (AppX removals can only be reinstalled from the Microsoft Store).'
        $approved = $false
        if ($Yes) {
            if ([string]::Equals($PlanId, [string]$plan.id, [System.StringComparison]::OrdinalIgnoreCase)) { $approved = $true }
            else {
                Write-WhLine ('-Yes needs -PlanId ' + $plan.id + ', the id of the plan you reviewed. Nothing was changed.') 'Yellow'
                Set-WhExit 2
                return
            }
        }
        else {
            $approved = Read-WhApproval -Word 'APPLY' -Prompt ('Apply plan ' + $plan.id + '?')
        }
        if (-not $approved) {
            Write-WhLine 'Not approved. Nothing was changed.'
            Set-WhExit 2
            return
        }
        $restore = $null
        if (-not $NoRestorePoint) {
            Write-WhLine 'Creating a System Restore point (best effort; the journal is the real rollback)...'
            $restore = New-WhRestorePoint -Description ('winharden before plan ' + $plan.id)
            Write-WhLine ('  restore point: ' + $restore.message)
        }
        Write-WhLog -Level 'info' -EventName 'apply-start' -Data ([ordered]@{ plan = $plan.id; level = $Level; fingerprint = $script:WhFingerprint })
        $applyResult = Invoke-WhApply -Plan $plan -RunId $run -Label ('profile ' + $Level) -RestorePoint $restore
        Write-WhLog -Level 'info' -EventName 'apply-end' -Data ([ordered]@{ plan = $plan.id; applied = $applyResult.applied; failed = $applyResult.failed })
        Write-WhLine ''
        Write-WhLine ('Applied ' + $applyResult.applied + ' entries, ' + $applyResult.failed + ' failed and were reverted. Checkpoint: ' + $applyResult.checkpoint)
        foreach ($r in @($applyResult.results)) {
            foreach ($man in @($r.manual)) { Write-WhLine ('  manual step: ' + $man) 'Yellow' }
        }
    }
    $model = Complete-WhRun -Context $ctx -Facts $facts -Kind 'apply' -PlanId ([string]$plan.id) -ApplyResult $applyResult -RunId $run -RunAudits $true
    if (($null -ne $applyResult) -and ($applyResult.failed -gt 0)) { Set-WhExit 1 }
    if (($model.summary.fail + $model.summary.error) -gt 0) { Set-WhExit 1 }
    if (($null -ne $applyResult) -and $summary.reboot) { Write-WhLine 'Restart Windows now to finish applying the changes.' 'Cyan' }
}

function Invoke-WhCmdVerify {
    $facts = Test-WhRunStart
    if ($null -eq $facts) { return }
    $ctx = Import-WhContext
    if ($null -eq $ctx) { Set-WhExit 3; return }
    [void](Initialize-WhStateDirectory)
    Enter-WhLock
    $run = New-WhRunId
    $model = Complete-WhRun -Context $ctx -Facts $facts -Kind 'verify' -PlanId '' -ApplyResult $null -RunId $run -RunAudits (-not $Quick)
    if (($model.summary.fail + $model.summary.error) -gt 0) { Set-WhExit 1 }
}

function Invoke-WhCmdCheckpoints {
    $j = Read-WhJournal
    if (@($j.records).Count -eq 0) {
        Write-WhLine 'The journal is empty: this tool has not applied anything on this machine.'
        return
    }
    if ($j.problems.Count -gt 0) {
        Write-WhLine 'The journal FAILED verification:' 'Red'
        foreach ($p in @($j.problems | Select-Object -First 10)) { Write-WhLine ('  ' + $p) 'Red' }
        Set-WhExit 3
    }
    else { Write-WhLine ('Journal verified: ' + @($j.records).Count + ' records, chain intact.') 'Green' }
    foreach ($c in @(Get-WhCheckpoints -Journal $j)) {
        $d = $c.data
        Write-WhLine (('{0,-28} {1}  profile {2}  plan {3}  {4} entries  {5}' -f $d.name, $c.ts, $d.level, $d.plan, $d.entries, $d.label))
    }
}

function Invoke-WhCmdRollback {
    if ($To -eq '') {
        Write-WhLine 'rollback needs a target: -To <checkpoint name|latest>. See `checkpoints`.' 'Yellow'
        Set-WhExit 2
        return
    }
    $facts = Test-WhRunStart
    if ($null -eq $facts) { return }
    if (-not (Test-WhJournalReady)) { Set-WhExit 3; return }
    $j = Read-WhJournal
    $cp = Resolve-WhCheckpoint -Journal $j -Name $To
    $cpSeq = [int]$cp.seq
    $count = @(@($j.records) | Where-Object { ([string]$_.type -eq 'before') -and ([int]$_.seq -gt $cpSeq) }).Count
    Write-WhLine ('Checkpoint ' + $cp.data.name + ' (' + $cp.ts + ', ' + $cp.data.label + '): ' + $count + ' journaled changes were made after it.')
    if ($count -eq 0) {
        Write-WhLine 'Nothing to roll back.'
        return
    }
    if (-not $Yes) {
        if (-not (Read-WhApproval -Word 'ROLLBACK' -Prompt ('Put back the state of ' + $cp.data.name + '?'))) {
            Write-WhLine 'Not approved. Nothing was changed.'
            Set-WhExit 2
            return
        }
    }
    Enter-WhLock
    $run = New-WhRunId
    $r = Invoke-WhRollback -Checkpoint ([string]$cp.data.name) -RunId $run -TrustJournal:$TrustJournal
    Write-WhLine ''
    Write-WhLine ('Restored ' + $r.restored + ' targets to the state of ' + $r.checkpoint + '.')
    foreach ($m in @($r.manual)) { Write-WhLine ('  manual step: ' + $m) 'Yellow' }
    foreach ($f in @($r.failed)) { Write-WhLine ('  FAILED: ' + $f) 'Red' }
    foreach ($m in @($r.mismatch)) { Write-WhLine ('  state differs after restore: ' + $m) 'Red' }
    if (-not $r.ok) { Set-WhExit 1 }
}

function Invoke-WhCmdStatus {
    $facts = Invoke-WhProv 'Facts'
    Write-WhLine (Format-WhFacts -Facts $facts)
    $pf = Test-WhPreflight -Facts $facts -Options (Get-WhPreflightOptions)
    Write-WhPreflight -Result $pf
    if ($pf.ok) { Write-WhLine 'Preflight: ready to apply.' 'Green' }
    else { Write-WhLine 'Preflight: apply would be refused (see above).' 'Yellow' }
    $j = Read-WhJournal
    Write-WhLine ('Journal: ' + @($j.records).Count + ' records, ' + @(Get-WhCheckpoints -Journal $j).Count + ' checkpoints, ' + $j.problems.Count + ' problems.')
    $task = Get-ScheduledTask -TaskPath $script:WhDriftTaskPath -TaskName $script:WhDriftTaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { Write-WhLine 'Drift task: not installed.' }
    else { Write-WhLine ('Drift task: installed (' + [string]@($task)[0].State + ').') }
    $last = Read-WhDriftState
    if ($null -ne $last) { Write-WhLine ('Last drift run: ' + $last.last_run + ', build ' + $last.build + '.' + $last.ubr + ', failing entries: ' + @($last.failing).Count) }
}

function Invoke-WhCmdDrift {
    # Started by the scheduled task. Verify only, unless the task was installed with -Reapply.
    $facts = Test-WhRunStart
    if ($null -eq $facts) { return }
    if (-not (Test-WhSelfTestGate)) { Set-WhExit 3; return }
    $ctx = Import-WhContext
    if ($null -eq $ctx) { Set-WhExit 3; return }
    [void](Initialize-WhStateDirectory)
    Enter-WhLock
    $run = New-WhRunId
    $previous = Read-WhDriftState
    Write-WhLine (Get-WhDriftNote -Previous $previous -Facts $facts)
    $applyResult = $null
    $planId = ''
    if ($Reapply) {
        if (-not (Test-WhJournalReady)) { Set-WhExit 3; return }
        $plan = New-WhRunPlan -Context $ctx -Facts $facts
        $planId = [string]$plan.id
        $summary = Get-WhPlanSummary -Plan $plan
        Format-WhPlan -Plan $plan
        if ($summary.entries_change -gt 0) {
            Write-WhLog -Level 'info' -EventName 'drift-reapply' -Data ([ordered]@{ plan = $plan.id; entries = $summary.entries_change })
            $applyResult = Invoke-WhApply -Plan $plan -RunId $run -Label 'drift reapply' -RestorePoint $null
            Write-WhLine ('Re-applied ' + $applyResult.applied + ' entries, ' + $applyResult.failed + ' failed and were reverted.')
        }
    }
    $model = Complete-WhRun -Context $ctx -Facts $facts -Kind 'drift' -PlanId $planId -ApplyResult $applyResult -RunId $run -RunAudits $true
    $failing = @(@($model.entries) | Where-Object { @('fail', 'error') -contains [string]$_.status } | ForEach-Object { [string]$_.id })
    Save-WhDriftState -Facts $facts -Counts $model.summary -FailingIds $failing
    Write-WhLog -Level 'info' -EventName 'drift-run' -Data ([ordered]@{ failing = $failing.Count; summary = $model.summary })
    if ($failing.Count -gt 0) { Set-WhExit 1 }
}

function Invoke-WhCmdInstallDrift {
    $facts = Test-WhRunStart
    if ($null -eq $facts) { return }
    if (-not (Test-WhSelfTestGate)) { Set-WhExit 3; return }
    $ctx = Import-WhContext
    if ($null -eq $ctx) { Set-WhExit 3; return }
    [void](Initialize-WhStateDirectory)
    Enter-WhLock
    $r = Install-WhDrift -SourceRoot $script:WhHome -Level $Level -Exclude (ConvertTo-WhPatternList -Values $Exclude) -OptIn (ConvertTo-WhPatternList -Values $OptIn) -Reapply ([bool]$Reapply) -AllowServicing ([bool]$AllowServicingAdjacent)
    Write-WhLine ('Installed a protected copy in ' + $r.directory)
    Write-WhLine ('Scheduled task ' + $r.task + ' runs as SYSTEM every Sunday at 03:00 and at every start-up.')
    Write-WhLine ('  arguments: ' + $r.arguments)
    if ($Reapply) { Write-WhLine 'It will also re-apply drifted settings (never entries that delete user data).' 'Yellow' }
    else { Write-WhLine 'It only verifies and writes a report; it changes nothing.' }
}

function Invoke-WhCmdRemoveDrift {
    $facts = Test-WhRunStart
    if ($null -eq $facts) { return }
    Enter-WhLock
    $r = Uninstall-WhDrift -RemoveFiles ([bool]$RemoveFiles)
    Write-WhLine ('Task removed: ' + $r.task_removed + '. Installed copy removed: ' + $r.files_removed + '.')
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
try {
    if (@('help', 'selftest', 'list') -notcontains $Command) { Show-WhBanner }
    switch ($Command) {
        'help' { Show-WhHelp }
        'selftest' { Invoke-WhCmdSelfTest }
        'list' { Invoke-WhCmdList }
        default {
            Invoke-WhProv 'SessionStart'
            $script:WhSessionOpen = $true
            switch ($Command) {
                'plan' { Invoke-WhCmdPlan }
                'apply' { Invoke-WhCmdApply }
                'verify' { Invoke-WhCmdVerify }
                'rollback' { Invoke-WhCmdRollback }
                'checkpoints' { Invoke-WhCmdCheckpoints }
                'status' { Invoke-WhCmdStatus }
                'drift' { Invoke-WhCmdDrift }
                'install-drift' { Invoke-WhCmdInstallDrift }
                'remove-drift' { Invoke-WhCmdRemoveDrift }
            }
        }
    }
}
catch {
    Write-WhLine ('ERROR: ' + $_.Exception.Message) 'Red'
    Write-WhLine ('  at line ' + $_.InvocationInfo.ScriptLineNumber + ' of ' + (Split-Path -Leaf ([string]$_.InvocationInfo.ScriptName))) 'Red'
    Write-WhLog -Level 'error' -EventName 'fatal' -Data ([ordered]@{ message = $_.Exception.Message; line = $_.InvocationInfo.ScriptLineNumber; fingerprint = $script:WhFingerprint })
    Set-WhExit 3
}
finally {
    if ($script:WhSessionOpen) {
        try { Invoke-WhProv 'SessionStop' }
        catch { Write-WhLog -Level 'warn' -EventName 'session-stop' -Data $_.Exception.Message }
    }
    Exit-WhLock
}
exit $script:WhExit
