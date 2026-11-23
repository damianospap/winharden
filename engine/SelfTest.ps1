# winharden engine: SelfTest.ps1
# `winharden.ps1 selftest` runs the engine against the in-memory fake provider and a temporary state folder. It changes
# nothing on the machine. `apply` runs it first and refuses to continue if any test fails. It also reads the shared test
# vectors (tests/vectors/*.json) that the Python tests check against the Python implementation of the same rules.
# Windows PowerShell 5.1, ASCII only.

$script:WhRoot = $null
$script:WhTestLog = $null
$script:WhTestTemp = $null
$script:WhTestSeq = 0
$script:WhTestCurrent = ''
$script:WhTestQuiet = $false

function Write-WhTestLine {
    # The harness's own lines. While the cases run, Write-WhLine is switched off (WhQuiet): a case that makes the engine
    # fail on purpose would otherwise print engine lines such as "FAILED ... (reverted)" that look like a failed test.
    param([string]$Text = '', [string]$Color = '')
    if ($script:WhTestQuiet) { return }
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

function Add-WhTestResult {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    # The log keeps the name of the test with the check, so a failure that is reported alone (the apply gate) says where it is.
    $label = $Name
    if ($script:WhTestCurrent -ne '') { $label = $script:WhTestCurrent + ': ' + $Name }
    $script:WhTestLog.Add([pscustomobject]@{ name = $label; ok = $Ok; detail = $Detail })
    if (-not $Ok) { Write-WhTestLine ('        FAILED: ' + $Name + ' ' + $Detail) 'Red' }
}

function Assert-WhTrue {
    param($Condition, [string]$Name, [string]$Detail = '')
    Add-WhTestResult -Name $Name -Ok ([bool]$Condition) -Detail $Detail
}

function Assert-WhEqual {
    param($Actual, $Expected, [string]$Name)
    $ok = ([string]$Actual -ceq [string]$Expected)
    Add-WhTestResult -Name $Name -Ok $ok -Detail ('expected [' + [string]$Expected + '] actual [' + [string]$Actual + ']')
}

function New-WhTestWorld {
    $script:WhTestSeq = $script:WhTestSeq + 1
    $dir = Join-Path $script:WhTestTemp ([string]$script:WhTestSeq)
    [void](New-Item -ItemType Directory -Path $dir -Force)
    $script:WhStateDir = $dir
    Reset-WhFake
    Reset-WhJournalCache
}

function Invoke-WhTest {
    param([string]$Name, [scriptblock]$Block)
    New-WhTestWorld
    $script:WhTestCurrent = $Name
    $before = $script:WhTestLog.Count
    try { [void](& $Block) }
    catch {
        $where = [System.IO.Path]::GetFileName([string]$_.InvocationInfo.ScriptName) + ':' + $_.InvocationInfo.ScriptLineNumber
        Add-WhTestResult -Name 'unexpected error' -Ok $false -Detail ($_.Exception.Message + ' (' + $where + ')')
    }
    $bad = 0
    for ($n = $before; $n -lt $script:WhTestLog.Count; $n++) { if (-not $script:WhTestLog[$n].ok) { $bad++ } }
    if ($bad -eq 0) { Write-WhTestLine ('  ok    ' + $Name) 'Green' } else { Write-WhTestLine ('  FAIL  ' + $Name) 'Red' }
    $script:WhTestCurrent = ''
}

# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
function New-WhTestEntry {
    param([string]$Id, $Ops, $Extra = $null)
    $e = [ordered]@{
        id             = $Id
        module         = 'm0-selftest'
        title          = ('Selftest entry ' + $Id)
        tier           = 'T1'
        min_profile    = 1
        mode           = 'enforce'
        home_effective = 'expected'
        channel_class  = 'cmdlet'
        rationale      = 'A synthetic entry that exists only in the self test.'
        impact         = 'None: it only exists in memory.'
        risk           = 'low'
        audit          = [ordered]@{ checks = @([ordered]@{ command = "Get-Service -Name 'WhTestSvc'"; expected = 'x' }) }
        rollback       = [ordered]@{ strategy = 'journal'; reversibility = 'full' }
        references     = @([ordered]@{ title = 'selftest'; url = 'https://example.org/selftest' })
        evidence       = @([ordered]@{ grade = 'background'; source = 'selftest'; claim = 'A synthetic claim for the self test.' })
        apply          = @($Ops)
    }
    if ($null -ne $Extra) { foreach ($k in @($Extra.Keys)) { $e[$k] = $Extra[$k] } }
    return (ConvertFrom-WhJson -Text (ConvertTo-WhJson -Object $e -Depth 10))
}

function New-WhTestRegOp {
    param([string]$Path, [string]$Name, $Data = 1, [string]$Scope = 'machine', [string]$Kind = 'DWord')
    $hive = 'HKLM'
    if ($Scope -eq 'user') { $hive = 'HKCU' }
    return [ordered]@{ type = 'registry'; hive = $hive; path = $Path; name = $Name; kind = $Kind; data = $Data; scope = $Scope }
}

function Get-WhTestGates {
    param([bool]$DataLoss = $false, [bool]$Servicing = $false)
    return [pscustomobject]@{ accept_data_loss = $DataLoss; allow_servicing_adjacent = $Servicing }
}

function Invoke-WhTestApply {
    param($Entries, $Gates = $null)
    if ($null -eq $Gates) { $Gates = Get-WhTestGates }
    $facts = Invoke-WhProv 'Facts'
    $plan = New-WhPlan -Entries @($Entries) -Facts $facts -Level 3 -Gates $Gates -ManifestHash 'selftest' -Excluded @()
    $run = New-WhRunId
    $result = Invoke-WhApply -Plan $plan -RunId $run -Label 'selftest' -RestorePoint $null
    return [pscustomobject]@{ plan = $plan; result = $result; run = $run }
}

function Get-WhFakeSnapshot {
    $o = [ordered]@{}
    foreach ($name in @('reg', 'keys', 'services', 'tasks', 'features', 'settings', 'dirs')) {
        $h = $script:WhFake[$name]
        $items = [ordered]@{}
        foreach ($k in @($h.Keys)) { $items[[string]$k] = $h[$k] }
        $o[$name] = $items
    }
    return (ConvertTo-WhCanonical -Value $o)
}

function Read-WhVectors {
    param([string]$Name)
    $path = Join-Path (Join-Path (Join-Path $script:WhRoot 'tests') 'vectors') $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Test vectors are missing: ' + $path) }
    # Windows PowerShell 5.1 hands back a top-level JSON array as one object and PowerShell 7 enumerates it: flatten both.
    $parsed = ConvertFrom-WhJson -Text (Read-WhFile -Path $path)
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $parsed) {
        if ($item -is [System.Array]) { foreach ($inner in $item) { $list.Add($inner) } }
        else { $list.Add($item) }
    }
    return $list.ToArray()
}

# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------
function Invoke-WhSelfTestCases {
    $policy = Import-WhPolicy -Path (Join-Path (Join-Path $script:WhRoot 'policy') 'never-touch.json')

    Invoke-WhTest 'audit lint agrees with the shared vectors' {
        foreach ($v in @(Read-WhVectors -Name 'audit-lint.json')) {
            $reasons = @(Get-WhAuditLintReasons -Command ([string]$v.command))
            Assert-WhEqual ($reasons.Count -eq 0) ([bool]$v.ok) ('lint: ' + [string]$v.name + ' / ' + [string]$v.command)
        }
    }

    Invoke-WhTest 'never-touch policy agrees with the shared vectors' {
        foreach ($v in @(Read-WhVectors -Name 'never-touch.json')) {
            $found = @(Get-WhOpViolations -Op $v.op -Policy $policy)
            Assert-WhEqual ($found.Count -gt 0) ([bool]$v.blocked) ('never-touch: ' + [string]$v.name)
            Assert-WhEqual (Test-WhServicingAdjacent -Op $v.op -Policy $policy) ([bool]$v.servicing_adjacent) ('servicing-adjacent: ' + [string]$v.name)
        }
    }

    Invoke-WhTest 'the shipped manifests load and pass the runtime checks' {
        $m = Import-WhManifests -Directory (Join-Path $script:WhRoot 'manifests') -Policy $policy
        Assert-WhEqual $m.errors.Count 0 ('manifest problems: ' + ($m.errors -join ' | '))
        Assert-WhTrue ($m.entries.Count -gt 0) 'there are entries'
        Assert-WhEqual $m.hash.Length 64 'manifest hash is a SHA-256'
        $recall = @($m.entries | Where-Object { $_.id -eq $script:WhRecallEntryId })
        Assert-WhEqual $recall.Count 1 'the Recall attestation entry is present'
    }

    Invoke-WhTest 'a manifest that breaks the never-touch policy is refused' {
        $bad = New-WhTestEntry 'tst-900-bad' @([ordered]@{ type = 'service'; name = 'wuauserv'; startup = 'Disabled'; stop = $true })
        $problems = @(Get-WhEntryProblems -Entry $bad -Policy $policy)
        Assert-WhTrue ($problems.Count -gt 0) 'service on the never-touch list is reported'
        $noRationale = New-WhTestEntry 'tst-901-norationale' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\a' 'V')) @{ rationale = '' }
        Assert-WhTrue (@(Get-WhEntryProblems -Entry $noRationale -Policy $policy).Count -gt 0) 'an entry without rationale is refused'
        $badLint = New-WhTestEntry 'tst-902-lint' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\a' 'V')) @{ audit = [ordered]@{ checks = @([ordered]@{ command = "Remove-Item 'C:\x'"; expected = 'x' }) } }
        Assert-WhTrue (@(Get-WhEntryProblems -Entry $badLint -Policy $policy).Count -gt 0) 'a write command in an audit is refused'
    }

    Invoke-WhTest 'number conversions between registry and manifest' {
        Assert-WhEqual (ConvertTo-WhDWord -Value 4294967295) -1 'DWord max becomes -1'
        Assert-WhEqual (ConvertTo-WhDWord -Value 2147483648) -2147483648 'DWord 0x80000000'
        Assert-WhEqual (ConvertTo-WhUInt64 -Value ([int32]-1)) 4294967295 'signed -1 reads as 4294967295'
        Assert-WhEqual (ConvertTo-WhQWord -Value ([uint64]18446744073709551615)) -1 'QWord max becomes -1'
        Assert-WhEqual (ConvertTo-WhUInt64 -Value ([int64]-1)) 18446744073709551615 'signed int64 -1 reads as the maximum'
    }

    Invoke-WhTest 'canonical text and fake snapshots: an entry called keys is an ordinary entry, and a snapshot follows the state' {
        Assert-WhEqual (ConvertTo-WhCanonical -Value ([ordered]@{ b = 2; a = 'x' })) '{"a":"x","b":2}' 'keys are sorted'
        Assert-WhEqual (ConvertTo-WhCanonical -Value @{ keys = 1; count = 2 }) '{"count":2,"keys":1}' 'entries called keys and count are read as entries'
        Assert-WhEqual (ConvertTo-WhCanonical -Value ([pscustomobject]@{ z = $true; y = $null })) '{"y":null,"z":true}' 'an object gives the same form as a dictionary'
        $empty = Get-WhFakeSnapshot
        $script:WhFake.keys['HKLM|SOFTWARE\winharden-selftest\snap'] = $true
        Assert-WhTrue ((Get-WhFakeSnapshot) -ne $empty) 'a snapshot notices a new registry key'
        $script:WhFake.services['WhTestSvc'] = @{ startup = 'Automatic'; status = 'Running'; driver = $false }
        $running = Get-WhFakeSnapshot
        $script:WhFake.services['WhTestSvc'].startup = 'Disabled'
        Assert-WhTrue ((Get-WhFakeSnapshot) -ne $running) 'a snapshot notices a changed service'
    }

    Invoke-WhTest 'journal detects edits, deletions and reordering' {
        $run = New-WhRunId
        [void](Add-WhJournalRecord -RunId $run -Type 'note' -Data ([ordered]@{ a = 1 }))
        [void](Add-WhJournalRecord -RunId $run -Type 'note' -Data ([ordered]@{ a = 2 }))
        [void](Add-WhJournalRecord -RunId $run -Type 'note' -Data ([ordered]@{ a = 3 }))
        Assert-WhEqual @((Read-WhJournal).problems).Count 0 'a fresh journal verifies'
        $path = Get-WhJournalPath
        $lines = @([System.IO.File]::ReadAllLines($path, $script:WhUtf8))
        Write-WhFile -Path $path -Text (($lines[0], $lines[1].Replace('"a":2', '"a":9'), $lines[2]) -join "`n")
        Assert-WhTrue (@((Read-WhJournal).problems).Count -gt 0) 'an edited record is detected'
        Write-WhFile -Path $path -Text (($lines[0], $lines[2]) -join "`n")
        Assert-WhTrue (@((Read-WhJournal).problems).Count -gt 0) 'a deleted record is detected'
        Write-WhFile -Path $path -Text (($lines[1], $lines[0], $lines[2]) -join "`n")
        Assert-WhTrue (@((Read-WhJournal).problems).Count -gt 0) 'reordered records are detected'
    }

    Invoke-WhTest 'registry: plan, apply, and a second run changes nothing' {
        $e = New-WhTestEntry 'tst-001-reg' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\a' 'V' 1))
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.plan.entries[0].status 'change' 'first plan wants a change'
        Assert-WhEqual $r.result.applied 1 'applied one entry'
        Assert-WhEqual $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\a|V'].data 1 'value written'
        $calls = $script:WhFake.calls.Count
        $r2 = Invoke-WhTestApply @($e)
        Assert-WhEqual $r2.plan.entries[0].status 'ok' 'second plan is already compliant'
        Assert-WhEqual $script:WhFake.calls.Count $calls 'second run made no change calls'
    }

    Invoke-WhTest 'registry: scope user reaches every profile and the Default user' {
        $e = New-WhTestEntry 'tst-002-user' @((New-WhTestRegOp 'Software\winharden-selftest\u' 'V' 0 'user'))
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.plan.entries[0].items.Count 3 'one target per profile plus Default'
        foreach ($label in @('S-1-5-21-1-2-3-1001', 'S-1-5-21-1-2-3-1002', 'DEFAULT')) {
            Assert-WhTrue ($script:WhFake.reg.ContainsKey($label + '|Software\winharden-selftest\u|V')) ('written for ' + $label)
        }
    }

    Invoke-WhTest 'registry: a value of the wrong type is replaced and restored' {
        $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\t|V'] = @{ kind = 'String'; data = '1' }
        $script:WhFake.keys['HKLM|SOFTWARE\winharden-selftest\t'] = $true
        $e = New-WhTestEntry 'tst-003-type' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\t' 'V' 1))
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.plan.entries[0].status 'change' 'REG_SZ 1 is not DWord 1'
        Assert-WhEqual $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\t|V'].kind 'DWord' 'now a DWord'
        $rb = Invoke-WhRollback -Checkpoint 'latest' -RunId (New-WhRunId)
        Assert-WhEqual $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\t|V'].kind 'String' 'rollback restores the type'
        Assert-WhEqual $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\t|V'].data '1' 'rollback restores the data'
        Assert-WhTrue $rb.ok 'rollback verified'
    }

    Invoke-WhTest 'hide list: tokens are merged, showonly aborts' {
        $op = New-WhTestRegOp 'SOFTWARE\winharden-selftest\h' 'SettingsPageVisibility' 'hide:home' 'machine' 'String'
        $op['merge'] = 'hide-list'
        $opObj = ConvertFrom-WhJson -Text (ConvertTo-WhJson -Object $op)
        $v1 = Get-WhRegistryVerdict -Op $opObj -State ([ordered]@{ exists = $false; key_exists = $false })
        Assert-WhEqual $v1.data 'hide:home' 'absent value gets the list'
        $v2 = Get-WhRegistryVerdict -Op $opObj -State ([ordered]@{ exists = $true; key_exists = $true; kind = 'String'; data = 'hide:windowsupdate' })
        Assert-WhEqual $v2.data 'hide:windowsupdate;home' 'existing tokens are kept'
        $v3 = Get-WhRegistryVerdict -Op $opObj -State ([ordered]@{ exists = $true; key_exists = $true; kind = 'String'; data = 'hide:home;windowsupdate' })
        Assert-WhEqual $v3.status 'ok' 'a list that already has the token is compliant'
        $v4 = Get-WhRegistryVerdict -Op $opObj -State ([ordered]@{ exists = $true; key_exists = $true; kind = 'String'; data = 'showonly:network' })
        Assert-WhEqual $v4.status 'blocked' 'showonly aborts the entry'
    }

    Invoke-WhTest 'an entry is atomic: a failure reverts what was already changed' {
        $script:WhFake.fail['RegSet|Boom'] = 'injected failure'
        $e = New-WhTestEntry 'tst-004-atomic' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\x' 'Fine' 1), (New-WhTestRegOp 'SOFTWARE\winharden-selftest\x' 'Boom' 1))
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.result.failed 1 'the entry failed'
        Assert-WhTrue (-not $script:WhFake.reg.ContainsKey('HKLM|SOFTWARE\winharden-selftest\x|Fine')) 'the first value was removed again'
        Assert-WhTrue (-not $script:WhFake.keys.ContainsKey('HKLM|SOFTWARE\winharden-selftest\x')) 'the key that did not exist is gone again'
        $types = @((Read-WhJournal).records | ForEach-Object { [string]$_.type })
        Assert-WhTrue ($types -contains 'txn-revert') 'the revert is journaled'
        Assert-WhTrue ($types -notcontains 'txn-commit') 'no commit for a failed entry'
    }

    Invoke-WhTest 'a failed entry does not stop the next entry' {
        $script:WhFake.fail['RegSet|Boom'] = 'injected failure'
        $bad = New-WhTestEntry 'tst-005-bad' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\y' 'Boom' 1))
        $good = New-WhTestEntry 'tst-006-good' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\y' 'Good' 1))
        $r = Invoke-WhTestApply @($bad, $good)
        Assert-WhEqual $r.result.failed 1 'one failure'
        Assert-WhEqual $r.result.applied 1 'one success'
        Assert-WhTrue $script:WhFake.reg.ContainsKey('HKLM|SOFTWARE\winharden-selftest\y|Good') 'the good entry was applied'
    }

    Invoke-WhTest 'a change made after the plan is detected and nothing is changed' {
        $e = New-WhTestEntry 'tst-007-race' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\z' 'V' 1))
        $facts = Invoke-WhProv 'Facts'
        $plan = New-WhPlan -Entries @($e) -Facts $facts -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'selftest' -Excluded @()
        $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\z|V'] = @{ kind = 'DWord'; data = [int64]7 }
        $script:WhFake.keys['HKLM|SOFTWARE\winharden-selftest\z'] = $true
        $res = Invoke-WhApply -Plan $plan -RunId (New-WhRunId) -Label 'selftest' -RestorePoint $null
        Assert-WhEqual $res.failed 1 'the stale plan is refused'
        Assert-WhEqual $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\z|V'].data 7 'the value was left alone'
    }

    Invoke-WhTest 'plan hash is stable and follows the state' {
        $e = New-WhTestEntry 'tst-008-hash' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\p' 'V' 1))
        $facts = Invoke-WhProv 'Facts'
        $p1 = New-WhPlan -Entries @($e) -Facts $facts -Level 2 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        $p2 = New-WhPlan -Entries @($e) -Facts $facts -Level 2 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p1.hash $p2.hash 'same state, same hash'
        $p3 = New-WhPlan -Entries @($e) -Facts $facts -Level 2 -Gates (Get-WhTestGates) -ManifestHash 'other' -Excluded @()
        Assert-WhTrue ($p1.hash -ne $p3.hash) 'a different manifest set changes the hash'
        $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\p|V'] = @{ kind = 'DWord'; data = [int64]3 }
        $p4 = New-WhPlan -Entries @($e) -Facts $facts -Level 2 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhTrue ($p1.hash -ne $p4.hash) 'a different system state changes the hash'
    }

    Invoke-WhTest 'rollback restores registry, service, task and feature exactly' {
        $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\r|Old'] = @{ kind = 'DWord'; data = [int64]5 }
        $script:WhFake.keys['HKLM|SOFTWARE\winharden-selftest\r'] = $true
        $script:WhFake.services['WhTestSvc'] = @{ startup = 'Automatic'; status = 'Running'; driver = $false }
        $script:WhFake.tasks['\winharden-selftest\T1'] = 'Ready'
        $script:WhFake.features['WhTestFeature'] = 'Enabled'
        $before = Get-WhFakeSnapshot
        $ops = @(
            (New-WhTestRegOp 'SOFTWARE\winharden-selftest\r' 'Old' 9),
            (New-WhTestRegOp 'SOFTWARE\winharden-selftest\r' 'New' 1),
            (New-WhTestRegOp 'SOFTWARE\winharden-selftest\fresh' 'N' 1),
            [ordered]@{ type = 'service'; name = 'WhTestSvc'; startup = 'Disabled'; stop = $true },
            [ordered]@{ type = 'scheduled_task'; path = '\winharden-selftest\'; name = 'T1'; state = 'Disabled'; if_missing = 'skip' },
            [ordered]@{ type = 'optional_feature'; name = 'WhTestFeature'; state = 'Disabled' }
        )
        $e = New-WhTestEntry 'tst-009-rollback' $ops
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.result.applied 1 'applied'
        Assert-WhEqual $script:WhFake.services['WhTestSvc'].startup 'Disabled' 'service disabled'
        Assert-WhEqual $script:WhFake.services['WhTestSvc'].status 'Stopped' 'service stopped'
        Assert-WhTrue ((Get-WhFakeSnapshot) -ne $before) 'the state changed'
        $rb = Invoke-WhRollback -Checkpoint ('cp-' + $r.run) -RunId (New-WhRunId)
        Assert-WhTrue $rb.ok ('rollback ok: ' + ($rb.failed -join '; ') + ' ' + ($rb.mismatch -join '; '))
        Assert-WhEqual (Get-WhFakeSnapshot) $before 'the fake system is exactly as before'
        Assert-WhEqual $script:WhFake.services['WhTestSvc'].status 'Running' 'the service runs again'
    }

    Invoke-WhTest 'rollback refuses a tampered journal' {
        $e = New-WhTestEntry 'tst-010-tamper' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\k' 'V' 1))
        $r = Invoke-WhTestApply @($e)
        $path = Get-WhJournalPath
        $text = Read-WhFile -Path $path
        Write-WhFile -Path $path -Text ($text.Replace('"V"', '"W"'))
        Reset-WhJournalCache
        $threw = $false
        try { [void](Invoke-WhRollback -Checkpoint 'latest' -RunId (New-WhRunId)) } catch { $threw = $true }
        Assert-WhTrue $threw 'rollback stops on a journal that fails verification'
    }

    Invoke-WhTest 'service and task: missing targets are skipped, if_missing=error blocks' {
        $e1 = New-WhTestEntry 'tst-011-missing' @([ordered]@{ type = 'service'; name = 'NoSuchSvc'; startup = 'Disabled'; stop = $true })
        $p1 = New-WhPlan -Entries @($e1) -Facts (Invoke-WhProv 'Facts') -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p1.entries[0].status 'skip' 'a missing service is not applicable'
        $e2 = New-WhTestEntry 'tst-012-task' @([ordered]@{ type = 'scheduled_task'; path = '\winharden-selftest\'; name = 'Missing'; state = 'Disabled'; if_missing = 'error' })
        $p2 = New-WhPlan -Entries @($e2) -Facts (Invoke-WhProv 'Facts') -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p2.entries[0].status 'blocked' 'if_missing=error blocks the entry'
    }

    Invoke-WhTest 'service: a stop that fails is a warning, the startup type still changes' {
        $script:WhFake.services['WhTestSvc'] = @{ startup = 'Automatic'; status = 'Running'; driver = $false }
        $script:WhFake.fail['ServiceRunning|WhTestSvc'] = 'cannot stop'
        $e = New-WhTestEntry 'tst-013-stopfail' @([ordered]@{ type = 'service'; name = 'WhTestSvc'; startup = 'Disabled'; stop = $true })
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.result.applied 1 'the entry is applied'
        Assert-WhEqual $script:WhFake.services['WhTestSvc'].startup 'Disabled' 'startup disabled'
        Assert-WhEqual @($r.result.results[0].warnings).Count 1 'one warning about the running service'
    }

    Invoke-WhTest 'AppX: installed and provisioned copies go together; rollback lists the manual step' {
        $script:WhFake.appx['Winharden.SelfTest.App'] = @{ installed = @('Winharden.SelfTest.App_1.0_x64__abc'); provisioned = @('Winharden.SelfTest.App_1.0_neutral_~_abc') }
        $e = New-WhTestEntry 'tst-014-appx' @([ordered]@{ type = 'appx'; package_name = 'Winharden.SelfTest.App'; action = 'remove'; deprovision = $true; all_users = $true })
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.result.applied 1 'removed'
        Assert-WhEqual @($script:WhFake.appx['Winharden.SelfTest.App'].installed).Count 0 'no installed copy left'
        Assert-WhEqual @($script:WhFake.appx['Winharden.SelfTest.App'].provisioned).Count 0 'no provisioned copy left'
        $rb = Invoke-WhRollback -Checkpoint 'latest' -RunId (New-WhRunId)
        Assert-WhEqual @($rb.manual).Count 1 'rollback reports the app for a manual reinstall'
        $again = Invoke-WhTestApply @($e)
        Assert-WhEqual $again.plan.entries[0].status 'ok' 'a removed app is compliant'
    }

    Invoke-WhTest 'optional feature: disabled, and a missing feature is not applicable' {
        $script:WhFake.features['WhTestFeature'] = 'Enabled'
        $e = New-WhTestEntry 'tst-015-feature' @([ordered]@{ type = 'optional_feature'; name = 'WhTestFeature'; state = 'Disabled' })
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $script:WhFake.features['WhTestFeature'] 'Disabled' 'feature disabled'
        $e2 = New-WhTestEntry 'tst-016-nofeature' @([ordered]@{ type = 'optional_feature'; name = 'NoSuchFeature'; state = 'Disabled' })
        $p = New-WhPlan -Entries @($e2) -Facts (Invoke-WhProv 'Facts') -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p.entries[0].status 'skip' 'a missing feature is not applicable'
    }

    Invoke-WhTest 'gates: user-data deletion and servicing-adjacent entries need explicit consent' {
        $ops = @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\g' 'V' 1))
        $eData = New-WhTestEntry 'tst-017-data' $ops @{ flags = [ordered]@{ deletes_user_data = $true } }
        $eServ = New-WhTestEntry 'tst-018-serv' $ops @{ flags = [ordered]@{ servicing_adjacent = $true } }
        $facts = Invoke-WhProv 'Facts'
        $p = New-WhPlan -Entries @($eData, $eServ) -Facts $facts -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p.entries[0].status 'blocked' 'data loss is blocked by default'
        Assert-WhEqual $p.entries[1].status 'blocked' 'servicing-adjacent is blocked by default'
        $p2 = New-WhPlan -Entries @($eData, $eServ) -Facts $facts -Level 3 -Gates (Get-WhTestGates $true $true) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p2.entries[0].status 'change' 'data loss allowed with consent'
        Assert-WhEqual $p2.entries[1].status 'change' 'servicing-adjacent allowed with consent'
        Assert-WhTrue ($p.hash -ne $p2.hash) 'consent is part of the plan hash'
    }

    Invoke-WhTest 'applicability: build, edition and hardware requirements' {
        $ops = @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\b' 'V' 1))
        $eBuild = New-WhTestEntry 'tst-019-build' $ops @{ applicability = [ordered]@{ min_build = 99999 } }
        $eHw = New-WhTestEntry 'tst-020-hw' $ops @{ requires_hardware = 'virtualization' }
        $facts = Invoke-WhProv 'Facts'
        $p = New-WhPlan -Entries @($eBuild, $eHw) -Facts $facts -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p.entries[0].status 'skip' 'a newer build requirement is not applicable'
        Assert-WhEqual $p.entries[1].status 'change' 'hardware requirement met'
        $script:WhFake.facts.virtualization = $false
        $p2 = New-WhPlan -Entries @($eHw) -Facts $facts -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p2.entries[0].status 'blocked' 'hardware requirement not met blocks the entry'
        $eAv = New-WhTestEntry 'tst-020-av' $ops @{ requires_hardware = 'defender_active' }
        Assert-WhEqual (New-WhPlan -Entries @($eAv) -Facts $facts -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()).entries[0].status 'change' 'Defender is the active antivirus'
        $script:WhFake.facts.defender_active = $false
        $p3 = New-WhPlan -Entries @($eAv) -Facts $facts -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p3.entries[0].status 'blocked' 'another antivirus blocks a Defender entry'
        Assert-WhTrue ($p3.entries[0].reason -like '*not the active antivirus*') 'the reason names the antivirus'
    }

    Invoke-WhTest 'selection: profile level, exclude and only' {
        $ops = @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\s' 'V' 1))
        $a = New-WhTestEntry 'tst-021-a' $ops
        $b = New-WhTestEntry 'tst-022-b' $ops @{ min_profile = 2 }
        $c = New-WhTestEntry 'tst-023-c' $ops @{ min_profile = 3 }
        Assert-WhEqual @((Select-WhEntries -Entries @($a, $b, $c) -Level 1).selected).Count 1 'profile 1'
        Assert-WhEqual @((Select-WhEntries -Entries @($a, $b, $c) -Level 3).selected).Count 3 'profile 3'
        $x = Select-WhEntries -Entries @($a, $b, $c) -Level 3 -Exclude @('tst-022*')
        Assert-WhEqual @($x.selected).Count 2 'exclude by pattern'
        Assert-WhEqual @($x.excluded).Count 1 'excluded entry is listed'
        Assert-WhEqual @((Select-WhEntries -Entries @($a, $b, $c) -Level 3 -Only @('tst-023-c')).selected).Count 1 'only'
    }

    Invoke-WhTest 'verify: pass, fail, error, na, manual and the SYSTEM rule for HKCU' {
        $script:WhFake.services['WhTestSvc'] = @{ startup = 'Disabled'; status = 'Stopped'; driver = $false }
        $svcOp = [ordered]@{ type = 'service'; name = 'WhTestSvc'; startup = 'Disabled'; stop = $true }
        $cmd = "Get-Service -Name 'WhTestSvc'"
        $ePass = New-WhTestEntry 'tst-030-pass' @($svcOp)
        $script:WhFake.audits[$cmd] = 'x'
        $facts = Invoke-WhProv 'Facts'
        Assert-WhEqual (Test-WhEntry -Entry $ePass -Facts $facts).status 'pass' 'state and audit agree'
        $script:WhFake.audits[$cmd] = 'y'
        Assert-WhEqual (Test-WhEntry -Entry $ePass -Facts $facts).status 'fail' 'the audit disagrees'
        $script:WhFake.audits.Remove($cmd)
        Assert-WhEqual (Test-WhEntry -Entry $ePass -Facts $facts).status 'error' 'an audit that cannot run is an error, not a pass'
        Assert-WhEqual (Test-WhEntry -Entry $ePass -Facts $facts -RunAudits $false).status 'pass' 'quick mode checks state only'
        $script:WhFake.services['WhTestSvc'].startup = 'Automatic'
        $script:WhFake.audits[$cmd] = 'x'
        Assert-WhEqual (Test-WhEntry -Entry $ePass -Facts $facts).status 'fail' 'the state check fails even when the audit passes'
        $script:WhFake.services.Remove('WhTestSvc')
        Assert-WhEqual (Test-WhEntry -Entry $ePass -Facts $facts).status 'na' 'nothing to enforce when the target is absent'
        $eManual = New-WhTestEntry 'tst-031-manual' @() @{ mode = 'manual'; manual_steps = @('Do the thing by hand.'); audit = [ordered]@{ manual_check = 'Open the settings page and confirm the toggle is off.' } }
        Assert-WhEqual (Test-WhEntry -Entry $eManual -Facts $facts).status 'manual' 'manual entries are reported as manual'
        $hk = "(Get-ItemProperty -Path 'HKCU:\Software\winharden-selftest' -Name V -ErrorAction SilentlyContinue).V"
        $script:WhFake.audits[$hk] = '1'
        $script:WhFake.services['WhTestSvc'] = @{ startup = 'Disabled'; status = 'Stopped'; driver = $false }
        $eHk = New-WhTestEntry 'tst-032-hkcu' @($svcOp) @{ audit = [ordered]@{ checks = @([ordered]@{ command = $hk; expected = '1' }) } }
        $script:WhFake.facts.is_system = $true
        $res = Test-WhEntry -Entry $eHk -Facts (Invoke-WhProv 'Facts')
        Assert-WhEqual $res.audit_checks[0].status 'skipped' 'HKCU audits are skipped when running as SYSTEM'
    }

    Invoke-WhTest 'verify: a failing entry that a closed gate keeps apply away from says so' {
        $script:WhFake.services['WhTestSvc'] = @{ startup = 'Automatic'; status = 'Running'; driver = $false }
        $svcOp = [ordered]@{ type = 'service'; name = 'WhTestSvc'; startup = 'Disabled'; stop = $true }
        $script:WhFake.audits["Get-Service -Name 'WhTestSvc'"] = 'x'
        $e = New-WhTestEntry 'tst-033-gated' @($svcOp) @{ flags = [ordered]@{ deletes_user_data = $true } }
        $facts = Invoke-WhProv 'Facts'
        $closed = Test-WhEntry -Entry $e -Facts $facts -Gates (Get-WhTestGates)
        $closedText = [string]$closed.reason
        Assert-WhEqual $closed.status 'fail' 'the system does not match the manifest'
        Assert-WhTrue $closedText.Contains('Apply skips this entry: Deletes user data') 'the reason names the closed gate'
        $open = Test-WhEntry -Entry $e -Facts $facts -Gates (Get-WhTestGates $true $true)
        $openText = [string]$open.reason
        Assert-WhEqual $open.status 'fail' 'an open gate does not change the status'
        Assert-WhTrue (-not $openText.Contains('Apply skips')) 'an open gate adds no note'
        $bare = Test-WhEntry -Entry $e -Facts $facts
        $bareText = [string]$bare.reason
        Assert-WhTrue (-not $bareText.Contains('Apply skips')) 'a caller that gives no gates gets no note'
    }

    Invoke-WhTest 'preflight: each platform problem blocks, overrides turn blockers into warnings' {
        $good = Invoke-WhProv 'Facts'
        Assert-WhTrue (Test-WhPreflight -Facts $good -Options @{}).ok 'a healthy Home 25H2 system passes'
        $cases = @(
            @{ name = 'not admin'; code = 'PF01'; mutate = { $script:WhFake.facts.is_admin = $false } },
            @{ name = '32-bit process'; code = 'PF02'; mutate = { $script:WhFake.facts.process_64bit = $false } },
            @{ name = 'old build'; code = 'PF03'; mutate = { $script:WhFake.facts.build = 26100 } },
            @{ name = 'future build'; code = 'PF03'; mutate = { $script:WhFake.facts.build = 28000 } },
            @{ name = 'Pro edition'; code = 'PF04'; mutate = { $script:WhFake.facts.edition_id = 'Professional' } },
            @{ name = 'pending reboot'; code = 'PF05'; mutate = { $script:WhFake.facts.pending_reboot = @('Windows Update') } },
            @{ name = 'Secure Boot off'; code = 'PF06'; mutate = { $script:WhFake.facts.secure_boot = 'disabled' } },
            @{ name = 'no TPM'; code = 'PF07'; mutate = { $script:WhFake.facts.tpm_present = $false } }
        )
        foreach ($c in $cases) {
            Reset-WhFake
            & $c.mutate
            $r = Test-WhPreflight -Facts (Invoke-WhProv 'Facts') -Options @{}
            Assert-WhTrue ((-not $r.ok) -and (@($r.blockers | Where-Object { $_.code -eq $c.code }).Count -eq 1)) ('blocks: ' + $c.name)
        }
        Reset-WhFake
        $script:WhFake.facts.secure_boot = 'disabled'
        $script:WhFake.facts.tpm_present = $false
        $r2 = Test-WhPreflight -Facts (Invoke-WhProv 'Facts') -Options @{ allow_platform_gaps = $true }
        Assert-WhTrue $r2.ok 'platform gaps pass with the explicit override'
        Assert-WhTrue (@($r2.warnings).Count -ge 2) 'and are still reported as warnings'
    }

    Invoke-WhTest 'report: JSON, HTML, CSV and XCCDF are produced and the Recall line is always there' {
        $facts = Invoke-WhProv 'Facts'
        $script:WhFake.services['WhTestSvc'] = @{ startup = 'Disabled'; status = 'Stopped'; driver = $false }
        $script:WhFake.audits["Get-Service -Name 'WhTestSvc'"] = 'x'
        $ePass = New-WhTestEntry 'tst-040-pass' @([ordered]@{ type = 'service'; name = 'WhTestSvc'; startup = 'Disabled'; stop = $true })
        $eFail = New-WhTestEntry 'tst-041-fail' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\rep' 'V' 1)) @{ title = 'A failing entry with <markup> & "quotes"' }
        $script:WhFake.audits["Get-Service -Name 'WhTestSvc'"] = 'x'
        $results = @(Invoke-WhVerify -Entries @($ePass, $eFail) -Facts $facts)
        $model = New-WhReportModel -Results $results -Facts $facts -Level 2 -ManifestHash 'm' -Kind 'verify' -Excluded @() -ApplyResult $null -PlanId ''
        Assert-WhEqual $model.recall.status 'not-checked' 'without the Recall entry the report says NOT CHECKED'
        $dir = Join-Path $script:WhStateDir 'out'
        $paths = Write-WhReports -Model $model -Directory $dir
        $json = ConvertFrom-WhJson -Text (Read-WhFile -Path $paths.json)
        Assert-WhEqual @($json.entries).Count 2 'JSON has both entries'
        $html = Read-WhFile -Path $paths.html
        Assert-WhTrue $html.Contains('Recall attestation') 'HTML has the Recall box'
        Assert-WhTrue (-not $html.Contains('<markup>')) 'HTML escapes entry text'
        $csv = Read-WhFile -Path $paths.poam
        Assert-WhTrue $csv.StartsWith('ID,Title,Status') 'CSV has the POA&M header'
        Assert-WhTrue $csv.Contains('tst-041-fail') 'CSV lists the failing entry'
        $xml = New-Object System.Xml.XmlDocument
        $xml.LoadXml((Read-WhFile -Path $paths.xccdf))
        Assert-WhEqual $xml.DocumentElement.LocalName 'Benchmark' 'XCCDF root element'
        $recallEntry = New-WhTestEntry $script:WhRecallEntryId @() @{ mode = 'attest' }
        $script:WhFake.audits["Get-Service -Name 'WhTestSvc'"] = 'x'
        $res2 = @(Invoke-WhVerify -Entries @($recallEntry) -Facts $facts)
        Assert-WhEqual (Get-WhRecallAttestation -Results $res2).status 'attested-off' 'a passing Recall entry is attested'
        $script:WhFake.audits["Get-Service -Name 'WhTestSvc'"] = 'wrong'
        $res3 = @(Invoke-WhVerify -Entries @($recallEntry) -Facts $facts)
        Assert-WhEqual (Get-WhRecallAttestation -Results $res3).status 'not-attested' 'a failing Recall entry is not attested'
    }

    Invoke-WhTest 'registry: a wildcard path covers every matching key and rollback restores them' {
        foreach ($n in @('Tcpip_{A}', 'Tcpip_{B}', 'Other')) { $script:WhFake.keys[('HKLM|SOFTWARE\winharden-selftest\nic\' + $n)] = $true }
        $before = Get-WhFakeSnapshot
        $e = New-WhTestEntry 'tst-040-glob' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\nic\Tcpip_*' 'NetbiosOptions' 2))
        Assert-WhEqual @(Get-WhEntryProblems -Entry $e -Policy $policy).Count 0 'the entry passes the runtime checks'
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.plan.entries[0].items.Count 2 'two matching keys; the third does not match'
        Assert-WhEqual $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\nic\Tcpip_{A}|NetbiosOptions'].data 2 'written below the first key'
        Assert-WhEqual $script:WhFake.reg['HKLM|SOFTWARE\winharden-selftest\nic\Tcpip_{B}|NetbiosOptions'].data 2 'written below the second key'
        Assert-WhTrue (-not $script:WhFake.reg.ContainsKey('HKLM|SOFTWARE\winharden-selftest\nic\Other|NetbiosOptions')) 'the key that does not match is untouched'
        $rb = Invoke-WhRollback -Checkpoint ('cp-' + $r.run) -RunId (New-WhRunId)
        Assert-WhTrue $rb.ok ('rollback ok: ' + ($rb.failed -join '; ') + ' ' + ($rb.mismatch -join '; '))
        Assert-WhEqual (Get-WhFakeSnapshot) $before 'the fake system is exactly as before'
        $script:WhFake.keys['HKLM|SOFTWARE\winharden-selftest\nic\Tcpip_{C}'] = $true
        $r2 = Invoke-WhTestApply @($e)
        Assert-WhEqual $r2.plan.entries[0].items.Count 3 'a key that appears later is found by the next plan'
    }

    Invoke-WhTest 'wildcard path: a pattern that could reach a protected key is refused at run time' {
        $bad = New-WhTestEntry 'tst-041-globbad' @((New-WhTestRegOp 'SYSTEM\CurrentControlSet\Services\*' 'Foo' 1))
        Assert-WhTrue (@(Get-WhEntryProblems -Entry $bad -Policy $policy).Count -gt 0) 'a pattern over all service keys is refused'
        $parent = New-WhTestEntry 'tst-042-globparent' @((New-WhTestRegOp 'SOFTWARE\winharden-selftest\*\x' 'V' 1))
        Assert-WhTrue (@(Get-WhEntryProblems -Entry $parent -Policy $policy).Count -gt 0) 'a wildcard outside the last segment is refused'
    }

    Invoke-WhTest 'settings: Defender preference, ASR rule and audit subcategory are applied, verified and rolled back' {
        $asr = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
        $audit = '0CCE9215-69AE-11D9-BED3-505054503030'
        $script:WhFake.settings['defender_pref|mapsreporting'] = '1'
        $script:WhFake.settings[('audit_policy|' + $audit.ToLowerInvariant())] = 'success'
        $before = Get-WhFakeSnapshot
        $ops = @(
            [ordered]@{ type = 'setting'; kind = 'defender_pref'; name = 'MAPSReporting'; value = 2 },
            [ordered]@{ type = 'setting'; kind = 'defender_asr'; name = $asr; value = 'block'; label = 'Block credential stealing from LSASS' },
            [ordered]@{ type = 'setting'; kind = 'audit_policy'; name = $audit; value = 'success_failure' }
        )
        $e = New-WhTestEntry 'tst-043-settings' $ops
        Assert-WhEqual @(Get-WhEntryProblems -Entry $e -Policy $policy).Count 0 'the entry passes the runtime checks'
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.result.applied 1 'applied'
        Assert-WhEqual $script:WhFake.settings['defender_pref|mapsreporting'] '2' 'the preference is written as text'
        Assert-WhEqual $script:WhFake.settings[('defender_asr|' + $asr)] 'block' 'the ASR rule is added'
        Assert-WhEqual $script:WhFake.settings[('audit_policy|' + $audit.ToLowerInvariant())] 'success_failure' 'the audit setting is written'
        $facts = Invoke-WhProv 'Facts'
        Assert-WhEqual (Test-WhEntry -Entry $e -Facts $facts -RunAudits $false).status 'pass' 'the state check passes'
        $rb = Invoke-WhRollback -Checkpoint ('cp-' + $r.run) -RunId (New-WhRunId)
        Assert-WhTrue $rb.ok ('rollback ok: ' + ($rb.failed -join '; ') + ' ' + ($rb.mismatch -join '; '))
        Assert-WhEqual (Get-WhFakeSnapshot) $before 'the preference, the ASR rule (removed again) and the audit setting are as before'
    }

    Invoke-WhTest 'settings: a second run changes nothing, a failed write reverts the whole entry' {
        $script:WhFake.settings['defender_pref|mapsreporting'] = '1'
        $ops = @(
            [ordered]@{ type = 'setting'; kind = 'defender_pref'; name = 'MAPSReporting'; value = 2 },
            [ordered]@{ type = 'setting'; kind = 'defender_pref'; name = 'PUAProtection'; value = 1 }
        )
        $e = New-WhTestEntry 'tst-044-settings2' $ops
        $script:WhFake.settings['defender_pref|puaprotection'] = '0'
        $script:WhFake.fail['SettingSet|PUAProtection'] = 'simulated failure'
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.result.failed 1 'the entry failed'
        Assert-WhEqual $script:WhFake.settings['defender_pref|mapsreporting'] '1' 'the first preference was put back'
        $script:WhFake.fail.Clear()
        $r2 = Invoke-WhTestApply @($e)
        Assert-WhEqual $r2.result.applied 1 'it applies once the fault is gone'
        $calls = $script:WhFake.calls.Count
        $r3 = Invoke-WhTestApply @($e)
        Assert-WhEqual $r3.plan.entries[0].status 'ok' 'the third plan is compliant'
        Assert-WhEqual $script:WhFake.calls.Count $calls 'no write on the third run'
    }

    Invoke-WhTest 'settings: the policy refuses a setting that is not on the allow-list' {
        $off = New-WhTestEntry 'tst-045-off' @([ordered]@{ type = 'setting'; kind = 'defender_pref'; name = 'DisableRealtimeMonitoring'; value = $true })
        Assert-WhTrue (@(Get-WhEntryProblems -Entry $off -Policy $policy).Count -gt 0) 'switching real-time protection off is refused'
        $wrongType = New-WhTestEntry 'tst-046-type' @([ordered]@{ type = 'setting'; kind = 'defender_asr'; name = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; value = 1 })
        Assert-WhTrue (@(Get-WhEntryProblems -Entry $wrongType -Policy $policy).Count -gt 0) 'an ASR action must be a word, not a number'
    }

    Invoke-WhTest 'cleanup: mode once deletes once, the plan id ignores file counts, verification leaves it out' {
        $script:WhFake.roots['machine|%systemroot%\temp'] = @('C:\Windows\Temp', 'C:\Windows\Missing')
        $script:WhFake.dirs['C:\Windows\Temp'] = @{ files = 12; bytes = 5242880 }
        $op = [ordered]@{ type = 'file_cleanup'; scope = 'machine'; root = '%SystemRoot%\Temp'; pattern = '*'; min_age_days = 7; recurse = $true }
        $extra = @{
            mode     = 'once'
            rollback = [ordered]@{ strategy = 'manual'; reversibility = 'partial'; limitation = 'Deleted files are not restored; Windows recreates caches and logs.' }
            audit    = [ordered]@{ manual_check = 'Open Settings, System, Storage, Temporary files and check the size.' }
        }
        $e = New-WhTestEntry 'tst-047-clean' @($op) $extra
        Assert-WhEqual @(Get-WhEntryProblems -Entry $e -Policy $policy).Count 0 'the cleanup entry passes the runtime checks'
        $facts = Invoke-WhProv 'Facts'
        $p1 = New-WhPlan -Entries @($e) -Facts $facts -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p1.entries[0].status 'change' 'files are waiting'
        Assert-WhEqual $p1.entries[0].items.Count 1 'only the folder that exists is listed'
        Assert-WhTrue ($p1.entries[0].items[0].label -like '*C:\Windows\Temp*') 'and it is the one that exists'
        $script:WhFake.dirs['C:\Windows\Temp']['files'] = 40
        $p2 = New-WhPlan -Entries @($e) -Facts $facts -Level 3 -Gates (Get-WhTestGates) -ManifestHash 'm' -Excluded @()
        Assert-WhEqual $p2.hash $p1.hash 'the plan id does not depend on how many files there are'
        $r = Invoke-WhTestApply @($e)
        Assert-WhEqual $r.result.applied 1 'applied'
        Assert-WhEqual $script:WhFake.dirs['C:\Windows\Temp'].files 0 'the files are gone'
        Assert-WhEqual @($script:WhFake.calls | Where-Object { $_ -like 'CleanRun*' }).Count 1 'the folder was cleaned once'
        $r2 = Invoke-WhTestApply @($e)
        Assert-WhEqual $r2.plan.entries[0].status 'ok' 'nothing left to clean'
        Assert-WhEqual @(Invoke-WhVerify -Entries @($e) -Facts $facts).Count 0 'a one-time entry is not part of verification'
        $rb = Invoke-WhRollback -Checkpoint ('cp-' + $r.run) -RunId (New-WhRunId)
        Assert-WhTrue $rb.ok 'rollback does not fail on a cleanup'
        Assert-WhTrue (@($rb.manual).Count -eq 1) 'rollback says once that deleted files are not restored'
    }

    Invoke-WhTest 'cleanup: a folder outside the allow-list and a mode that does not fit are refused' {
        $op = [ordered]@{ type = 'file_cleanup'; scope = 'machine'; root = '%SystemRoot%\SoftwareDistribution\Download'; pattern = '*'; min_age_days = 0; recurse = $true }
        $extra = @{
            mode     = 'once'
            rollback = [ordered]@{ strategy = 'manual'; reversibility = 'partial'; limitation = 'Deleted files are not restored; Windows recreates caches and logs.' }
            audit    = [ordered]@{ manual_check = 'Look at the folder.' }
        }
        $wu = New-WhTestEntry 'tst-048-wu' @($op) $extra
        Assert-WhTrue (@(Get-WhEntryProblems -Entry $wu -Policy $policy).Count -gt 0) 'the Windows Update download cache is refused'
        $op2 = [ordered]@{ type = 'file_cleanup'; scope = 'machine'; root = '%SystemRoot%\Temp'; pattern = '*'; min_age_days = 7; recurse = $true }
        $enforce = New-WhTestEntry 'tst-049-enforce' @($op2)
        Assert-WhTrue (@(Get-WhEntryProblems -Entry $enforce -Policy $policy).Count -gt 0) 'a cleanup in mode enforce is refused'
    }

    Invoke-WhTest 'verify: a check that prints translated text is skipped on a system that is not in English' {
        $script:WhFake.settings['audit_policy|0cce9215-69ae-11d9-bed3-505054503030'] = 'success_failure'
        $cmd = "auditpol /get /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /r"
        $check = [ordered]@{ command = $cmd; expected = 'Success and Failure'; locale_dependent = $true }
        $ops = @([ordered]@{ type = 'setting'; kind = 'audit_policy'; name = '0CCE9215-69AE-11D9-BED3-505054503030'; value = 'success_failure' })
        $e = New-WhTestEntry 'tst-050-locale' $ops @{ audit = [ordered]@{ checks = @($check) } }
        $script:WhFake.facts.ui_language = 'el'
        $res = Test-WhEntry -Entry $e -Facts (Invoke-WhProv 'Facts')
        Assert-WhEqual $res.audit_checks[0].status 'skipped' 'skipped on a Greek system'
        Assert-WhEqual $res.status 'pass' 'the state check still decides'
        $script:WhFake.facts.ui_language = 'en'
        $script:WhFake.audits[$cmd] = 'Success and Failure'
        Assert-WhEqual (Test-WhEntry -Entry $e -Facts (Invoke-WhProv 'Facts')).audit_checks[0].status 'pass' 'compared on an English system'
    }

    Invoke-WhTest 'the install folder check flags a writable folder' {
        Assert-WhTrue ((Get-WhInstallDirectory).EndsWith('winharden')) 'install folder is named winharden'
        $note = Get-WhDriftNote -Previous $null -Facts (Invoke-WhProv 'Facts')
        Assert-WhTrue ($note -like 'First*') 'first drift run is labeled'
        $prev = [pscustomobject]@{ build = 26100; ubr = 1 }
        Assert-WhTrue ((Get-WhDriftNote -Previous $prev -Facts (Invoke-WhProv 'Facts')) -like '*feature update*') 'a build change is a feature update'
    }
}

function Invoke-WhSelfTest {
    param([string]$Root, [switch]$Quiet)
    $saved = @{
        prov = $script:WhProv; dir = $script:WhStateDir; acl = $script:WhSkipAcl; quiet = $script:WhQuiet; testquiet = $script:WhTestQuiet
        tail = $script:WhJournalTail; trust = $script:WhJournalTrust; root = $script:WhRoot
    }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('winharden-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        $script:WhRoot = $Root
        # The engine stays silent while the cases run. -Quiet silences the harness's own lines as well (the apply gate).
        $script:WhQuiet = $true
        $script:WhTestQuiet = [bool]$Quiet
        $script:WhSkipAcl = $true
        $script:WhTestLog = New-Object 'System.Collections.Generic.List[object]'
        $script:WhTestTemp = $tmp
        $script:WhTestSeq = 0
        [void](New-Item -ItemType Directory -Path $tmp -Force)
        Use-WhProvider 'fake'
        Write-WhTestLine 'Self test (in-memory system, nothing on this computer is changed):'
        [void](Invoke-WhSelfTestCases)
    }
    catch {
        Add-WhTestResult -Name 'self test harness' -Ok $false -Detail $_.Exception.Message
    }
    finally {
        $script:WhProv = $saved.prov
        $script:WhStateDir = $saved.dir
        $script:WhSkipAcl = $saved.acl
        $script:WhQuiet = $saved.quiet
        $script:WhTestQuiet = $saved.testquiet
        $script:WhTestCurrent = ''
        $script:WhJournalTail = $saved.tail
        $script:WhJournalTrust = $saved.trust
        $script:WhRoot = $saved.root
        $leaf = Split-Path -Leaf $tmp
        if ((Test-Path -LiteralPath $tmp -PathType Container) -and $leaf.StartsWith('winharden-selftest-')) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $failed = @($script:WhTestLog | Where-Object { -not $_.ok })
    return [pscustomobject]@{ passed = ($script:WhTestLog.Count - $failed.Count); failed = $failed.Count; failures = $failed }
}
