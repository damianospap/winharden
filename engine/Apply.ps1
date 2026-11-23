# winharden engine: Apply.ps1
# Applies a plan. Each entry is one transaction group: its before-states are journaled (write-ahead) one target at a
# time, every change is read back, and any failure puts every already-changed target of that entry back from the
# journal before the next entry starts. Restore-WhSlot is shared with rollback.
# Windows PowerShell 5.1, ASCII only.

function Invoke-WhSlotApply {
    param($Item, $Warnings, $Notes)
    $op = $Item.op
    $slot = $Item.slot
    $ident = $slot.ident
    $type = [string]$ident.type
    if ($type -eq 'registry') {
        Invoke-WhProv 'RegSet' $slot.target ([string]$ident.path) ([string]$ident.name) ([string]$op.kind) $Item.data
    }
    elseif ($type -eq 'service') {
        $name = [string]$ident.name
        if ([string](Get-WhProp -Object $Item.before -Name 'startup') -ne [string]$op.startup) {
            Invoke-WhProv 'ServiceStartup' $name ([string]$op.startup)
        }
        $running = (@('Running', 'StartPending', 'ContinuePending') -contains [string](Get-WhProp -Object $Item.before -Name 'status'))
        if ([bool]$op.stop -and $running) {
            try { Invoke-WhProv 'ServiceRunning' $name $false }
            catch {
                $Warnings.Add('Service ' + $name + ' could not be stopped now (' + $_.Exception.Message + '). It is disabled and will stay stopped after the next restart.')
            }
        }
    }
    elseif ($type -eq 'scheduled_task') {
        Invoke-WhProv 'TaskEnabled' ([string]$ident.path) ([string]$ident.name) $false
    }
    elseif ($type -eq 'appx') {
        Invoke-WhProv 'AppxRemove' ([string]$ident.package) ([bool]$op.deprovision) ([bool]$op.all_users)
    }
    elseif ($type -eq 'optional_feature') {
        Invoke-WhProv 'FeatureEnabled' ([string]$ident.name) $false
    }
    elseif ($type -eq 'setting') {
        Invoke-WhProv 'SettingSet' ([string]$ident.kind) ([string]$ident.name) ([string]$Item.data)
    }
    elseif ($type -eq 'file_cleanup') {
        $r = Invoke-WhProv 'CleanRun' ([string]$ident.dir) ([string]$ident.pattern) ([int]$ident.min_age_days) ([bool]$ident.recurse)
        $mb = [Math]::Round(([double]$r.bytes) / 1048576, 1)
        $Notes.Add('Deleted ' + [string]$r.deleted + ' files (' + [string]$mb + ' MB) in ' + [string]$ident.dir + '.')
        if ([int]$r.failed -gt 0) {
            $Warnings.Add([string]$r.failed + ' items in ' + [string]$ident.dir + ' could not be deleted (in use or no access) and were left.')
        }
    }
    else { throw ('Unknown target type ' + $type) }
}

function New-WhRestoreResult {
    param([bool]$Ok, [bool]$Manual, [string]$Message)
    return [pscustomobject]@{ ok = $Ok; manual = $Manual; message = $Message }
}

function Restore-WhSlot {
    # Puts one target back to the state saved in the journal. Never throws: the result says what happened.
    param($Ident, $Before)
    $type = [string]$Ident.type
    try {
        if ($type -eq 'registry') {
            $target = $null
            foreach ($t in @(Invoke-WhProv 'Targets' ([string]$Ident.scope))) {
                if ([string]$t.label -eq [string]$Ident.target) { $target = $t }
            }
            if ($null -eq $target) { return (New-WhRestoreResult -Ok $true -Manual $false -Message ('Skipped: the target ' + $Ident.target + ' no longer exists.')) }
            if ([bool](Get-WhProp -Object $Before -Name 'exists' -Default $false)) {
                Invoke-WhProv 'RegSet' $target ([string]$Ident.path) ([string]$Ident.name) ([string]$Before.kind) $Before.data
            }
            else {
                Invoke-WhProv 'RegRemove' $target ([string]$Ident.path) ([string]$Ident.name) (-not [bool](Get-WhProp -Object $Before -Name 'key_exists' -Default $true))
            }
            return (New-WhRestoreResult -Ok $true -Manual $false -Message 'Restored.')
        }
        if ($type -eq 'service') {
            $name = [string]$Ident.name
            if (-not [bool](Get-WhProp -Object $Before -Name 'exists' -Default $false)) { return (New-WhRestoreResult -Ok $true -Manual $false -Message 'The service did not exist before.') }
            $now = Invoke-WhProv 'ServiceGet' $name
            if (-not [bool](Get-WhProp -Object $now -Name 'exists' -Default $false)) { return (New-WhRestoreResult -Ok $true -Manual $false -Message 'Skipped: the service is gone.') }
            $startup = [string](Get-WhProp -Object $Before -Name 'startup')
            if ($startup -ne [string](Get-WhProp -Object $now -Name 'startup')) { Invoke-WhProv 'ServiceStartup' $name $startup }
            $message = 'Restored.'
            $wasRunning = ([string](Get-WhProp -Object $Before -Name 'status') -eq 'Running')
            if ($wasRunning -and ($startup -ne 'Disabled') -and ([string](Get-WhProp -Object $now -Name 'status') -ne 'Running')) {
                try { Invoke-WhProv 'ServiceRunning' $name $true }
                catch { $message = 'Startup type restored. The service was running before and could not be started now: ' + $_.Exception.Message }
            }
            return (New-WhRestoreResult -Ok $true -Manual $false -Message $message)
        }
        if ($type -eq 'scheduled_task') {
            if (-not [bool](Get-WhProp -Object $Before -Name 'exists' -Default $false)) { return (New-WhRestoreResult -Ok $true -Manual $false -Message 'The task did not exist before.') }
            $enable = ([string](Get-WhProp -Object $Before -Name 'state') -ne 'Disabled')
            Invoke-WhProv 'TaskEnabled' ([string]$Ident.path) ([string]$Ident.name) $enable
            return (New-WhRestoreResult -Ok $true -Manual $false -Message 'Restored.')
        }
        if ($type -eq 'optional_feature') {
            if (-not [bool](Get-WhProp -Object $Before -Name 'exists' -Default $false)) { return (New-WhRestoreResult -Ok $true -Manual $false -Message 'The feature did not exist before.') }
            $was = [string](Get-WhProp -Object $Before -Name 'state')
            $enable = ($was -eq 'Enabled')
            Invoke-WhProv 'FeatureEnabled' ([string]$Ident.name) $enable
            return (New-WhRestoreResult -Ok $true -Manual $false -Message 'Restored.')
        }
        if ($type -eq 'setting') {
            if ([bool](Get-WhProp -Object $Before -Name 'exists' -Default $false)) {
                Invoke-WhProv 'SettingSet' ([string]$Ident.kind) ([string]$Ident.name) ([string](Get-WhProp -Object $Before -Name 'value' -Default ''))
            }
            else {
                Invoke-WhProv 'SettingClear' ([string]$Ident.kind) ([string]$Ident.name)
            }
            return (New-WhRestoreResult -Ok $true -Manual $false -Message 'Restored.')
        }
        if ($type -eq 'file_cleanup') {
            return (New-WhRestoreResult -Ok $true -Manual $true -Message 'Files deleted by a cleanup are not restored by rollback. Windows and the apps recreate caches, temporary files and logs.')
        }
        if ($type -eq 'appx') {
            $names = (@(Get-WhProp -Object $Before -Name 'installed' -Default @()) + @(Get-WhProp -Object $Before -Name 'provisioned' -Default @())) -join ', '
            return (New-WhRestoreResult -Ok $true -Manual $true -Message ('Reinstall ' + $Ident.package + ' from the Microsoft Store by hand (it had: ' + $names + '). Its local data cannot be restored.'))
        }
        return (New-WhRestoreResult -Ok $false -Manual $false -Message ('Unknown target type ' + $type))
    }
    catch {
        return (New-WhRestoreResult -Ok $false -Manual $false -Message $_.Exception.Message)
    }
}

function Invoke-WhEntryApply {
    param($PlanEntry, [string]$RunId)
    $txn = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $id = [string]$PlanEntry.id
    $journaled = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $failure = $null
    try {
        [void](Add-WhJournalRecord -RunId $RunId -Type 'txn-begin' -Data ([ordered]@{ txn = $txn; entry = $id }))
        foreach ($item in @($PlanEntry.items)) {
            if ([string]$item.status -ne 'change') { continue }
            # A cleanup has no state to compare or read back: the folder changes all the time and files in use stay.
            $volatile = ([string]$item.op_type -eq 'file_cleanup')
            if (-not $volatile) {
                $now = Read-WhSlotState -Slot $item.slot
                if ((Get-WhStateKey -Type $item.op_type -State $now) -ne (Get-WhStateKey -Type $item.op_type -State $item.before)) {
                    throw ('The state of ' + $item.label + ' changed after the plan was made. Nothing was changed for this entry; plan again.')
                }
            }
            [void](Add-WhJournalRecord -RunId $RunId -Type 'before' -Data ([ordered]@{ txn = $txn; entry = $id; ident = $item.ident; before = $item.before }))
            $journaled.Add($item)
            Invoke-WhSlotApply -Item $item -Warnings $warnings -Notes $notes
            Invoke-WhProv 'ClearCaches'
            if (-not $volatile) {
                $after = Read-WhSlotState -Slot $item.slot
                $verdict = Get-WhSlotVerdict -Op $item.op -State $after -AfterApply
                if ([string]$verdict.status -ne 'ok') {
                    throw ('Read-back of ' + $item.label + ' does not show the desired state (' + (Format-WhState -Type $item.op_type -State $after) + ').')
                }
            }
        }
        [void](Add-WhJournalRecord -RunId $RunId -Type 'txn-commit' -Data ([ordered]@{ txn = $txn; entry = $id; notes = $notes.ToArray() }))
    }
    catch {
        $failure = $_.Exception.Message
    }
    if ($null -eq $failure) {
        return [pscustomobject]@{ entry = $id; ok = $true; error = ''; warnings = $warnings.ToArray(); notes = $notes.ToArray(); reverted = @(); manual = @() }
    }
    $reverted = New-Object System.Collections.Generic.List[string]
    $manual = New-Object System.Collections.Generic.List[string]
    for ($n = $journaled.Count - 1; $n -ge 0; $n--) {
        $item = $journaled[$n]
        $r = Restore-WhSlot -Ident $item.ident -Before $item.before
        if ($r.manual) { $manual.Add($r.message) }
        elseif ($r.ok) { $reverted.Add($item.label) }
        else { $manual.Add('Could not restore ' + $item.label + ': ' + $r.message) }
    }
    Invoke-WhProv 'ClearCaches'
    try {
        [void](Add-WhJournalRecord -RunId $RunId -Type 'txn-revert' -Data ([ordered]@{ txn = $txn; entry = $id; reason = $failure; restored = $reverted.ToArray(); manual = $manual.ToArray() }))
    }
    catch {
        $manual.Add('The revert could not be journaled: ' + $_.Exception.Message)
    }
    return [pscustomobject]@{ entry = $id; ok = $false; error = $failure; warnings = $warnings.ToArray(); notes = @(); reverted = $reverted.ToArray(); manual = $manual.ToArray() }
}

function New-WhRestorePoint {
    # Best effort and never required: the journal is the rollback mechanism. Windows allows one restore point per day
    # by default; the engine does not change that setting.
    param([string]$Description)
    if ([object]::ReferenceEquals($script:WhProv, $script:WhFakeProvider)) { return [pscustomobject]@{ created = $false; message = 'skipped (test provider)' } }
    try {
        $warn = $null
        Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop -WarningVariable warn -WarningAction SilentlyContinue
        if (($null -ne $warn) -and (@($warn).Count -gt 0)) { return [pscustomobject]@{ created = $false; message = ([string]@($warn)[0]) } }
        return [pscustomobject]@{ created = $true; message = 'created' }
    }
    catch {
        return [pscustomobject]@{ created = $false; message = $_.Exception.Message }
    }
}

function Invoke-WhApply {
    # The caller holds the lock, has run preflight and has shown the plan to the user.
    param($Plan, [string]$RunId, [string]$Label, $RestorePoint)
    $summary = Get-WhPlanSummary -Plan $Plan
    $checkpoint = New-WhCheckpoint -RunId $RunId -Name ('cp-' + $RunId) -Data ([ordered]@{
            label         = $Label
            plan          = [string]$Plan.id
            level         = [int]$Plan.level
            manifest_hash = [string]$Plan.manifest_hash
            engine        = [string]$Plan.engine
            entries       = [int]$summary.entries_change
            restore_point = $RestorePoint
        })
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Plan.entries)) {
        if ([string]$e.status -ne 'change') { continue }
        $r = Invoke-WhEntryApply -PlanEntry $e -RunId $RunId
        $results.Add($r)
        if ($r.ok) { Write-WhLine ('  applied   ' + $r.entry) }
        else { Write-WhLine ('  FAILED    ' + $r.entry + ': ' + $r.error + ' (reverted)') 'Yellow' }
        foreach ($n in @($r.notes)) { Write-WhLine ('            ' + $n) }
        foreach ($w in @($r.warnings)) { Write-WhLine ('            ' + $w) 'Yellow' }
        Write-WhLog -Level 'info' -EventName 'entry-applied' -Data ([ordered]@{ entry = $r.entry; ok = $r.ok; error = $r.error })
    }
    return [pscustomobject]@{
        checkpoint = [string]$checkpoint.data.name
        results    = $results.ToArray()
        applied    = @($results | Where-Object { $_.ok }).Count
        failed     = @($results | Where-Object { -not $_.ok }).Count
    }
}
