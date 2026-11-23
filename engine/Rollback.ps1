# winharden engine: Rollback.ps1
# rollback --to <checkpoint>: puts every target that was journaled after the checkpoint back to the state it had at the
# checkpoint, newest record first. Restoring a recorded state is idempotent, so records of transactions that were
# already reverted are harmless. AppX removals cannot be undone by the engine; they are listed for the user.
# Windows PowerShell 5.1, ASCII only.

function Read-WhIdentState {
    param($Ident)
    $type = [string]$Ident.type
    if ($type -eq 'registry') {
        foreach ($t in @(Invoke-WhProv 'Targets' ([string]$Ident.scope))) {
            if ([string]$t.label -eq [string]$Ident.target) { return (Invoke-WhProv 'RegGet' $t ([string]$Ident.path) ([string]$Ident.name)) }
        }
        return $null
    }
    if ($type -eq 'service') { return (Invoke-WhProv 'ServiceGet' ([string]$Ident.name)) }
    if ($type -eq 'scheduled_task') { return (Invoke-WhProv 'TaskGet' ([string]$Ident.path) ([string]$Ident.name)) }
    if ($type -eq 'appx') { return (Invoke-WhProv 'AppxGet' ([string]$Ident.package)) }
    if ($type -eq 'optional_feature') { return (Invoke-WhProv 'FeatureGet' ([string]$Ident.name)) }
    if ($type -eq 'setting') { return (Invoke-WhProv 'SettingGet' ([string]$Ident.kind) ([string]$Ident.name)) }
    if ($type -eq 'file_cleanup') { return $null }
    return $null
}

function Resolve-WhCheckpoint {
    param($Journal, [string]$Name)
    $all = @(Get-WhCheckpoints -Journal $Journal)
    if ($all.Count -eq 0) { throw 'The journal has no checkpoints: nothing was applied by this engine on this machine.' }
    if ($Name -eq 'latest') { return $all[$all.Count - 1] }
    foreach ($c in $all) { if ([string]$c.data.name -ieq $Name) { return $c } }
    throw ('Unknown checkpoint ' + $Name + '. Known checkpoints: ' + ((@($all | ForEach-Object { [string]$_.data.name })) -join ', '))
}

function Invoke-WhRollback {
    param([string]$Checkpoint, [string]$RunId, [switch]$TrustJournal)
    $journal = Read-WhJournal
    if (($journal.problems.Count -gt 0) -and (-not $TrustJournal)) {
        throw ('The journal failed verification: ' + ($journal.problems -join ' ') + ' Use -TrustJournal only if you are sure nobody tampered with it.')
    }
    if ($TrustJournal) { $script:WhJournalTrust = $true }
    $cp = Resolve-WhCheckpoint -Journal $journal -Name $Checkpoint
    $cpSeq = [int]$cp.seq
    $befores = New-Object System.Collections.Generic.List[object]
    foreach ($r in $journal.records) {
        if (([string]$r.type -eq 'before') -and ([int]$r.seq -gt $cpSeq)) { $befores.Add($r) }
    }
    [void](Add-WhJournalRecord -RunId $RunId -Type 'rollback-begin' -Data ([ordered]@{ checkpoint = [string]$cp.data.name; records = $befores.Count }))
    $restored = 0
    $failed = New-Object System.Collections.Generic.List[string]
    $manual = New-Object System.Collections.Generic.List[string]
    $oldest = [ordered]@{}
    for ($n = $befores.Count - 1; $n -ge 0; $n--) {
        $b = $befores[$n]
        $ident = $b.data.ident
        $r = Restore-WhSlot -Ident $ident -Before $b.data.before
        if ($r.manual) { if ($manual -notcontains $r.message) { $manual.Add($r.message) } }
        elseif ($r.ok) { $restored++ }
        else { $failed.Add((ConvertTo-WhCanonical -Value $ident) + ': ' + $r.message) }
        $oldest[(ConvertTo-WhCanonical -Value $ident)] = $b
    }
    Invoke-WhProv 'ClearCaches'
    $mismatch = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($oldest.Keys)) {
        $b = $oldest[$k]
        $type = [string]$b.data.ident.type
        if (@('appx', 'file_cleanup') -contains $type) { continue }
        $now = Read-WhIdentState -Ident $b.data.ident
        if ($null -eq $now) { continue }
        if ((Get-WhStateKey -Type $type -State $now) -ne (Get-WhStateKey -Type $type -State $b.data.before)) { $mismatch.Add($k) }
    }
    [void](Add-WhJournalRecord -RunId $RunId -Type 'rollback-end' -Data ([ordered]@{
                checkpoint = [string]$cp.data.name; restored = $restored; failed = $failed.ToArray(); manual = $manual.ToArray(); mismatch = $mismatch.ToArray()
            }))
    return [pscustomobject]@{
        checkpoint = [string]$cp.data.name
        restored   = $restored
        failed     = $failed.ToArray()
        manual     = $manual.ToArray()
        mismatch   = $mismatch.ToArray()
        ok         = (($failed.Count -eq 0) -and ($mismatch.Count -eq 0))
    }
}
