# winharden engine: Journal.ps1
# Append-only state journal. Every record carries an HMAC-SHA256 over its own content and the MAC of the previous
# record, so deleting, reordering or editing a line is detected. The key lives next to the journal in a folder that
# only SYSTEM and Administrators can write. This is tamper-EVIDENCE against anything that is not an administrator;
# an administrator can rewrite both key and journal, and the threat model says so.
# Windows PowerShell 5.1, ASCII only.

$script:WhJournalTail = $null
$script:WhJournalTrust = $false
$script:WhMutex = $null
$script:WhZeroMac = ('0' * 64)

function Get-WhJournalDirectory { return (Join-Path (Get-WhStateDir) 'journal') }
function Get-WhJournalPath { return (Join-Path (Get-WhJournalDirectory) 'journal.jsonl') }

function Enter-WhLock {
    # One engine run at a time per machine.
    $m = New-Object System.Threading.Mutex($false, 'Global\winharden-engine')
    $got = $false
    try { $got = $m.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $got = $true }
    if (-not $got) {
        $m.Dispose()
        throw 'Another winharden run is in progress on this machine.'
    }
    $script:WhMutex = $m
}

function Exit-WhLock {
    if ($null -eq $script:WhMutex) { return }
    try { $script:WhMutex.ReleaseMutex() } catch { Write-WhLog -Level 'warn' -EventName 'lock-release' -Data $_.Exception.Message }
    $script:WhMutex.Dispose()
    $script:WhMutex = $null
}

function Get-WhJournalKey {
    # Returns the HMAC key; creates it on first use. With -MustExist, a missing key is an error (verification case).
    param([switch]$MustExist)
    $dir = Get-WhJournalDirectory
    $keyPath = Join-Path $dir 'journal.key'
    if (Test-Path -LiteralPath $keyPath -PathType Leaf) {
        return [System.Convert]::FromBase64String((Read-WhFile -Path $keyPath).Trim())
    }
    if ($MustExist) { return $null }
    [void](Initialize-WhDirectory -Path $dir -Protect)
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    Write-WhFile -Path $keyPath -Text ([System.Convert]::ToBase64String($bytes))
    return $bytes
}

function Get-WhRecordMac {
    param([byte[]]$Key, [string]$Prev, $Record)
    $text = $Prev + '|' + [string]$Record.seq + '|' + [string]$Record.ts + '|' + [string]$Record.run + '|' + [string]$Record.type + '|' + (ConvertTo-WhCanonical -Value $Record.data)
    $h = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try { $mac = $h.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) } finally { $h.Dispose() }
    return ([System.BitConverter]::ToString($mac).Replace('-', '').ToLowerInvariant())
}

function Read-WhJournal {
    # Returns { records, problems }. A non-empty problems list means the journal cannot be trusted.
    $path = Get-WhJournalPath
    $records = New-Object System.Collections.Generic.List[object]
    $problems = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{ records = @(); problems = @() }
    }
    $key = Get-WhJournalKey -MustExist
    if ($null -eq $key) { $problems.Add('The journal key is missing, so the journal cannot be verified.') }
    $prev = $script:WhZeroMac
    $n = 0
    foreach ($line in [System.IO.File]::ReadAllLines($path, $script:WhUtf8)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $n++
        $r = $null
        try { $r = ConvertFrom-WhJson -Text $line }
        catch { $problems.Add('Record ' + $n + ' is not valid JSON.'); continue }
        if ([int]$r.seq -ne $n) { $problems.Add('Record ' + $n + ' has sequence number ' + $r.seq + ' (a record was removed, added or reordered).') }
        if ([string]$r.prev -ne $prev) { $problems.Add('Record ' + $n + ' does not follow the previous record (chain broken).') }
        if ($null -ne $key) {
            if ((Get-WhRecordMac -Key $key -Prev ([string]$r.prev) -Record $r) -ne [string]$r.mac) { $problems.Add('Record ' + $n + ' was modified (MAC mismatch).') }
        }
        $prev = [string]$r.mac
        $records.Add($r)
    }
    return [pscustomobject]@{ records = $records.ToArray(); problems = $problems.ToArray() }
}

function Add-WhJournalRecord {
    # Write-ahead: the record is on disk (flushed) before the caller does what the record describes.
    param([string]$RunId, [string]$Type, $Data)
    $dir = Get-WhJournalDirectory
    [void](Initialize-WhDirectory -Path $dir -Protect)
    $key = Get-WhJournalKey -MustExist
    if ($null -eq $key) {
        if ((Test-Path -LiteralPath (Get-WhJournalPath) -PathType Leaf) -and (-not $script:WhJournalTrust)) {
            throw 'The journal exists but its key is missing. Refusing to start a new key over an unverifiable journal.'
        }
        $key = Get-WhJournalKey
    }
    if ($null -eq $script:WhJournalTail) {
        $existing = Read-WhJournal
        if (($existing.problems.Count -gt 0) -and (-not $script:WhJournalTrust)) { throw ('The journal failed verification: ' + $existing.problems[0] + ' Refusing to append to it.') }
        $tail = @{ seq = 0; mac = $script:WhZeroMac }
        if ($existing.records.Count -gt 0) {
            $last = $existing.records[$existing.records.Count - 1]
            $tail = @{ seq = [int]$last.seq; mac = [string]$last.mac }
        }
        $script:WhJournalTail = $tail
    }
    $rec = [ordered]@{
        seq  = ($script:WhJournalTail.seq + 1)
        ts   = (Get-WhUtcStamp)
        run  = $RunId
        type = $Type
        prev = $script:WhJournalTail.mac
        data = $Data
    }
    $rec['mac'] = Get-WhRecordMac -Key $key -Prev ([string]$rec.prev) -Record $rec
    Add-WhFileLine -Path (Get-WhJournalPath) -Line (ConvertTo-WhJson -Object $rec -Depth 12)
    $script:WhJournalTail = @{ seq = [int]$rec.seq; mac = [string]$rec.mac }
    return $rec
}

function Reset-WhJournalCache {
    $script:WhJournalTail = $null
    $script:WhJournalTrust = $false
}

function New-WhCheckpoint {
    param([string]$RunId, [string]$Name, $Data)
    $d = [ordered]@{ name = $Name }
    foreach ($k in @($Data.Keys)) { $d[$k] = $Data[$k] }
    return (Add-WhJournalRecord -RunId $RunId -Type 'checkpoint' -Data $d)
}

function Get-WhCheckpoints {
    param($Journal)
    return @($Journal.records | Where-Object { $_.type -eq 'checkpoint' })
}
