# winharden engine: Manifest.ps1
# Loads manifests/*.json and re-checks, at runtime, what CI already checked (schema subset, never-touch, audit lint).
# A manifest set with any problem is refused as a whole: the engine never runs part of a broken set.
# Windows PowerShell 5.1, ASCII only.

$script:WhOpFields = @{
    registry         = @('hive', 'path', 'name', 'kind', 'data', 'scope')
    service          = @('name', 'startup', 'stop')
    scheduled_task   = @('path', 'name', 'state', 'if_missing')
    appx             = @('package_name', 'action', 'deprovision', 'all_users')
    optional_feature = @('name', 'state')
    setting          = @('kind', 'name', 'value')
    file_cleanup     = @('scope', 'root', 'pattern', 'min_age_days', 'recurse')
}
$script:WhRegistryKinds = @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString')
$script:WhServiceStartups = @('Disabled', 'Manual', 'Automatic', 'AutomaticDelayed')
$script:WhSettingKinds = @('defender_pref', 'defender_asr', 'audit_policy')

function Test-WhIsInteger {
    param($Value)
    return (($Value -is [int]) -or ($Value -is [long]))
}

function Test-WhRegistryDataFitsKind {
    param([string]$Kind, $Data)
    if ($Kind -eq 'DWord') { return ((Test-WhIsInteger -Value $Data) -and ([long]$Data -ge 0) -and ([long]$Data -le 4294967295)) }
    if ($Kind -eq 'QWord') { return ((Test-WhIsInteger -Value $Data) -and ([long]$Data -ge 0)) }
    if (($Kind -eq 'String') -or ($Kind -eq 'ExpandString')) { return ($Data -is [string]) }
    if ($Kind -eq 'MultiString') {
        if ($Data -is [string]) { return $false }
        foreach ($x in @($Data)) { if ($x -isnot [string]) { return $false } }
        return $true
    }
    return $false
}

function Get-WhOpProblems {
    # Structure and policy problems of one operation. Empty array = fine.
    param($Op, $Policy, [bool]$ServicingFlag, [int]$MinProfile)
    $p = New-Object System.Collections.Generic.List[string]
    $type = [string](Get-WhProp -Object $Op -Name 'type' -Default '')
    if (-not $script:WhOpFields.ContainsKey($type)) {
        $p.Add('unknown operation type ' + $type)
        return $p.ToArray()
    }
    foreach ($field in $script:WhOpFields[$type]) {
        if ($null -eq (Get-WhProp -Object $Op -Name $field)) { $p.Add($type + ' operation lacks field ' + $field) }
    }
    if ($p.Count -gt 0) { return $p.ToArray() }
    if ($type -eq 'registry') {
        $hive = [string]$Op.hive
        $scope = [string]$Op.scope
        if (-not ((($hive -eq 'HKLM') -and ($scope -eq 'machine')) -or (($hive -eq 'HKCU') -and ($scope -eq 'user')))) {
            $p.Add('hive ' + $hive + ' does not match scope ' + $scope)
        }
        if ($script:WhRegistryKinds -notcontains [string]$Op.kind) { $p.Add('unknown registry kind ' + $Op.kind) }
        elseif (-not (Test-WhRegistryDataFitsKind -Kind ([string]$Op.kind) -Data $Op.data)) { $p.Add('data does not fit kind ' + $Op.kind) }
        if ((Get-WhProp -Object $Op -Name 'merge') -eq 'hide-list') {
            if (($Op.kind -ne 'String') -or (-not (([string]$Op.data).StartsWith('hide:', [System.StringComparison]::OrdinalIgnoreCase)))) {
                $p.Add('merge hide-list needs kind String and data starting with hide:')
            }
        }
        $regPath = [string]$Op.path
        if (Test-WhHasWildcard -Text $regPath) {
            $cut = $regPath.LastIndexOf('\')
            if (($cut -lt 1) -or (Test-WhHasWildcard -Text $regPath.Substring(0, $cut)) -or (-not (Test-WhHasWildcard -Text $regPath.Substring($cut + 1))) -or $regPath.Contains('[') -or $regPath.Contains(']')) {
                $p.Add('a wildcard is allowed only in the last segment of the path, below a fixed parent key')
            }
            if ($null -ne (Get-WhProp -Object $Op -Name 'merge')) { $p.Add('merge cannot be combined with a wildcard path') }
        }
    }
    elseif ($type -eq 'service') {
        if ($script:WhServiceStartups -notcontains [string]$Op.startup) { $p.Add('unknown service startup ' + $Op.startup) }
    }
    elseif ($type -eq 'scheduled_task') {
        if ([string]$Op.state -ne 'Disabled') { $p.Add('scheduled task state must be Disabled') }
        if (@('skip', 'error') -notcontains [string]$Op.if_missing) { $p.Add('if_missing must be skip or error') }
    }
    elseif ($type -eq 'appx') {
        if ([string]$Op.action -ne 'remove') { $p.Add('appx action must be remove') }
        if (([string]$Op.package_name).Contains('*') -or ([string]$Op.package_name).Contains('?')) { $p.Add('appx package names must be exact (no wildcards)') }
    }
    elseif ($type -eq 'optional_feature') {
        if ([string]$Op.state -ne 'Disabled') { $p.Add('optional feature state must be Disabled') }
    }
    elseif ($type -eq 'setting') {
        if ($script:WhSettingKinds -notcontains [string]$Op.kind) { $p.Add('unknown setting kind ' + $Op.kind) }
        elseif ([string]$Op.kind -eq 'defender_pref') {
            if (($Op.value -isnot [bool]) -and (-not (Test-WhIsInteger -Value $Op.value))) { $p.Add('a Defender preference value must be an integer or a boolean') }
        }
        elseif ($Op.value -isnot [string]) { $p.Add('the value of ' + $Op.kind + ' must be a string') }
    }
    elseif ($type -eq 'file_cleanup') {
        if (@('machine', 'user') -notcontains [string]$Op.scope) { $p.Add('cleanup scope must be machine or user') }
        if (([string]$Op.pattern).Contains('\') -or ([string]$Op.pattern).Contains('/') -or ([string]$Op.pattern).Contains(':')) { $p.Add('the cleanup pattern is a file name, not a path') }
        if ((-not (Test-WhIsInteger -Value $Op.min_age_days)) -or ([long]$Op.min_age_days -lt 0) -or ([long]$Op.min_age_days -gt 3650)) { $p.Add('min_age_days must be an integer from 0 to 3650') }
        if ($Op.recurse -isnot [bool]) { $p.Add('recurse must be true or false') }
    }
    foreach ($v in @(Get-WhOpViolations -Op $Op -Policy $Policy)) { $p.Add('never-touch: ' + $v) }
    if ((Test-WhServicingAdjacent -Op $Op -Policy $Policy) -and (-not ($ServicingFlag -and ($MinProfile -eq 3)))) {
        $p.Add('servicing-adjacent target needs flags.servicing_adjacent and min_profile 3')
    }
    return $p.ToArray()
}

function Get-WhEntryProblems {
    param($Entry, $Policy)
    $p = New-Object System.Collections.Generic.List[string]
    foreach ($field in @('id', 'module', 'title', 'tier', 'min_profile', 'mode', 'rationale', 'impact', 'audit', 'rollback', 'risk', 'references', 'evidence')) {
        $v = Get-WhProp -Object $Entry -Name $field
        if (($null -eq $v) -or (($v -is [string]) -and ([string]::IsNullOrWhiteSpace($v))) -or (($v -is [System.Array]) -and ($v.Count -eq 0))) {
            $p.Add('missing or empty field ' + $field)
        }
    }
    if ($p.Count -gt 0) { return $p.ToArray() }
    $mode = [string]$Entry.mode
    $minProfile = Get-WhProp -Object $Entry -Name 'min_profile'
    if (@(1, 2, 3) -notcontains $minProfile) { $p.Add('min_profile must be 1, 2 or 3') }
    if (@('enforce', 'once', 'attest', 'manual') -notcontains $mode) { $p.Add('mode must be enforce, once, attest or manual') }
    $flags = Get-WhProp -Object $Entry -Name 'flags'
    $servicing = [bool](Get-WhProp -Object $flags -Name 'servicing_adjacent' -Default $false)
    $deletes = [bool](Get-WhProp -Object $flags -Name 'deletes_user_data' -Default $false)
    $ops = @(Get-WhProp -Object $Entry -Name 'apply' -Default @())
    $runs = (@('enforce', 'once') -contains $mode)
    if ($runs -and ($ops.Count -eq 0)) { $p.Add('mode ' + $mode + ' needs apply') }
    if ((-not $runs) -and ($ops.Count -gt 0)) { $p.Add('mode ' + $mode + ' must not have apply') }
    if ($deletes -and (-not $runs)) { $p.Add('deletes_user_data only makes sense for mode enforce or once') }
    $cleanupOps = @($ops | Where-Object { [string](Get-WhProp -Object $_ -Name 'type' -Default '') -eq 'file_cleanup' }).Count
    if (($mode -eq 'once') -and ($cleanupOps -ne $ops.Count)) { $p.Add('mode once is only for entries whose operations are all file_cleanup') }
    if (($mode -ne 'once') -and ($cleanupOps -gt 0)) { $p.Add('file_cleanup operations need mode once') }
    if (($mode -eq 'once') -and ([string](Get-WhProp -Object (Get-WhProp -Object $Entry -Name 'rollback') -Name 'reversibility' -Default '') -ne 'partial')) {
        $p.Add('a one-time cleanup cannot be reversed: reversibility must be partial')
    }
    $audit = $Entry.audit
    $checks = @(Get-WhProp -Object $audit -Name 'checks' -Default @())
    if ((@('enforce', 'attest') -contains $mode) -and ($checks.Count -eq 0)) { $p.Add('mode ' + $mode + ' needs audit.checks') }
    if (($mode -eq 'once') -and ($checks.Count -eq 0) -and [string]::IsNullOrWhiteSpace([string](Get-WhProp -Object $audit -Name 'manual_check' -Default ''))) {
        $p.Add('mode once needs audit.checks or audit.manual_check')
    }
    if (($mode -eq 'manual') -and [string]::IsNullOrWhiteSpace([string](Get-WhProp -Object $audit -Name 'manual_check' -Default ''))) {
        $p.Add('mode manual needs audit.manual_check')
    }
    $i = 0
    foreach ($check in $checks) {
        foreach ($reason in @(Get-WhAuditLintReasons -Command ([string](Get-WhProp -Object $check -Name 'command' -Default '')))) {
            $p.Add('audit.checks[' + $i + ']: ' + $reason)
        }
        if ([string]::IsNullOrEmpty([string](Get-WhProp -Object $check -Name 'expected' -Default ''))) { $p.Add('audit.checks[' + $i + '] has no expected value') }
        $i++
    }
    $i = 0
    foreach ($op in $ops) {
        foreach ($reason in @(Get-WhOpProblems -Op $op -Policy $Policy -ServicingFlag $servicing -MinProfile ([int]$minProfile))) {
            $p.Add('apply[' + $i + ']: ' + $reason)
        }
        $i++
    }
    return $p.ToArray()
}

function Import-WhManifests {
    # Returns { entries, files (name -> sha256), hash, errors }. A non-empty errors list means: do not use.
    param([string]$Directory, $Policy)
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { throw ('The manifests folder is missing: ' + $Directory) }
    $files = @(Get-ChildItem -LiteralPath $Directory -Filter '*.json' -File | Sort-Object -Property Name)
    if ($files.Count -eq 0) { throw ('No manifest files in ' + $Directory) }
    $entries = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    $hashes = [ordered]@{}
    $seen = @{}
    foreach ($f in $files) {
        $hashes[$f.Name] = Get-WhSha256File -Path $f.FullName
        $doc = $null
        try { $doc = ConvertFrom-WhJson -Text (Read-WhFile -Path $f.FullName) }
        catch {
            $errors.Add($f.Name + ': not valid JSON: ' + $_.Exception.Message)
            continue
        }
        if (($null -eq (Get-WhProp -Object $doc -Name 'entries')) -or ((Get-WhProp -Object $doc -Name 'schema_version') -ne 1)) {
            $errors.Add($f.Name + ': not a schema_version 1 manifest file')
            continue
        }
        foreach ($e in @($doc.entries)) {
            $id = [string](Get-WhProp -Object $e -Name 'id' -Default '<no id>')
            if ($seen.ContainsKey($id)) { $errors.Add($f.Name + ' ' + $id + ': duplicate id (first in ' + $seen[$id] + ')') }
            $seen[$id] = $f.Name
            foreach ($problem in @(Get-WhEntryProblems -Entry $e -Policy $Policy)) { $errors.Add($f.Name + ' ' + $id + ': ' + $problem) }
            $entries.Add($e)
        }
    }
    $lines = @($hashes.Keys | ForEach-Object { $_ + ':' + $hashes[$_] })
    return [pscustomobject]@{
        entries = $entries.ToArray()
        files   = $hashes
        hash    = (Get-WhSha256String -Text ($lines -join "`n"))
        errors  = $errors.ToArray()
    }
}

function Select-WhEntries {
    # Level N takes every entry with min_profile <= N. Exclude and Only hold id patterns (-like).
    # An entry with an opt_in name is left out unless that name is in OptIn; it is returned in .optional so the plan can say so.
    param($Entries, [int]$Level, [string[]]$Exclude = @(), [string[]]$Only = @(), [string[]]$OptIn = @())
    $selected = New-Object System.Collections.Generic.List[object]
    $excluded = New-Object System.Collections.Generic.List[object]
    $optional = New-Object System.Collections.Generic.List[object]
    $wanted = @($Only | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $optedIn = @($OptIn | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    foreach ($e in @($Entries)) {
        if ([int]$e.min_profile -gt $Level) { continue }
        if ($wanted.Count -gt 0) {
            $match = $false
            foreach ($pattern in $wanted) { if ([string]$e.id -like $pattern) { $match = $true } }
            if (-not $match) { continue }
        }
        $gate = [string](Get-WhProp -Object $e -Name 'opt_in' -Default '')
        if (($gate -ne '') -and ($optedIn -notcontains $gate)) {
            $optional.Add($e)
            continue
        }
        $hit = $false
        foreach ($pattern in @($Exclude)) {
            if ((-not [string]::IsNullOrWhiteSpace($pattern)) -and ([string]$e.id -like $pattern)) { $hit = $true }
        }
        if ($hit) { $excluded.Add($e) } else { $selected.Add($e) }
    }
    return [pscustomobject]@{ selected = $selected.ToArray(); excluded = $excluded.ToArray(); optional = $optional.ToArray() }
}
