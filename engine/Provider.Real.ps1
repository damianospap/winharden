# winharden engine: Provider.Real.ps1
# The only file that touches the real system: registry, services, scheduled tasks, AppX, optional features,
# user hives and the audit runspace. Everything else talks to a provider through the table in Provider.ps1,
# so the same engine code runs against the fake provider in `winharden.ps1 selftest`.
# Windows PowerShell 5.1, ASCII only. Every function here takes positional arguments (the dispatcher uses splatting).

$script:WhUserTargets = $null
$script:WhLoadedHives = New-Object 'System.Collections.Generic.List[string]'
$script:WhAppxInstalled = $null
$script:WhAppxProvisioned = $null
$script:WhFeatureCache = $null
$script:WhAuditRunspace = $null
$script:WhAuditRunspaceFull = $null
$script:WhAsrText =@{ 0 = 'disabled'; 1 = 'block'; 2 = 'audit'; 6 = 'warn' }
$script:WhAsrAction = @{ disabled = 'Disabled'; block = 'Enabled'; audit = 'AuditMode'; warn = 'Warn' }
$script:WhAuditText = @{ 0 = 'none'; 1 = 'success'; 2 = 'failure'; 3 = 'success_failure' }
$script:WhAuditFlags = @{ none = @('disable', 'disable'); success = @('enable', 'disable'); failure = @('disable', 'enable'); success_failure = @('enable', 'enable') }

function Get-WhRealMachineTarget {
    return [pscustomobject]@{ label = 'HKLM'; scope = 'machine'; hive = 'LocalMachine'; prefix = '' }
}

function Open-WhRealKey {
    # Always the 64-bit registry view: a 32-bit PowerShell on 64-bit Windows would be redirected to Wow6432Node.
    param($Target, [string]$Path, [bool]$Writable, [bool]$Create)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]$Target.hive, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $full = [string]$Target.prefix + $Path
        if ($Create) { return $base.CreateSubKey($full) }
        return $base.OpenSubKey($full, $Writable)
    }
    finally {
        $base.Close()
    }
}

function Invoke-WhNative {
    # Runs a native tool from System32 and returns { ok, text }. Used for reg.exe load/unload, sc.exe config and auditpol.exe.
    param([string]$Tool, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $exe = Join-Path ([Environment]::GetFolderPath('System')) $Tool
    $text = ((& $exe @Arguments 2>&1) | Out-String).Trim()
    return [pscustomobject]@{ ok = ($LASTEXITCODE -eq 0); text = $text }
}

# ---------------------------------------------------------------------------
# Registry and user hives
# ---------------------------------------------------------------------------
function ConvertTo-WhRegState {
    param($Kind, $Raw)
    $k = [string]$Kind
    $s = [ordered]@{ key_exists = $true; exists = $true; kind = $k }
    if ($k -eq 'DWord') { $s['data'] = [int64](ConvertTo-WhUInt64 -Value $Raw) }
    elseif ($k -eq 'QWord') { $s['data'] = [string](ConvertTo-WhUInt64 -Value $Raw) }
    elseif (($k -eq 'String') -or ($k -eq 'ExpandString')) { $s['data'] = [string]$Raw }
    elseif ($k -eq 'MultiString') { $s['data'] = [string[]]@($Raw) }
    elseif ($k -eq 'Binary') { $s['data'] = ([System.BitConverter]::ToString([byte[]]$Raw)).Replace('-', '') }
    else { $s['kind'] = 'Other'; $s['other_kind'] = $k; $s['data'] = '' }
    return $s
}

function Get-WhRealRegState {
    param($Target, [string]$Path, [string]$Name)
    $key = Open-WhRealKey -Target $Target -Path $Path -Writable $false -Create $false
    if ($null -eq $key) { return [ordered]@{ key_exists = $false; exists = $false } }
    try {
        $actual = $null
        foreach ($n in $key.GetValueNames()) {
            if ($n -ieq $Name) { $actual = $n; break }
        }
        if ($null -eq $actual) { return [ordered]@{ key_exists = $true; exists = $false } }
        $kind = $key.GetValueKind($actual)
        $raw = $key.GetValue($actual, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return (ConvertTo-WhRegState -Kind $kind -Raw $raw)
    }
    finally {
        $key.Close()
    }
}

function ConvertTo-WhRegData {
    # Manifest or journal data -> the .NET object RegistryKey.SetValue expects.
    param([string]$Kind, $Data)
    if ($Kind -eq 'DWord') { return (ConvertTo-WhDWord -Value $Data) }
    if ($Kind -eq 'QWord') { return (ConvertTo-WhQWord -Value ([uint64]([string]$Data))) }
    if ($Kind -eq 'MultiString') { return , ([string[]]@($Data)) }
    if ($Kind -eq 'Binary') {
        $hex = [string]$Data
        $bytes = New-Object byte[] ([int]($hex.Length / 2))
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [System.Convert]::ToByte($hex.Substring(2 * $i, 2), 16) }
        return , $bytes
    }
    return [string]$Data
}

function Set-WhRealRegValue {
    param($Target, [string]$Path, [string]$Name, [string]$Kind, $Data)
    $key = Open-WhRealKey -Target $Target -Path $Path -Writable $true -Create $true
    if ($null -eq $key) { throw ('Cannot open or create ' + $Target.label + '\' + $Path) }
    try {
        $key.SetValue($Name, (ConvertTo-WhRegData -Kind $Kind -Data $Data), [Microsoft.Win32.RegistryValueKind]$Kind)
    }
    finally {
        $key.Close()
    }
}

function Remove-WhRealRegValue {
    # Deletes one value. With RemoveEmptyKey, also removes the leaf key when it is left with no values and no subkeys.
    param($Target, [string]$Path, [string]$Name, [bool]$RemoveEmptyKey)
    $key = Open-WhRealKey -Target $Target -Path $Path -Writable $true -Create $false
    if ($null -eq $key) { return }
    try { $key.DeleteValue($Name, $false) } finally { $key.Close() }
    if (-not $RemoveEmptyKey) { return }
    $cut = $Path.LastIndexOf('\')
    if ($cut -lt 1) { return }
    $leaf = $Path.Substring($cut + 1)
    $parent = Open-WhRealKey -Target $Target -Path $Path.Substring(0, $cut) -Writable $true -Create $false
    if ($null -eq $parent) { return }
    try {
        $sub = $parent.OpenSubKey($leaf, $false)
        if ($null -eq $sub) { return }
        $empty = $false
        try { $empty = (($sub.ValueCount -eq 0) -and ($sub.SubKeyCount -eq 0)) } finally { $sub.Close() }
        if ($empty) { $parent.DeleteSubKey($leaf, $false) }
    }
    finally {
        $parent.Close()
    }
}

function Get-WhRealRegSubKeys {
    param($Target, [string]$Path)
    $key = Open-WhRealKey -Target $Target -Path $Path -Writable $false -Create $false
    if ($null -eq $key) { return @() }
    try { return @($key.GetSubKeyNames() | Sort-Object) } finally { $key.Close() }
}

function Get-WhRealProfileDirectory {
    param($ProfileListKey, [string]$ValueName)
    $dir = $ProfileListKey.GetValue($ValueName)
    if ($null -eq $dir) { return $null }
    return [string]$dir
}

function Open-WhRealUserHives {
    # One target per existing user profile plus the Default user. Hives of users who are not signed in are
    # loaded under HKU\winharden-<name> and unloaded again by Stop-WhRealSession.
    $list = New-Object System.Collections.Generic.List[object]
    $listKey = Open-WhRealKey -Target (Get-WhRealMachineTarget) -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Writable $false -Create $false
    if ($null -eq $listKey) { throw 'The ProfileList registry key is missing, so user profiles cannot be enumerated.' }
    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $wanted = New-Object System.Collections.Generic.List[object]
        foreach ($sid in $listKey.GetSubKeyNames()) {
            if ($sid -notmatch '^S-1-(5-21|12-1)-[0-9-]+$') { continue }
            $sub = $listKey.OpenSubKey($sid)
            $dir = $null
            if ($null -ne $sub) { try { $dir = [string]$sub.GetValue('ProfileImagePath') } finally { $sub.Close() } }
            $wanted.Add([pscustomobject]@{ label = $sid; dir = $dir; hive = $sid })
        }
        $wanted.Add([pscustomobject]@{ label = 'DEFAULT'; dir = (Get-WhRealProfileDirectory -ProfileListKey $listKey -ValueName 'Default'); hive = 'winharden-default' })
        foreach ($w in $wanted) {
            $open = $users.OpenSubKey($w.hive)
            if ($null -ne $open) {
                $open.Close()
                $list.Add([pscustomobject]@{ label = $w.label; scope = 'user'; hive = 'Users'; prefix = ($w.hive + '\') })
                continue
            }
            if ([string]::IsNullOrWhiteSpace($w.dir)) { Write-WhLog -Level 'warn' -EventName 'hive-skipped' -Data @{ label = $w.label; reason = 'no profile path' }; continue }
            $file = Join-Path $w.dir 'NTUSER.DAT'
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Write-WhLog -Level 'warn' -EventName 'hive-skipped' -Data @{ label = $w.label; reason = 'no NTUSER.DAT' }; continue }
            $hiveName = $w.hive
            if ($hiveName -notlike 'winharden-*') { $hiveName = 'winharden-' + $w.hive }
            $r = Invoke-WhNative -Tool 'reg.exe' -Arguments @('load', ('HKU\' + $hiveName), $file)
            if (-not $r.ok) { Write-WhLog -Level 'warn' -EventName 'hive-load-failed' -Data @{ label = $w.label; text = $r.text }; continue }
            $script:WhLoadedHives.Add($hiveName)
            $list.Add([pscustomobject]@{ label = $w.label; scope = 'user'; hive = 'Users'; prefix = ($hiveName + '\') })
        }
    }
    finally {
        $users.Close()
        $listKey.Close()
    }
    return $list.ToArray()
}

function Get-WhRealTargets {
    param([string]$Scope)
    if ($Scope -eq 'machine') { return (Get-WhRealMachineTarget) }
    if ($null -eq $script:WhUserTargets) { $script:WhUserTargets = @(Open-WhRealUserHives) }
    return $script:WhUserTargets
}

function Start-WhRealSession {
    $script:WhAppxInstalled = $null
    $script:WhAppxProvisioned = $null
    $script:WhFeatureCache = $null
}

function Stop-WhRealSession {
    $script:WhUserTargets = $null
    Close-WhAuditRunspaces
    if ($script:WhLoadedHives.Count -eq 0) { return }
    foreach ($hiveName in @($script:WhLoadedHives.ToArray())) {
        $ok = $false
        for ($i = 0; ($i -lt 6) -and (-not $ok); $i++) {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            $ok = (Invoke-WhNative -Tool 'reg.exe' -Arguments @('unload', ('HKU\' + $hiveName))).ok
            if (-not $ok) { Start-Sleep -Milliseconds 500 }
        }
        if ($ok) { [void]$script:WhLoadedHives.Remove($hiveName) }
        else { Write-WhLog -Level 'warn' -EventName 'hive-unload-failed' -Data $hiveName }
    }
}

function Clear-WhRealCaches {
    $script:WhAppxInstalled = $null
    $script:WhAppxProvisioned = $null
    $script:WhFeatureCache = $null
}

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------
function Get-WhRealServiceState {
    param([string]$Name)
    $key = Open-WhRealKey -Target (Get-WhRealMachineTarget) -Path ('SYSTEM\CurrentControlSet\Services\' + $Name) -Writable $false -Create $false
    if ($null -eq $key) { return [ordered]@{ exists = $false } }
    $start = $null
    $delayed = $null
    $type = $null
    try {
        $start = $key.GetValue('Start')
        $delayed = $key.GetValue('DelayedAutostart')
        $type = $key.GetValue('Type')
    }
    finally {
        $key.Close()
    }
    $startup = 'Unknown'
    if ($null -ne $start) {
        switch ([int]$start) {
            0 { $startup = 'Boot' }
            1 { $startup = 'System' }
            2 { if ($delayed -eq 1) { $startup = 'AutomaticDelayed' } else { $startup = 'Automatic' } }
            3 { $startup = 'Manual' }
            4 { $startup = 'Disabled' }
        }
    }
    $isDriver = $false
    if ($null -ne $type) { $isDriver = ((([int]$type) -band 48) -eq 0) }
    $status = 'Unknown'
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $svc) { $status = [string]@($svc)[0].Status }
    return [ordered]@{ exists = $true; startup = $startup; status = $status; is_driver = $isDriver }
}

function Set-WhRealServiceStartup {
    param([string]$Name, [string]$Startup)
    if (($Startup -eq 'Disabled') -or ($Startup -eq 'Manual')) {
        Set-Service -Name $Name -StartupType $Startup -ErrorAction Stop
        return
    }
    $mode = 'auto'
    if ($Startup -eq 'AutomaticDelayed') { $mode = 'delayed-auto' }
    $r = Invoke-WhNative -Tool 'sc.exe' -Arguments @('config', $Name, 'start=', $mode)
    if (-not $r.ok) { throw ('sc.exe config failed for ' + $Name + ': ' + $r.text) }
}

function Set-WhRealServiceRunning {
    param([string]$Name, [bool]$Running)
    $want = 'Stopped'
    if ($Running) { Start-Service -Name $Name -ErrorAction Stop; $want = 'Running' }
    else { Stop-Service -Name $Name -ErrorAction Stop }
    $svc = Get-Service -Name $Name -ErrorAction Stop
    $svc.WaitForStatus($want, [TimeSpan]::FromSeconds(30))
}

# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------
function Get-WhRealTaskState {
    param([string]$Path, [string]$Name)
    $task = Get-ScheduledTask -TaskPath $Path -TaskName $Name -ErrorAction SilentlyContinue
    if ($null -eq $task) { return [ordered]@{ exists = $false } }
    return [ordered]@{ exists = $true; state = [string]@($task)[0].State }
}

function Set-WhRealTaskEnabled {
    param([string]$Path, [string]$Name, [bool]$Enabled)
    if ($Enabled) { [void](Enable-ScheduledTask -TaskPath $Path -TaskName $Name -ErrorAction Stop) }
    else { [void](Disable-ScheduledTask -TaskPath $Path -TaskName $Name -ErrorAction Stop) }
}

# ---------------------------------------------------------------------------
# AppX: installed for any user, and provisioned in the image (future users)
# ---------------------------------------------------------------------------
function Get-WhRealAppxState {
    param([string]$Package)
    if ($null -eq $script:WhAppxInstalled) {
        $script:WhAppxInstalled = @(Get-AppxPackage -AllUsers -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ name = [string]$_.Name; full = [string]$_.PackageFullName } })
    }
    if ($null -eq $script:WhAppxProvisioned) {
        $script:WhAppxProvisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ name = [string]$_.DisplayName; full = [string]$_.PackageName } })
    }
    $installed = @($script:WhAppxInstalled | Where-Object { $_.name -ieq $Package } | ForEach-Object { $_.full } | Sort-Object -Unique)
    $provisioned = @($script:WhAppxProvisioned | Where-Object { $_.name -ieq $Package } | ForEach-Object { $_.full } | Sort-Object -Unique)
    return [ordered]@{ installed = $installed; provisioned = $provisioned }
}

function Remove-WhRealAppx {
    # Provisioned copy first, so no new profile can stage the app while the installed copies are being removed.
    param([string]$Package, [bool]$Deprovision, [bool]$AllUsers)
    $state = Get-WhRealAppxState -Package $Package
    if ($Deprovision) {
        foreach ($full in @($state.provisioned)) {
            [void](Remove-AppxProvisionedPackage -Online -PackageName $full -ErrorAction Stop)
        }
    }
    foreach ($full in @($state.installed)) {
        if ($AllUsers) { Remove-AppxPackage -Package $full -AllUsers -ErrorAction Stop }
        else { Remove-AppxPackage -Package $full -ErrorAction Stop }
    }
    Clear-WhRealCaches
}

# ---------------------------------------------------------------------------
# Optional features (DISM)
# ---------------------------------------------------------------------------
function Get-WhRealFeatureState {
    param([string]$Name)
    if ($null -eq $script:WhFeatureCache) {
        $map = @{}
        foreach ($f in @(Get-WindowsOptionalFeature -Online -ErrorAction Stop)) { $map[([string]$f.FeatureName).ToLowerInvariant()] = [string]$f.State }
        $script:WhFeatureCache = $map
    }
    $key = $Name.ToLowerInvariant()
    if (-not $script:WhFeatureCache.ContainsKey($key)) { return [ordered]@{ exists = $false } }
    return [ordered]@{ exists = $true; state = [string]$script:WhFeatureCache[$key] }
}

function Set-WhRealFeatureEnabled {
    param([string]$Name, [bool]$Enabled)
    if ($Enabled) { [void](Enable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart -ErrorAction Stop) }
    else { [void](Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart -ErrorAction Stop) }
    $script:WhFeatureCache = $null
}

# ---------------------------------------------------------------------------
# Settings without a registry value the engine may write
# Every value travels as text: 2, true, block, success_failure. The functions below translate to and from what
# Windows uses, so the engine compares and journals plain strings.
# ---------------------------------------------------------------------------
function Get-WhDefenderPreferences {
    # Needs the Microsoft Defender service. When another antivirus is active the call fails and the plan says "cannot read".
    $p = @(Get-MpPreference -ErrorAction Stop)
    if ($p.Count -eq 0) { throw 'Get-MpPreference returned nothing. Is Microsoft Defender Antivirus the active antivirus?' }
    return $p[0]
}

function ConvertTo-WhSettingText {
    param($Value)
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    return ([string][int64]$Value)
}

function Get-WhRealDefenderPref {
    param([string]$Name)
    $prop = (Get-WhDefenderPreferences).PSObject.Properties[$Name]
    if (($null -eq $prop) -or ($null -eq $prop.Value)) { throw ('Get-MpPreference has no value for ' + $Name + ' on this system.') }
    return [ordered]@{ exists = $true; value = (ConvertTo-WhSettingText -Value $prop.Value) }
}

function Set-WhRealDefenderPref {
    param([string]$Name, [string]$Value)
    $typed = $null
    if (($Value -eq 'true') -or ($Value -eq 'false')) { $typed = ($Value -eq 'true') } else { $typed = [int]$Value }
    $splat = @{}
    $splat[$Name] = $typed
    Set-MpPreference @splat -ErrorAction Stop
}

function Get-WhRealAsrRule {
    param([string]$Guid)
    $p = Get-WhDefenderPreferences
    $ids = @($p.AttackSurfaceReductionRules_Ids)
    $actions = @($p.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if (([string]$ids[$i]) -ieq $Guid) {
            $code = [int]$actions[$i]
            if ($code -eq 5) { return [ordered]@{ exists = $false } }
            if (-not $script:WhAsrText.ContainsKey($code)) { throw ('The ASR rule ' + $Guid + ' has the unknown action code ' + $code + '.') }
            return [ordered]@{ exists = $true; value = [string]$script:WhAsrText[$code] }
        }
    }
    return [ordered]@{ exists = $false }
}

function Set-WhRealAsrRule {
    # Add-MpPreference adds a rule without touching the others (Set-MpPreference would replace the whole list).
    # A rule that is already listed is removed first, so the list never holds one rule twice.
    param([string]$Guid, [string]$Value)
    $action = [string]$script:WhAsrAction[$Value]
    if ($action -eq '') { throw ('Unknown ASR action ' + $Value) }
    if ([bool](Get-WhRealAsrRule -Guid $Guid).exists) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $Guid -ErrorAction Stop }
    Add-MpPreference -AttackSurfaceReductionRules_Ids $Guid -AttackSurfaceReductionRules_Actions $action -ErrorAction Stop
}

function Get-WhAuditGuid {
    param([string]$Guid)
    return ('{' + $Guid.Trim('{', '}').ToUpperInvariant() + '}')
}

function Get-WhRealAuditSetting {
    # auditpol prints translated words, so the state is read from the numeric "Setting Value" column of a backup file
    # (0 none, 1 success, 2 failure, 3 both). The columns are named by position for the same reason.
    param([string]$Guid)
    $file = Join-Path ([System.IO.Path]::GetTempPath()) ('winharden-audit-' + [guid]::NewGuid().ToString('N') + '.csv')
    try {
        $r = Invoke-WhNative -Tool 'auditpol.exe' -Arguments @('/backup', ('/file:' + $file))
        if (-not $r.ok) { throw ('auditpol /backup failed: ' + $r.text) }
        $header = @('Machine', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion', 'Value')
        $rows = @(Get-Content -LiteralPath $file | Select-Object -Skip 1 | ConvertFrom-Csv -Header $header)
        $want = Get-WhAuditGuid -Guid $Guid
        foreach ($row in $rows) {
            if (([string]$row.Guid).Trim().ToUpperInvariant() -eq $want) {
                $n = [int]([string]$row.Value)
                if (-not $script:WhAuditText.ContainsKey($n)) { throw ('Unknown audit setting value ' + $n + ' for ' + $Guid) }
                return [ordered]@{ exists = $true; value = [string]$script:WhAuditText[$n] }
            }
        }
        throw ('The audit subcategory ' + $Guid + ' is not in the auditpol backup.')
    }
    finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }
}

function Set-WhRealAuditSetting {
    param([string]$Guid, [string]$Value)
    $flags = $script:WhAuditFlags[$Value]
    if ($null -eq $flags) { throw ('Unknown audit setting ' + $Value) }
    $r = Invoke-WhNative -Tool 'auditpol.exe' -Arguments @('/set', ('/subcategory:' + (Get-WhAuditGuid -Guid $Guid)), ('/success:' + $flags[0]), ('/failure:' + $flags[1]))
    if (-not $r.ok) { throw ('auditpol /set failed for ' + $Guid + ': ' + $r.text) }
}

function Get-WhRealSettingState {
    param([string]$Kind, [string]$Name)
    if ($Kind -eq 'defender_pref') { return (Get-WhRealDefenderPref -Name $Name) }
    if ($Kind -eq 'defender_asr') { return (Get-WhRealAsrRule -Guid $Name) }
    if ($Kind -eq 'audit_policy') { return (Get-WhRealAuditSetting -Guid $Name) }
    throw ('Unknown setting kind ' + $Kind)
}

function Set-WhRealSetting {
    param([string]$Kind, [string]$Name, [string]$Value)
    if ($Kind -eq 'defender_pref') { Set-WhRealDefenderPref -Name $Name -Value $Value; return }
    if ($Kind -eq 'defender_asr') { Set-WhRealAsrRule -Guid $Name -Value $Value; return }
    if ($Kind -eq 'audit_policy') { Set-WhRealAuditSetting -Guid $Name -Value $Value; return }
    throw ('Unknown setting kind ' + $Kind)
}

function Clear-WhRealSetting {
    # Only an ASR rule can be "not configured". Preferences and audit settings always have a value, so rollback sets the old one.
    param([string]$Kind, [string]$Name)
    if ($Kind -eq 'defender_asr') { Remove-MpPreference -AttackSurfaceReductionRules_Ids $Name -ErrorAction Stop; return }
    throw ('A ' + $Kind + ' setting cannot be cleared, only set.')
}

# ---------------------------------------------------------------------------
# File cleanup
# ---------------------------------------------------------------------------
function Get-WhRealProfileDirectories {
    # Folders of the real user profiles (local, Microsoft and Entra accounts), never the Default user or service accounts.
    $dirs = New-Object System.Collections.Generic.List[string]
    $listKey = Open-WhRealKey -Target (Get-WhRealMachineTarget) -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Writable $false -Create $false
    if ($null -eq $listKey) { throw 'The ProfileList registry key is missing, so user profiles cannot be enumerated.' }
    try {
        foreach ($sid in $listKey.GetSubKeyNames()) {
            if ($sid -notmatch '^S-1-(5-21|12-1)-[0-9-]+$') { continue }
            $sub = $listKey.OpenSubKey($sid)
            if ($null -eq $sub) { continue }
            try { $dir = [string]$sub.GetValue('ProfileImagePath') } finally { $sub.Close() }
            if (-not [string]::IsNullOrWhiteSpace($dir)) { $dirs.Add($dir) }
        }
    }
    finally {
        $listKey.Close()
    }
    return $dirs.ToArray()
}

function Expand-WhCleanupRoot {
    # Replaces the leading %variable% of a policy root with Base. Only the variables listed in Get-WhRealCleanDirs are accepted.
    param([string]$Root, [string]$Base, [string]$Variable)
    return ($Base.TrimEnd('\') + $Root.Substring($Variable.Length))
}

function Get-WhRealCleanDirs {
    param([string]$Scope, [string]$Root)
    $candidates = New-Object System.Collections.Generic.List[string]
    $lower = $Root.ToLowerInvariant()
    $found = $false
    if ($Scope -eq 'machine') {
        $tokens = [ordered]@{}
        $tokens['%systemroot%'] = [Environment]::GetFolderPath('Windows')
        $tokens['%windir%'] = [Environment]::GetFolderPath('Windows')
        $tokens['%programdata%'] = [Environment]::GetFolderPath('CommonApplicationData')
        $tokens['%systemdrive%'] = [Environment]::GetEnvironmentVariable('SystemDrive')
        foreach ($t in @($tokens.Keys)) {
            if (-not $lower.StartsWith($t + '\')) { continue }
            $found = $true
            $candidates.Add((Expand-WhCleanupRoot -Root $Root -Base ([string]$tokens[$t]) -Variable $t))
        }
    }
    else {
        $suffix = [ordered]@{}
        $suffix['%userprofile%'] = ''
        $suffix['%localappdata%'] = '\AppData\Local'
        $suffix['%appdata%'] = '\AppData\Roaming'
        foreach ($t in @($suffix.Keys)) {
            if (-not $lower.StartsWith($t + '\')) { continue }
            $found = $true
            foreach ($profileDir in @(Get-WhRealProfileDirectories)) {
                $candidates.Add((Expand-WhCleanupRoot -Root $Root -Base ($profileDir + [string]$suffix[$t]) -Variable $t))
            }
        }
    }
    if (-not $found) { throw ('The cleanup folder ' + $Root + ' does not start with a ' + $Scope + ' variable the engine knows.') }
    $existing = New-Object System.Collections.Generic.List[string]
    foreach ($dir in $candidates) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        # A folder that is itself a link is not followed: it could lead anywhere.
        if (((Get-Item -LiteralPath $dir -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $existing.Add($dir)
    }
    return $existing.ToArray()
}

function Get-WhCleanCandidates {
    # Files below Dir whose name matches Pattern and whose last write is older than MinAgeDays. The walk never enters a
    # link (junction or symbolic link) and never lists a link as a file: a link planted in a folder that ordinary users
    # can write to must not turn the cleanup into a delete somewhere else.
    param([string]$Dir, [string]$Pattern, [int]$MinAgeDays, [bool]$Recurse)
    $cutoff = [DateTime]::UtcNow.AddDays(-1 * $MinAgeDays)
    $files = New-Object System.Collections.Generic.List[object]
    $skipped = 0
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($Dir)
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        try {
            $info = New-Object System.IO.DirectoryInfo($current)
            foreach ($f in $info.GetFiles()) {
                if (($f.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                if (-not ($f.Name -like $Pattern)) { continue }
                if ($f.LastWriteTimeUtc -ge $cutoff) { continue }
                $files.Add([pscustomobject]@{ path = $f.FullName; bytes = [int64]$f.Length })
            }
            if ($Recurse) {
                foreach ($d in $info.GetDirectories()) {
                    if (($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $pending.Push($d.FullName)
                }
            }
        }
        catch {
            $skipped++
        }
    }
    return [pscustomobject]@{ files = $files.ToArray(); skipped = $skipped }
}

function Get-WhRealCleanScan {
    param([string]$Dir, [string]$Pattern, [int]$MinAgeDays, [bool]$Recurse)
    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return [ordered]@{ exists = $false; files = 0; bytes = 0; skipped = 0 } }
    $found = Get-WhCleanCandidates -Dir $Dir -Pattern $Pattern -MinAgeDays $MinAgeDays -Recurse $Recurse
    $bytes = [int64]0
    foreach ($f in $found.files) { $bytes += [int64]$f.bytes }
    return [ordered]@{ exists = $true; files = @($found.files).Count; bytes = $bytes; skipped = [int]$found.skipped }
}

function Invoke-WhRealCleanRun {
    param([string]$Dir, [string]$Pattern, [int]$MinAgeDays, [bool]$Recurse)
    $found = Get-WhCleanCandidates -Dir $Dir -Pattern $Pattern -MinAgeDays $MinAgeDays -Recurse $Recurse
    $deleted = 0
    $failed = [int]$found.skipped
    $bytes = [int64]0
    foreach ($f in $found.files) {
        try {
            [System.IO.File]::SetAttributes([string]$f.path, [System.IO.FileAttributes]::Normal)
            [System.IO.File]::Delete([string]$f.path)
            $deleted++
            $bytes += [int64]$f.bytes
        }
        catch {
            $failed++
        }
    }
    return [ordered]@{ deleted = $deleted; bytes = $bytes; failed = $failed }
}

# ---------------------------------------------------------------------------
# Audit commands: linted (Policy.ps1), then run in a ConstrainedLanguage runspace.
# A command that needs a CIM-based module (Defender, ScheduledTasks, NetSecurity) cannot load it there: it is run again in a
# FullLanguage runspace. Both runspaces only ever see a command that passed the lint.
# ---------------------------------------------------------------------------
function Get-WhAuditRunspace {
    param([bool]$Full)
    if ($Full) {
        if ($null -eq $script:WhAuditRunspaceFull) {
            $script:WhAuditRunspaceFull = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $script:WhAuditRunspaceFull.Open()
        }
        return $script:WhAuditRunspaceFull
    }
    if ($null -eq $script:WhAuditRunspace) {
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $iss.LanguageMode = [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage
        $script:WhAuditRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
        $script:WhAuditRunspace.Open()
    }
    return $script:WhAuditRunspace
}

function Close-WhAuditRunspaces {
    foreach ($rs in @($script:WhAuditRunspace, $script:WhAuditRunspaceFull)) {
        if ($null -eq $rs) { continue }
        try { $rs.Dispose() } catch { Write-WhLog -Level 'warn' -EventName 'audit-runspace-dispose' -Data $_.Exception.Message }
    }
    $script:WhAuditRunspace = $null
    $script:WhAuditRunspaceFull = $null
}

function Invoke-WhAuditOnce {
    # Runs one command in one runspace. The error is copied into plain values before the PowerShell object is disposed.
    param($Runspace, [string]$Command)
    $ps = [System.Management.Automation.PowerShell]::Create()
    try {
        $ps.Runspace = $Runspace
        [void]$ps.AddScript($Command)
        $async = $ps.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne(120000)) {
            $ps.Stop()
            throw 'audit command timed out after 120 seconds'
        }
        $out = $ps.EndInvoke($async)
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($o in $out) { $lines.Add([string]$o) }
        $failed = ($ps.Streams.Error.Count -gt 0)
        $message = ''
        $notFound = $false
        if ($failed) {
            $first = $ps.Streams.Error[0]
            $message = [string]$first
            $notFound = ($first.Exception -is [System.Management.Automation.CommandNotFoundException])
        }
        return [pscustomobject]@{ lines = $lines.ToArray(); failed = $failed; message = $message; command_not_found = $notFound }
    }
    finally {
        $ps.Dispose()
    }
}

function Invoke-WhRealAudit {
    # Returns the trimmed text form of the command output, or '<absent>' when there is none.
    # Any error record makes the audit an error, never a pass: an access-denied read must not look like "0 found".
    param([string]$Command)
    $reasons = @(Get-WhAuditLintReasons -Command $Command)
    if ($reasons.Count -gt 0) { throw ('audit command refused by the lint: ' + ($reasons -join '; ')) }
    $run = Invoke-WhAuditOnce -Runspace (Get-WhAuditRunspace -Full $false) -Command $Command
    if ($run.failed -and $run.command_not_found) {
        $run = Invoke-WhAuditOnce -Runspace (Get-WhAuditRunspace -Full $true) -Command $Command
    }
    if ($run.failed) { throw ('audit command reported an error: ' + $run.message) }
    $text = (@($run.lines) -join "`n").Trim()
    if ($text.Length -eq 0) { return '<absent>' }
    return $text
}

# ---------------------------------------------------------------------------
# Facts for preflight
# ---------------------------------------------------------------------------
function Get-WhRealRegistryText {
    param([string]$Path, [string]$Name)
    $key = Open-WhRealKey -Target (Get-WhRealMachineTarget) -Path $Path -Writable $false -Create $false
    if ($null -eq $key) { return $null }
    try { return $key.GetValue($Name) } finally { $key.Close() }
}

function Test-WhRealRegistryKey {
    param([string]$Path)
    $key = Open-WhRealKey -Target (Get-WhRealMachineTarget) -Path $Path -Writable $false -Create $false
    if ($null -eq $key) { return $false }
    $key.Close()
    return $true
}

function Get-WhRealFacts {
    $f = [ordered]@{}
    $f['computer'] = [string]$env:COMPUTERNAME
    $f['is_admin'] = [bool](Test-WhAdmin)
    $f['is_system'] = [bool][System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
    $f['process_64bit'] = [Environment]::Is64BitProcess
    $f['os_64bit'] = [Environment]::Is64BitOperatingSystem
    $cv = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = Get-WhRealRegistryText -Path $cv -Name 'CurrentBuildNumber'
    $f['build'] = 0
    if ($null -ne $build) { $f['build'] = [int]$build }
    $ubr = Get-WhRealRegistryText -Path $cv -Name 'UBR'
    $f['ubr'] = 0
    if ($null -ne $ubr) { $f['ubr'] = [int]$ubr }
    $f['edition_id'] = [string](Get-WhRealRegistryText -Path $cv -Name 'EditionID')
    $f['display_version'] = [string](Get-WhRealRegistryText -Path $cv -Name 'DisplayVersion')
    $f['ui_language'] = [System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName

    $sb = Get-WhRealRegistryText -Path 'SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled'
    if ($null -eq $sb) { $f['secure_boot'] = 'unsupported' }
    elseif ([int]$sb -eq 1) { $f['secure_boot'] = 'enabled' }
    else { $f['secure_boot'] = 'disabled' }

    $f['tpm_present'] = $false
    $f['tpm_spec'] = ''
    $f['tpm_enabled'] = $false
    try {
        $tpm = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName 'Win32_Tpm' -ErrorAction Stop)
        if ($tpm.Count -gt 0) {
            $f['tpm_present'] = $true
            $f['tpm_spec'] = [string]$tpm[0].SpecVersion
            $f['tpm_enabled'] = [bool]$tpm[0].IsEnabled_InitialValue
        }
    }
    catch { $f['tpm_error'] = $_.Exception.Message }

    $f['virtualization'] = $false
    try {
        $cs = @(Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction Stop)[0]
        $cpu = @(Get-CimInstance -ClassName 'Win32_Processor' -ErrorAction Stop)[0]
        $f['virtualization'] = ([bool]$cs.HypervisorPresent -or [bool]$cpu.VirtualizationFirmwareEnabled)
    }
    catch { $f['virtualization_error'] = $_.Exception.Message }

    # Defender preferences only take effect while Defender is the active antivirus (AMRunningMode Normal).
    $f['defender_active'] = $false
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $f['defender_active'] = ([bool]$mp.AntivirusEnabled -and ([string]$mp.AMRunningMode -eq 'Normal'))
    }
    catch { $f['defender_error'] = $_.Exception.Message }

    $reasons = New-Object System.Collections.Generic.List[string]
    if (Test-WhRealRegistryKey -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons.Add('component servicing') }
    if (Test-WhRealRegistryKey -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons.Add('Windows Update') }
    if ($null -ne (Get-WhRealRegistryText -Path 'SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations')) { $reasons.Add('pending file renames') }
    $f['pending_reboot'] = $reasons.ToArray()

    $f['bitlocker'] = 'unknown'
    if ($null -ne (Get-Command -Name 'Get-BitLockerVolume' -ErrorAction SilentlyContinue)) {
        try {
            $vol = @(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop)[0]
            $f['bitlocker'] = ([string]$vol.ProtectionStatus).ToLowerInvariant()
        }
        catch { $f['bitlocker_error'] = $_.Exception.Message }
    }
    return [pscustomobject]$f
}
