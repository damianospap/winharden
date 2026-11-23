# winharden engine: Provider.Fake.ps1
# In-memory system for `winharden.ps1 selftest`. Same function surface as Provider.Real.ps1.
# Faults can be injected with $script:WhFake.fail['<Operation>|<name>'] = '<message>'.
# Every mutating call is appended to $script:WhFake.calls, so a test can prove "second run: zero side effects".
# Windows PowerShell 5.1, ASCII only.

$script:WhFake = $null

function Reset-WhFake {
    $script:WhFake = @{
        facts    = [pscustomobject]@{
            computer = 'FAKE-PC'; is_admin = $true; is_system = $false; process_64bit = $true; os_64bit = $true
            build = 26200; ubr = 1; edition_id = 'Core'; display_version = '25H2'
            secure_boot = 'enabled'; tpm_present = $true; tpm_spec = '2.0, 0, 1.59'; tpm_enabled = $true
            virtualization = $true; defender_active = $true; pending_reboot = @(); bitlocker = 'off'; ui_language = 'en'
        }
        users    = @('S-1-5-21-1-2-3-1001', 'S-1-5-21-1-2-3-1002', 'DEFAULT')
        reg      = @{}
        keys     = @{}
        services = @{}
        tasks    = @{}
        appx     = @{}
        features = @{}
        settings = @{}
        dirs     = @{}
        roots    = @{}
        audits   = @{}
        fail     = @{}
        calls    = (New-Object 'System.Collections.Generic.List[string]')
    }
}

function Assert-WhFakeNoFault {
    param([string]$Operation, [string]$Name)
    $k = $Operation + '|' + $Name
    if ($script:WhFake.fail.ContainsKey($k)) { throw [string]$script:WhFake.fail[$k] }
}

function Get-WhFakeFacts { return $script:WhFake.facts }
function Start-WhFakeSession { }
function Stop-WhFakeSession { }
function Clear-WhFakeCaches { }

function Get-WhFakeTargets {
    param([string]$Scope)
    if ($Scope -eq 'machine') { return [pscustomobject]@{ label = 'HKLM'; scope = 'machine'; hive = 'LocalMachine'; prefix = '' } }
    foreach ($u in @($script:WhFake.users)) {
        [pscustomobject]@{ label = $u; scope = 'user'; hive = 'Users'; prefix = ($u + '\') }
    }
}

function Get-WhFakeRegState {
    param($Target, [string]$Path, [string]$Name)
    $k = $Target.label + '|' + $Path + '|' + $Name
    if ($script:WhFake.reg.ContainsKey($k)) {
        $v = $script:WhFake.reg[$k]
        return [ordered]@{ key_exists = $true; exists = $true; kind = $v.kind; data = $v.data }
    }
    return [ordered]@{ key_exists = $script:WhFake.keys.ContainsKey($Target.label + '|' + $Path); exists = $false }
}

function Set-WhFakeRegValue {
    param($Target, [string]$Path, [string]$Name, [string]$Kind, $Data)
    Assert-WhFakeNoFault -Operation 'RegSet' -Name $Name
    $script:WhFake.calls.Add('RegSet ' + $Target.label + '|' + $Path + '|' + $Name)
    $stored = $Data
    if ($Kind -eq 'DWord') { $stored = [int64]$Data }
    elseif ($Kind -eq 'QWord') { $stored = [string][uint64]([string]$Data) }
    elseif ($Kind -eq 'MultiString') { $stored = [string[]]@($Data) }
    elseif ($Kind -ne 'Binary') { $stored = [string]$Data }
    $script:WhFake.keys[$Target.label + '|' + $Path] = $true
    $script:WhFake.reg[$Target.label + '|' + $Path + '|' + $Name] = @{ kind = $Kind; data = $stored }
}

function Remove-WhFakeRegValue {
    param($Target, [string]$Path, [string]$Name, [bool]$RemoveEmptyKey)
    Assert-WhFakeNoFault -Operation 'RegRemove' -Name $Name
    $script:WhFake.calls.Add('RegRemove ' + $Target.label + '|' + $Path + '|' + $Name)
    $script:WhFake.reg.Remove($Target.label + '|' + $Path + '|' + $Name)
    if (-not $RemoveEmptyKey) { return }
    $prefix = $Target.label + '|' + $Path + '|'
    foreach ($k in @($script:WhFake.reg.Keys)) {
        if ($k.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return }
    }
    $script:WhFake.keys.Remove($Target.label + '|' + $Path)
}

function Get-WhFakeRegSubKeys {
    param($Target, [string]$Path)
    $prefix = ($Target.label + '|' + $Path + '\').ToLowerInvariant()
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($script:WhFake.keys.Keys)) {
        if (-not ([string]$k).ToLowerInvariant().StartsWith($prefix)) { continue }
        $first = ([string]$k).Substring($prefix.Length).Split('\')[0]
        if (($first -ne '') -and ($found -notcontains $first)) { $found.Add($first) }
    }
    return @($found.ToArray() | Sort-Object)
}

function Get-WhFakeServiceState {
    param([string]$Name)
    if (-not $script:WhFake.services.ContainsKey($Name)) { return [ordered]@{ exists = $false } }
    $s = $script:WhFake.services[$Name]
    return [ordered]@{ exists = $true; startup = $s.startup; status = $s.status; is_driver = [bool]$s.driver }
}

function Set-WhFakeServiceStartup {
    param([string]$Name, [string]$Startup)
    Assert-WhFakeNoFault -Operation 'ServiceStartup' -Name $Name
    $script:WhFake.calls.Add('ServiceStartup ' + $Name + ' ' + $Startup)
    $script:WhFake.services[$Name].startup = $Startup
}

function Set-WhFakeServiceRunning {
    param([string]$Name, [bool]$Running)
    Assert-WhFakeNoFault -Operation 'ServiceRunning' -Name $Name
    $script:WhFake.calls.Add('ServiceRunning ' + $Name + ' ' + $Running)
    if ($Running) { $script:WhFake.services[$Name].status = 'Running' } else { $script:WhFake.services[$Name].status = 'Stopped' }
}

function Get-WhFakeTaskState {
    param([string]$Path, [string]$Name)
    $k = $Path + $Name
    if (-not $script:WhFake.tasks.ContainsKey($k)) { return [ordered]@{ exists = $false } }
    return [ordered]@{ exists = $true; state = [string]$script:WhFake.tasks[$k] }
}

function Set-WhFakeTaskEnabled {
    param([string]$Path, [string]$Name, [bool]$Enabled)
    Assert-WhFakeNoFault -Operation 'TaskEnabled' -Name $Name
    $script:WhFake.calls.Add('TaskEnabled ' + $Path + $Name + ' ' + $Enabled)
    if ($Enabled) { $script:WhFake.tasks[$Path + $Name] = 'Ready' } else { $script:WhFake.tasks[$Path + $Name] = 'Disabled' }
}

function Get-WhFakeAppxState {
    param([string]$Package)
    if (-not $script:WhFake.appx.ContainsKey($Package)) { return [ordered]@{ installed = @(); provisioned = @() } }
    $a = $script:WhFake.appx[$Package]
    return [ordered]@{ installed = @($a.installed | Sort-Object); provisioned = @($a.provisioned | Sort-Object) }
}

function Remove-WhFakeAppx {
    param([string]$Package, [bool]$Deprovision, [bool]$AllUsers)
    Assert-WhFakeNoFault -Operation 'AppxRemove' -Name $Package
    $script:WhFake.calls.Add('AppxRemove ' + $Package)
    if (-not $script:WhFake.appx.ContainsKey($Package)) { return }
    if ($Deprovision) { $script:WhFake.appx[$Package].provisioned = @() }
    $script:WhFake.appx[$Package].installed = @()
}

function Get-WhFakeFeatureState {
    param([string]$Name)
    if (-not $script:WhFake.features.ContainsKey($Name)) { return [ordered]@{ exists = $false } }
    return [ordered]@{ exists = $true; state = [string]$script:WhFake.features[$Name] }
}

function Set-WhFakeFeatureEnabled {
    param([string]$Name, [bool]$Enabled)
    Assert-WhFakeNoFault -Operation 'FeatureEnabled' -Name $Name
    $script:WhFake.calls.Add('FeatureEnabled ' + $Name + ' ' + $Enabled)
    if ($Enabled) { $script:WhFake.features[$Name] = 'Enabled' } else { $script:WhFake.features[$Name] = 'Disabled' }
}

function Get-WhFakeSettingState {
    param([string]$Kind, [string]$Name)
    $k = ($Kind + '|' + $Name).ToLowerInvariant()
    if (-not $script:WhFake.settings.ContainsKey($k)) { return [ordered]@{ exists = $false } }
    return [ordered]@{ exists = $true; value = [string]$script:WhFake.settings[$k] }
}

function Set-WhFakeSetting {
    param([string]$Kind, [string]$Name, [string]$Value)
    Assert-WhFakeNoFault -Operation 'SettingSet' -Name $Name
    $script:WhFake.calls.Add('SettingSet ' + $Kind + ' ' + $Name + ' ' + $Value)
    $script:WhFake.settings[($Kind + '|' + $Name).ToLowerInvariant()] = $Value
}

function Clear-WhFakeSetting {
    param([string]$Kind, [string]$Name)
    Assert-WhFakeNoFault -Operation 'SettingClear' -Name $Name
    $script:WhFake.calls.Add('SettingClear ' + $Kind + ' ' + $Name)
    $script:WhFake.settings.Remove(($Kind + '|' + $Name).ToLowerInvariant())
}

function Get-WhFakeCleanDirs {
    # roots['<scope>|<root>'] = @('C:\Fake\Temp', ...) is set by the test. Like the real provider, this returns only the
    # folders that exist, and a folder exists when it is in dirs.
    param([string]$Scope, [string]$Root)
    $k = ($Scope + '|' + $Root).ToLowerInvariant()
    $found = New-Object System.Collections.Generic.List[string]
    if ($script:WhFake.roots.ContainsKey($k)) {
        foreach ($dir in @($script:WhFake.roots[$k])) {
            if ($script:WhFake.dirs.ContainsKey([string]$dir)) { $found.Add([string]$dir) }
        }
    }
    return $found.ToArray()
}

function Get-WhFakeCleanScan {
    param([string]$Dir, [string]$Pattern, [int]$MinAgeDays, [bool]$Recurse)
    if (-not $script:WhFake.dirs.ContainsKey($Dir)) { return [ordered]@{ exists = $false; files = 0; bytes = 0; skipped = 0 } }
    $d = $script:WhFake.dirs[$Dir]
    return [ordered]@{ exists = $true; files = [int]$d.files; bytes = [int64]$d.bytes; skipped = 0 }
}

function Invoke-WhFakeCleanRun {
    param([string]$Dir, [string]$Pattern, [int]$MinAgeDays, [bool]$Recurse)
    Assert-WhFakeNoFault -Operation 'CleanRun' -Name $Dir
    $script:WhFake.calls.Add('CleanRun ' + $Dir)
    if (-not $script:WhFake.dirs.ContainsKey($Dir)) { return [ordered]@{ deleted = 0; bytes = 0; failed = 0 } }
    $d = $script:WhFake.dirs[$Dir]
    $result = [ordered]@{ deleted = [int]$d.files; bytes = [int64]$d.bytes; failed = 0 }
    $d['files'] = 0
    $d['bytes'] = 0
    return $result
}

function Invoke-WhFakeAudit {
    param([string]$Command)
    if ($script:WhFake.audits.ContainsKey($Command)) { return [string]$script:WhFake.audits[$Command] }
    throw 'no canned audit output for this command'
}
