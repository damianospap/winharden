# winharden engine: Provider.ps1
# The seam between the engine and the system. A provider is a table of function names; every function takes
# positional arguments. Provider.Real.ps1 is the real system, Provider.Fake.ps1 is an in-memory system used by
# `winharden.ps1 selftest` (no change is ever made to the machine in that mode).
# Windows PowerShell 5.1, ASCII only.

$script:WhRealProvider = @{
    Facts          = 'Get-WhRealFacts'
    SessionStart   = 'Start-WhRealSession'
    SessionStop    = 'Stop-WhRealSession'
    Targets        = 'Get-WhRealTargets'
    RegGet         = 'Get-WhRealRegState'
    RegSet         = 'Set-WhRealRegValue'
    RegRemove      = 'Remove-WhRealRegValue'
    RegSubKeys     = 'Get-WhRealRegSubKeys'
    ServiceGet     = 'Get-WhRealServiceState'
    ServiceStartup = 'Set-WhRealServiceStartup'
    ServiceRunning = 'Set-WhRealServiceRunning'
    TaskGet        = 'Get-WhRealTaskState'
    TaskEnabled    = 'Set-WhRealTaskEnabled'
    AppxGet        = 'Get-WhRealAppxState'
    AppxRemove     = 'Remove-WhRealAppx'
    FeatureGet     = 'Get-WhRealFeatureState'
    FeatureEnabled = 'Set-WhRealFeatureEnabled'
    SettingGet     = 'Get-WhRealSettingState'
    SettingSet     = 'Set-WhRealSetting'
    SettingClear   = 'Clear-WhRealSetting'
    CleanDirs      = 'Get-WhRealCleanDirs'
    CleanScan      = 'Get-WhRealCleanScan'
    CleanRun       = 'Invoke-WhRealCleanRun'
    Audit          = 'Invoke-WhRealAudit'
    ClearCaches    = 'Clear-WhRealCaches'
}

$script:WhFakeProvider = @{
    Facts          = 'Get-WhFakeFacts'
    SessionStart   = 'Start-WhFakeSession'
    SessionStop    = 'Stop-WhFakeSession'
    Targets        = 'Get-WhFakeTargets'
    RegGet         = 'Get-WhFakeRegState'
    RegSet         = 'Set-WhFakeRegValue'
    RegRemove      = 'Remove-WhFakeRegValue'
    RegSubKeys     = 'Get-WhFakeRegSubKeys'
    ServiceGet     = 'Get-WhFakeServiceState'
    ServiceStartup = 'Set-WhFakeServiceStartup'
    ServiceRunning = 'Set-WhFakeServiceRunning'
    TaskGet        = 'Get-WhFakeTaskState'
    TaskEnabled    = 'Set-WhFakeTaskEnabled'
    AppxGet        = 'Get-WhFakeAppxState'
    AppxRemove     = 'Remove-WhFakeAppx'
    FeatureGet     = 'Get-WhFakeFeatureState'
    FeatureEnabled = 'Set-WhFakeFeatureEnabled'
    SettingGet     = 'Get-WhFakeSettingState'
    SettingSet     = 'Set-WhFakeSetting'
    SettingClear   = 'Clear-WhFakeSetting'
    CleanDirs      = 'Get-WhFakeCleanDirs'
    CleanScan      = 'Get-WhFakeCleanScan'
    CleanRun       = 'Invoke-WhFakeCleanRun'
    Audit          = 'Invoke-WhFakeAudit'
    ClearCaches    = 'Clear-WhFakeCaches'
}

$script:WhProv = $script:WhRealProvider

function Use-WhProvider {
    param([ValidateSet('real', 'fake')][string]$Name)
    if ($Name -eq 'fake') { $script:WhProv = $script:WhFakeProvider } else { $script:WhProv = $script:WhRealProvider }
}

function Invoke-WhProv {
    # Positional arguments only: Invoke-WhProv 'RegGet' $target $path $name
    param([string]$Operation)
    $fn = $script:WhProv[$Operation]
    if ([string]::IsNullOrEmpty($fn)) { throw ('Unknown provider operation ' + $Operation) }
    & $fn @args
}
