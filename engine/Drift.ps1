# winharden engine: Drift.ps1
# Drift check as a scheduled task that runs as SYSTEM: weekly and at every start-up. After a feature update (a different
# build number than the last run) Windows brings back apps and settings, and the first start-up run reports it.
# The task only VERIFIES and writes a report. Re-applying is a separate, explicit choice (-Reapply at install time) and
# it never includes entries that delete user data or touch servicing.
# A SYSTEM task that runs scripts is a privilege-escalation path if a normal user can edit those scripts, so the files
# are copied to a folder only SYSTEM and Administrators can write, and the ACL is checked before the task is registered.
# Windows PowerShell 5.1, ASCII only.

$script:WhDriftTaskName = 'winharden-drift'
$script:WhDriftTaskPath = '\winharden\'

function Get-WhInstallDirectory {
    $pf = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($pf)) { throw 'The Program Files folder could not be found.' }
    return (Join-Path $pf 'winharden')
}

function Get-WhAclWriters {
    # Principals other than SYSTEM, Administrators, TrustedInstaller and CREATOR OWNER that can write in the folder.
    param([string]$Path)
    $allowed = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0')
    $writeMask = [System.Security.AccessControl.FileSystemRights]::WriteData -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    $offenders = New-Object System.Collections.Generic.List[string]
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if (([int]($rule.FileSystemRights -band $writeMask)) -eq 0) { continue }
        $sid = $null
        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $sid = [string]$rule.IdentityReference }
        if ($allowed -notcontains $sid) { $offenders.Add([string]$rule.IdentityReference) }
    }
    return $offenders.ToArray()
}

function Remove-WhInstallFiles {
    # Deletes the installed copy. Refuses when the folder is not the expected one or contains a link, so a
    # reparse point planted inside it cannot redirect the delete.
    $dir = Get-WhInstallDirectory
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return $false }
    if ((Split-Path -Leaf $dir) -ne 'winharden') { throw ('Refusing to delete ' + $dir + ': it is not a winharden folder.') }
    $links = @(Get-ChildItem -LiteralPath $dir -Recurse -Force | Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 })
    if ($links.Count -gt 0) { throw ('Refusing to delete ' + $dir + ': it contains a link (' + $links[0].FullName + ').') }
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
    return $true
}

function Install-WhDrift {
    param([string]$SourceRoot, [int]$Level, [string[]]$Exclude, [string[]]$OptIn, [bool]$Reapply, [bool]$AllowServicing)
    $dest = Get-WhInstallDirectory
    # A fresh copy every time: a file that a newer version removed must not stay behind and be loaded.
    [void](Remove-WhInstallFiles)
    [void](New-Item -ItemType Directory -Path $dest -Force)
    Protect-WhDirectory -Path $dest
    foreach ($item in @('winharden.ps1', 'engine', 'manifests', 'policy')) {
        $src = Join-Path $SourceRoot $item
        if (-not (Test-Path -LiteralPath $src)) { throw ('Cannot install: ' + $src + ' is missing.') }
        Copy-Item -LiteralPath $src -Destination $dest -Recurse -Force
    }
    # The self test reads the shared vectors, so the installed copy needs them too.
    $vectors = Join-Path (Join-Path $SourceRoot 'tests') 'vectors'
    if (Test-Path -LiteralPath $vectors -PathType Container) {
        $testsDir = Join-Path $dest 'tests'
        [void](New-Item -ItemType Directory -Path $testsDir -Force)
        Copy-Item -LiteralPath $vectors -Destination $testsDir -Recurse -Force
    }
    $offenders = @(Get-WhAclWriters -Path $dest)
    if ($offenders.Count -gt 0) {
        throw ('The install folder ' + $dest + ' can be written by: ' + ($offenders -join ', ') + '. Refusing to register a SYSTEM task that runs scripts from it.')
    }
    $psExe = Join-Path $PSHOME 'powershell.exe'
    $argText = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $dest 'winharden.ps1') + '" drift -Profile ' + $Level
    if ($Reapply) { $argText = $argText + ' -Reapply' }
    if ($AllowServicing) { $argText = $argText + ' -AllowServicingAdjacent' }
    $patterns = @($Exclude | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($patterns.Count -gt 0) { $argText = $argText + ' -Exclude "' + ($patterns -join ',') + '"' }
    $optIns = @($OptIn | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($optIns.Count -gt 0) { $argText = $argText + ' -OptIn "' + ($optIns -join ',') + '"' }
    $action = New-ScheduledTaskAction -Execute $psExe -Argument $argText -WorkingDirectory $dest
    $weekly = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At ([datetime]'03:00')
    $boot = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    [void](Register-ScheduledTask -TaskName $script:WhDriftTaskName -TaskPath $script:WhDriftTaskPath -Action $action -Trigger @($weekly, $boot) -Principal $principal -Settings $settings -Description 'winharden drift check: verifies the hardening settings and writes a report. Changes nothing unless installed with -Reapply.' -Force -ErrorAction Stop)
    return [pscustomobject]@{ directory = $dest; task = ($script:WhDriftTaskPath + $script:WhDriftTaskName); arguments = $argText }
}

function Uninstall-WhDrift {
    param([bool]$RemoveFiles)
    $removed = $false
    $task = Get-ScheduledTask -TaskPath $script:WhDriftTaskPath -TaskName $script:WhDriftTaskName -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        Unregister-ScheduledTask -TaskPath $script:WhDriftTaskPath -TaskName $script:WhDriftTaskName -Confirm:$false -ErrorAction Stop
        $removed = $true
    }
    $filesRemoved = $false
    if ($RemoveFiles) { $filesRemoved = [bool](Remove-WhInstallFiles) }
    return [pscustomobject]@{ task_removed = $removed; files_removed = $filesRemoved }
}

function Get-WhDriftStatePath { return (Join-Path (Get-WhStateDir) 'drift-state.json') }

function Read-WhDriftState {
    $path = Get-WhDriftStatePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try { return (ConvertFrom-WhJson -Text (Read-WhFile -Path $path)) } catch { return $null }
}

function Save-WhDriftState {
    param($Facts, $Counts, [string[]]$FailingIds)
    $state = [ordered]@{
        last_run     = (Get-WhUtcStamp)
        build        = [int](Get-WhProp -Object $Facts -Name 'build' -Default 0)
        ubr          = [int](Get-WhProp -Object $Facts -Name 'ubr' -Default 0)
        counts       = $Counts
        failing      = @($FailingIds)
    }
    Write-WhFile -Path (Get-WhDriftStatePath) -Text (ConvertTo-WhJson -Object $state -Depth 6 -Pretty)
}

function Get-WhDriftNote {
    # What changed in the OS since the previous drift run.
    param($Previous, $Facts)
    if ($null -eq $Previous) { return 'First drift run on this machine.' }
    $b = [int](Get-WhProp -Object $Facts -Name 'build' -Default 0)
    $pb = [int](Get-WhProp -Object $Previous -Name 'build' -Default 0)
    if ($b -ne $pb) { return ('A feature update was detected: build ' + $pb + ' -> ' + $b + '. Windows can bring back removed apps and reset settings after a feature update; the failures below are the regressions.') }
    $u = [int](Get-WhProp -Object $Facts -Name 'ubr' -Default 0)
    $pu = [int](Get-WhProp -Object $Previous -Name 'ubr' -Default 0)
    if ($u -ne $pu) { return ('A cumulative update was installed: revision ' + $pu + ' -> ' + $u + '.') }
    return 'No operating system update since the previous drift run.'
}
