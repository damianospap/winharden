# winharden engine: Preflight.ps1
# Fail-closed checks before anything is applied. Each finding has a code and a diagnosis a person can act on.
# Blockers stop apply. Warnings are shown. Platform gaps (Secure Boot, TPM 2.0) are blockers unless the person
# passes -AllowPlatformGaps, and entries that declare requires_hardware stay blocked by the plan either way.
# Windows PowerShell 5.1, ASCII only.

$script:WhMinBuild = 26200
$script:WhMaxTestedBuild = 26999

function Add-WhFinding {
    param($List, [string]$Code, [string]$Message)
    $List.Add([pscustomobject]@{ code = $Code; message = $Message })
}

function Test-WhPreflight {
    param($Facts, $Options)
    $blockers = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[object]
    $build = [int](Get-WhProp -Object $Facts -Name 'build' -Default 0)

    if (-not [bool](Get-WhProp -Object $Facts -Name 'is_admin' -Default $false)) {
        Add-WhFinding $blockers 'PF01' 'Not running as Administrator. Start Windows PowerShell with "Run as administrator".'
    }
    if ((-not [bool](Get-WhProp -Object $Facts -Name 'os_64bit' -Default $true))) {
        Add-WhFinding $blockers 'PF02' 'This is a 32-bit Windows. Windows 11 is 64-bit only, so this system is not supported.'
    }
    elseif (-not [bool](Get-WhProp -Object $Facts -Name 'process_64bit' -Default $true)) {
        Add-WhFinding $blockers 'PF02' 'This is a 32-bit PowerShell on 64-bit Windows. Registry writes would be redirected to Wow6432Node. Start the 64-bit Windows PowerShell.'
    }
    if ($build -lt 22000) {
        Add-WhFinding $blockers 'PF03' ('Build ' + $build + ' is not Windows 11. This tool supports Windows 11 Home only.')
    }
    elseif ($build -lt $script:WhMinBuild) {
        Add-WhFinding $blockers 'PF03' ('Build ' + $build + ' is older than ' + $script:WhMinBuild + ' (Windows 11 25H2). The manifests were written for 25H2 and newer. Update Windows first.')
    }
    elseif ($build -gt $script:WhMaxTestedBuild) {
        if ([bool](Get-WhProp -Object $Options -Name 'allow_untested_build' -Default $false)) {
            Add-WhFinding $warnings 'PF03' ('Build ' + $build + ' is newer than the builds the manifests were written for (up to ' + $script:WhMaxTestedBuild + '). Continuing because -AllowUntestedBuild was given.')
        }
        else {
            Add-WhFinding $blockers 'PF03' ('Build ' + $build + ' is newer than the builds the manifests were written for (up to ' + $script:WhMaxTestedBuild + '). Pass -AllowUntestedBuild to continue at your own risk.')
        }
    }
    $edition = Get-WhEditionName -Facts $Facts
    if ($edition -ne 'Home') {
        if ([bool](Get-WhProp -Object $Options -Name 'allow_other_edition' -Default $false)) {
            Add-WhFinding $warnings 'PF04' ('Edition ' + $edition + ' is not Windows 11 Home. Continuing because -AllowOtherEdition was given; the Home notes in the manifests do not describe this edition.')
        }
        else {
            Add-WhFinding $blockers 'PF04' ('Edition ' + $edition + ' is not Windows 11 Home. This tool is for Home only. Pass -AllowOtherEdition to continue at your own risk.')
        }
    }
    $pending = @(Get-WhProp -Object $Facts -Name 'pending_reboot' -Default @())
    if ($pending.Count -gt 0) {
        $text = 'A restart is pending (' + ($pending -join ', ') + '). Restart Windows and run the tool again, so it does not change the system in the middle of servicing.'
        if ([bool](Get-WhProp -Object $Options -Name 'ignore_pending_reboot' -Default $false)) { Add-WhFinding $warnings 'PF05' $text }
        else { Add-WhFinding $blockers 'PF05' $text }
    }
    $gaps = [bool](Get-WhProp -Object $Options -Name 'allow_platform_gaps' -Default $false)
    $secure = [string](Get-WhProp -Object $Facts -Name 'secure_boot' -Default 'unknown')
    if ($secure -ne 'enabled') {
        $text = 'Secure Boot is ' + $secure + '. Windows 11 expects Secure Boot, and the hardening in this tool assumes a trusted boot chain. Turn it on in the UEFI setup. This tool never changes Secure Boot.'
        if ($gaps) { Add-WhFinding $warnings 'PF06' ($text + ' Continuing because -AllowPlatformGaps was given.') } else { Add-WhFinding $blockers 'PF06' ($text + ' Pass -AllowPlatformGaps to continue anyway.') }
    }
    $tpmSpec = [string](Get-WhProp -Object $Facts -Name 'tpm_spec' -Default '')
    if ((-not [bool](Get-WhProp -Object $Facts -Name 'tpm_present' -Default $false)) -or (-not [bool](Get-WhProp -Object $Facts -Name 'tpm_enabled' -Default $false)) -or (-not $tpmSpec.StartsWith('2.0'))) {
        $text = 'No enabled TPM 2.0 was found (present: ' + (Get-WhProp -Object $Facts -Name 'tpm_present' -Default $false) + ', enabled: ' + (Get-WhProp -Object $Facts -Name 'tpm_enabled' -Default $false) + ', spec: ' + $tpmSpec + '). Enable it in the UEFI setup (fTPM or PTT). This tool never changes TPM settings.'
        if ($gaps) { Add-WhFinding $warnings 'PF07' ($text + ' Continuing because -AllowPlatformGaps was given.') } else { Add-WhFinding $blockers 'PF07' ($text + ' Pass -AllowPlatformGaps to continue anyway.') }
    }
    if ([string](Get-WhProp -Object $Facts -Name 'bitlocker' -Default 'unknown') -eq 'on') {
        Add-WhFinding $warnings 'PF08' 'BitLocker or Device Encryption protects the system drive. The tool does not change it, but confirm you have the recovery key before you apply system-level changes.'
    }
    if ([bool](Get-WhProp -Object $Facts -Name 'is_system' -Default $false)) {
        Add-WhFinding $warnings 'PF09' 'Running as SYSTEM: audit commands that read HKCU are skipped; the state check still covers every profile.'
    }
    return [pscustomobject]@{
        ok       = ($blockers.Count -eq 0)
        blockers = $blockers.ToArray()
        warnings = $warnings.ToArray()
    }
}

function Format-WhFacts {
    param($Facts)
    $tpm = 'no TPM'
    if ([bool](Get-WhProp -Object $Facts -Name 'tpm_present' -Default $false)) { $tpm = 'TPM ' + [string](Get-WhProp -Object $Facts -Name 'tpm_spec') }
    return ('Windows 11 ' + (Get-WhEditionName -Facts $Facts) + ' ' + [string](Get-WhProp -Object $Facts -Name 'display_version') + ', build ' + [string](Get-WhProp -Object $Facts -Name 'build') + '.' + [string](Get-WhProp -Object $Facts -Name 'ubr') + ', Secure Boot ' + [string](Get-WhProp -Object $Facts -Name 'secure_boot') + ', ' + $tpm + ', virtualization ' + [string](Get-WhProp -Object $Facts -Name 'virtualization'))
}

function Write-WhPreflight {
    param($Result)
    foreach ($b in @($Result.blockers)) { Write-WhLine ('  BLOCKED ' + $b.code + '  ' + $b.message) 'Red' }
    foreach ($w in @($Result.warnings)) { Write-WhLine ('  warning ' + $w.code + '  ' + $w.message) 'Yellow' }
}
