# winharden engine: Plan.ps1
# Builds the plan: for every selected entry it reads the current state of every target (all user profiles for
# scope=user) and decides ok / change / skip / blocked. Nothing in this file changes the system.
# An entry is a transaction group: if any of its targets is blocked, the whole entry is blocked.
# Windows PowerShell 5.1, ASCII only.

function New-WhVerdict {
    param([string]$Status, [string]$Reason = '', [string]$Desired = '', $Data = $null)
    return [pscustomobject]@{ status = $Status; reason = $Reason; desired = $Desired; data = $Data }
}

# ---------------------------------------------------------------------------
# Targets of an operation ("slots") and how to read them
# ---------------------------------------------------------------------------
function Expand-WhRegistryPath {
    # A path whose last segment holds * or ? stands for every existing sub key of the fixed parent that matches it.
    # Keys that appear later (a new network adapter) are picked up by the next plan or verify.
    param($Target, [string]$Path)
    $cut = $Path.LastIndexOf('\')
    if ($cut -lt 1) { throw ('The wildcard path ' + $Path + ' has no fixed parent key.') }
    $parent = $Path.Substring(0, $cut)
    $leaf = $Path.Substring($cut + 1)
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($n in @(Invoke-WhProv 'RegSubKeys' $Target $parent)) {
        if ([string]$n -like $leaf) { $found.Add($parent + '\' + [string]$n) }
    }
    return $found.ToArray()
}

function Get-WhOpSlots {
    param($Op)
    $type = [string]$Op.type
    $slots = New-Object System.Collections.Generic.List[object]
    if ($type -eq 'registry') {
        foreach ($t in @(Invoke-WhProv 'Targets' ([string]$Op.scope))) {
            $paths = @([string]$Op.path)
            if (Test-WhHasWildcard -Text ([string]$Op.path)) { $paths = @(Expand-WhRegistryPath -Target $t -Path ([string]$Op.path)) }
            foreach ($keyPath in $paths) {
                $ident = [ordered]@{ type = 'registry'; scope = [string]$Op.scope; target = [string]$t.label; path = $keyPath; name = [string]$Op.name }
                if ([string]$Op.scope -eq 'machine') { $label = 'HKLM\' + $keyPath + ' : ' + $Op.name }
                else { $label = 'HKCU[' + $t.label + ']\' + $keyPath + ' : ' + $Op.name }
                $slots.Add([pscustomobject]@{ ident = $ident; target = $t; label = $label })
            }
        }
    }
    elseif ($type -eq 'service') {
        $slots.Add([pscustomobject]@{ ident = [ordered]@{ type = 'service'; name = [string]$Op.name }; target = $null; label = ('service ' + $Op.name) })
    }
    elseif ($type -eq 'scheduled_task') {
        $slots.Add([pscustomobject]@{ ident = [ordered]@{ type = 'scheduled_task'; path = [string]$Op.path; name = [string]$Op.name }; target = $null; label = ('task ' + $Op.path + $Op.name) })
    }
    elseif ($type -eq 'appx') {
        $slots.Add([pscustomobject]@{ ident = [ordered]@{ type = 'appx'; package = [string]$Op.package_name }; target = $null; label = ('AppX ' + $Op.package_name) })
    }
    elseif ($type -eq 'optional_feature') {
        $slots.Add([pscustomobject]@{ ident = [ordered]@{ type = 'optional_feature'; name = [string]$Op.name }; target = $null; label = ('feature ' + $Op.name) })
    }
    elseif ($type -eq 'setting') {
        $label = [string]$Op.kind + ' ' + [string]$Op.name
        $note = [string](Get-WhProp -Object $Op -Name 'label' -Default '')
        if ($note -ne '') { $label = $label + ' (' + $note + ')' }
        $slots.Add([pscustomobject]@{ ident = [ordered]@{ type = 'setting'; kind = [string]$Op.kind; name = [string]$Op.name }; target = $null; label = $label })
    }
    elseif ($type -eq 'file_cleanup') {
        foreach ($dir in @(Invoke-WhProv 'CleanDirs' ([string]$Op.scope) ([string]$Op.root))) {
            $ident = [ordered]@{ type = 'file_cleanup'; dir = [string]$dir; pattern = [string]$Op.pattern; min_age_days = [int]$Op.min_age_days; recurse = [bool]$Op.recurse }
            $slots.Add([pscustomobject]@{ ident = $ident; target = $null; label = ('clean ' + [string]$dir + ' (' + [string]$Op.pattern + ', older than ' + [string]$Op.min_age_days + ' days)') })
        }
    }
    else { throw ('Unknown operation type ' + $type) }
    return $slots.ToArray()
}

function Read-WhSlotState {
    param($Slot)
    $i = $Slot.ident
    $type = [string]$i.type
    if ($type -eq 'registry') { return (Invoke-WhProv 'RegGet' $Slot.target ([string]$i.path) ([string]$i.name)) }
    if ($type -eq 'service') { return (Invoke-WhProv 'ServiceGet' ([string]$i.name)) }
    if ($type -eq 'scheduled_task') { return (Invoke-WhProv 'TaskGet' ([string]$i.path) ([string]$i.name)) }
    if ($type -eq 'appx') { return (Invoke-WhProv 'AppxGet' ([string]$i.package)) }
    if ($type -eq 'optional_feature') { return (Invoke-WhProv 'FeatureGet' ([string]$i.name)) }
    if ($type -eq 'setting') { return (Invoke-WhProv 'SettingGet' ([string]$i.kind) ([string]$i.name)) }
    if ($type -eq 'file_cleanup') { return (Invoke-WhProv 'CleanScan' ([string]$i.dir) ([string]$i.pattern) ([int]$i.min_age_days) ([bool]$i.recurse)) }
    throw ('Unknown target type ' + $type)
}

# ---------------------------------------------------------------------------
# Comparing a state with the desired state
# ---------------------------------------------------------------------------
function Test-WhRegDataEqual {
    param([string]$Kind, $Actual, $Wanted)
    if ($Kind -eq 'DWord') { return ([int64]$Actual -eq [int64]$Wanted) }
    if ($Kind -eq 'QWord') { return (([string][uint64]([string]$Actual)) -eq ([string][uint64]([string]$Wanted))) }
    if ($Kind -eq 'MultiString') {
        $a = @()
        if ($null -ne $Actual) { $a = @($Actual) }
        $b = @()
        if ($null -ne $Wanted) { $b = @($Wanted) }
        if ($a.Count -ne $b.Count) { return $false }
        for ($n = 0; $n -lt $a.Count; $n++) {
            if (-not ([string]$a[$n]).Equals([string]$b[$n], [System.StringComparison]::Ordinal)) { return $false }
        }
        return $true
    }
    return ([string]$Actual).Equals([string]$Wanted, [System.StringComparison]::Ordinal)
}

function Format-WhRegValue {
    param([string]$Kind, $Data)
    if ($Kind -eq 'MultiString') { return ($Kind + ' ' + ((@($Data) | ForEach-Object { [string]$_ }) -join '; ')) }
    return ($Kind + ' ' + [string]$Data)
}

function Merge-WhHideList {
    # Adds the tokens of Desired ('hide:a;b') to Current. Existing tokens and their order are kept.
    param([string]$Current, [string]$Desired)
    $prefix = $Desired.Substring(0, 5)
    $tokens = New-Object System.Collections.Generic.List[string]
    if ($Current.StartsWith('hide:', [System.StringComparison]::OrdinalIgnoreCase)) {
        $prefix = $Current.Substring(0, 5)
        foreach ($t in $Current.Substring(5).Split(';')) { if ($t -ne '') { $tokens.Add($t) } }
    }
    foreach ($t in $Desired.Substring(5).Split(';')) {
        if (($t -ne '') -and ($tokens -notcontains $t)) { $tokens.Add($t) }
    }
    return ($prefix + ($tokens.ToArray() -join ';'))
}

function Get-WhRegistryVerdict {
    param($Op, $State)
    $kind = [string]$Op.kind
    $exists = [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)
    $haveKind = [string](Get-WhProp -Object $State -Name 'kind' -Default '')
    $want = $Op.data
    if ($exists -and ($haveKind -eq 'Other')) {
        return (New-WhVerdict -Status 'blocked' -Reason 'The existing value has a type the engine cannot save and restore, so it will not overwrite it.')
    }
    if ((Get-WhProp -Object $Op -Name 'merge') -eq 'hide-list') {
        $current = ''
        if ($exists) {
            if ($haveKind -ne 'String') { return (New-WhVerdict -Status 'blocked' -Reason 'The existing value is not a string, so the hide list cannot be merged.') }
            $current = [string](Get-WhProp -Object $State -Name 'data' -Default '')
            if ($current.StartsWith('showonly:', [System.StringComparison]::OrdinalIgnoreCase)) {
                return (New-WhVerdict -Status 'blocked' -Reason 'An existing showonly: list is not overwritten. Remove or change it by hand, then plan again.')
            }
        }
        $want = Merge-WhHideList -Current $current -Desired ([string]$Op.data)
    }
    $desired = Format-WhRegValue -Kind $kind -Data $want
    if ($exists -and ($haveKind -eq $kind) -and (Test-WhRegDataEqual -Kind $kind -Actual (Get-WhProp -Object $State -Name 'data') -Wanted $want)) {
        return (New-WhVerdict -Status 'ok' -Desired $desired -Data $want)
    }
    return (New-WhVerdict -Status 'change' -Desired $desired -Data $want)
}

function Get-WhServiceVerdict {
    param($Op, $State, [bool]$AfterApply)
    $desired = [string]$Op.startup
    if ([bool]$Op.stop) { $desired = $desired + ', stopped' }
    if (-not [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)) {
        return (New-WhVerdict -Status 'skip' -Reason 'The service is not present on this system.' -Desired $desired)
    }
    if ([bool](Get-WhProp -Object $State -Name 'is_driver' -Default $false)) {
        return (New-WhVerdict -Status 'blocked' -Reason 'The name belongs to a driver, not a Win32 service.' -Desired $desired)
    }
    $startup = [string](Get-WhProp -Object $State -Name 'startup' -Default 'Unknown')
    if (@('Boot', 'System', 'Unknown') -contains $startup) {
        return (New-WhVerdict -Status 'blocked' -Reason ('The start type ' + $startup + ' is not managed by the engine.') -Desired $desired)
    }
    $running = (@('Running', 'StartPending', 'ContinuePending') -contains [string](Get-WhProp -Object $State -Name 'status' -Default ''))
    $needStop = ([bool]$Op.stop) -and (-not $AfterApply) -and $running
    if (($startup -eq [string]$Op.startup) -and (-not $needStop)) { return (New-WhVerdict -Status 'ok' -Desired $desired) }
    return (New-WhVerdict -Status 'change' -Desired $desired)
}

function Get-WhTaskVerdict {
    param($Op, $State)
    if (-not [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)) {
        if ([string]$Op.if_missing -eq 'error') { return (New-WhVerdict -Status 'blocked' -Reason 'The task is missing and the entry requires it.' -Desired 'Disabled') }
        return (New-WhVerdict -Status 'skip' -Reason 'The task is not present on this system.' -Desired 'Disabled')
    }
    if ([string](Get-WhProp -Object $State -Name 'state' -Default '') -eq 'Disabled') { return (New-WhVerdict -Status 'ok' -Desired 'Disabled') }
    return (New-WhVerdict -Status 'change' -Desired 'Disabled')
}

function Get-WhAppxVerdict {
    param($Op, $State)
    if (-not [bool]$Op.all_users) {
        return (New-WhVerdict -Status 'blocked' -Reason 'Only all_users=true is supported: the engine does not remove an app for one user only.' -Desired 'removed')
    }
    $installed = @(Get-WhProp -Object $State -Name 'installed' -Default @())
    $provisioned = @(Get-WhProp -Object $State -Name 'provisioned' -Default @())
    $left = $provisioned.Count
    if (-not [bool]$Op.deprovision) { $left = 0 }
    if (($installed.Count -eq 0) -and ($left -eq 0)) { return (New-WhVerdict -Status 'ok' -Reason 'Not installed.' -Desired 'removed') }
    return (New-WhVerdict -Status 'change' -Desired 'removed')
}

function Get-WhFeatureVerdict {
    param($Op, $State)
    if (-not [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)) {
        return (New-WhVerdict -Status 'skip' -Reason 'The feature is not present on this system.' -Desired 'Disabled')
    }
    if (@('Disabled', 'DisabledWithPayloadRemoved', 'DisablePending') -contains [string](Get-WhProp -Object $State -Name 'state' -Default '')) {
        return (New-WhVerdict -Status 'ok' -Desired 'Disabled')
    }
    return (New-WhVerdict -Status 'change' -Desired 'Disabled')
}

function Get-WhSettingVerdict {
    param($Op, $State)
    $want = ConvertTo-WhValueText -Value $Op.value
    $exists = [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)
    if ($exists -and ([string](Get-WhProp -Object $State -Name 'value' -Default '') -eq $want)) {
        return (New-WhVerdict -Status 'ok' -Desired $want -Data $want)
    }
    return (New-WhVerdict -Status 'change' -Desired $want -Data $want)
}

function Get-WhCleanupVerdict {
    # The desired text and the data stay the same whatever the folder holds, so the plan id does not change when a
    # temporary file appears between two runs. After the cleanup nothing is compared: files that are in use stay.
    param($Op, $State, [bool]$AfterApply)
    $desired = 'delete files older than ' + [string]$Op.min_age_days + ' days'
    if ($AfterApply) { return (New-WhVerdict -Status 'ok' -Desired $desired) }
    if (-not [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)) {
        return (New-WhVerdict -Status 'skip' -Reason 'The folder does not exist.' -Desired $desired)
    }
    if ([int64](Get-WhProp -Object $State -Name 'files' -Default 0) -eq 0) {
        return (New-WhVerdict -Status 'ok' -Reason 'Nothing to clean.' -Desired $desired)
    }
    return (New-WhVerdict -Status 'change' -Desired $desired)
}

function Get-WhSlotVerdict {
    param($Op, $State, [switch]$AfterApply)
    $type = [string]$Op.type
    if ($type -eq 'registry') { return (Get-WhRegistryVerdict -Op $Op -State $State) }
    if ($type -eq 'service') { return (Get-WhServiceVerdict -Op $Op -State $State -AfterApply ([bool]$AfterApply)) }
    if ($type -eq 'scheduled_task') { return (Get-WhTaskVerdict -Op $Op -State $State) }
    if ($type -eq 'appx') { return (Get-WhAppxVerdict -Op $Op -State $State) }
    if ($type -eq 'optional_feature') { return (Get-WhFeatureVerdict -Op $Op -State $State) }
    if ($type -eq 'setting') { return (Get-WhSettingVerdict -Op $Op -State $State) }
    if ($type -eq 'file_cleanup') { return (Get-WhCleanupVerdict -Op $Op -State $State -AfterApply ([bool]$AfterApply)) }
    throw ('Unknown operation type ' + $type)
}

function Get-WhStateKey {
    # Canonical text of the part of a state that decides compliance. Details that can change on their own
    # (a service's running status, whether the leaf registry key exists, Ready vs Running) are left out, so
    # the comparisons between plan, apply and rollback do not fail on noise.
    param([string]$Type, $State)
    $exists = [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)
    if ($Type -eq 'registry') {
        return (ConvertTo-WhCanonical -Value ([ordered]@{ exists = $exists; kind = (Get-WhProp -Object $State -Name 'kind' -Default ''); data = (Get-WhProp -Object $State -Name 'data' -Default '') }))
    }
    if ($Type -eq 'service') {
        return (ConvertTo-WhCanonical -Value ([ordered]@{ exists = $exists; startup = (Get-WhProp -Object $State -Name 'startup' -Default '') }))
    }
    if ($Type -eq 'scheduled_task') {
        return (ConvertTo-WhCanonical -Value ([ordered]@{ exists = $exists; disabled = ([string](Get-WhProp -Object $State -Name 'state' -Default '') -eq 'Disabled') }))
    }
    if ($Type -eq 'appx') {
        return (ConvertTo-WhCanonical -Value ([ordered]@{ installed = @(Get-WhProp -Object $State -Name 'installed' -Default @()); provisioned = @(Get-WhProp -Object $State -Name 'provisioned' -Default @()) }))
    }
    if ($Type -eq 'setting') {
        return (ConvertTo-WhCanonical -Value ([ordered]@{ exists = $exists; value = (Get-WhProp -Object $State -Name 'value' -Default '') }))
    }
    if ($Type -eq 'file_cleanup') {
        # What a folder holds changes all the time; only the fact that it is a cleanup is part of the key.
        return (ConvertTo-WhCanonical -Value ([ordered]@{ cleanup = $true }))
    }
    return (ConvertTo-WhCanonical -Value ([ordered]@{ exists = $exists; state = (Get-WhProp -Object $State -Name 'state' -Default '') }))
}

function Format-WhState {
    param([string]$Type, $State)
    if ($Type -eq 'registry') {
        if (-not [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)) { return '(absent)' }
        return (Format-WhRegValue -Kind ([string](Get-WhProp -Object $State -Name 'kind')) -Data (Get-WhProp -Object $State -Name 'data'))
    }
    if ($Type -eq 'appx') {
        return ('installed ' + @(Get-WhProp -Object $State -Name 'installed' -Default @()).Count + ', provisioned ' + @(Get-WhProp -Object $State -Name 'provisioned' -Default @()).Count)
    }
    if ($Type -eq 'setting') {
        if (-not [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)) { return '(not configured)' }
        return [string](Get-WhProp -Object $State -Name 'value' -Default '')
    }
    if ($Type -eq 'file_cleanup') {
        if (-not [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)) { return '(folder missing)' }
        $mb = [Math]::Round(([double](Get-WhProp -Object $State -Name 'bytes' -Default 0)) / 1048576, 1)
        return ([string](Get-WhProp -Object $State -Name 'files' -Default 0) + ' files, ' + [string]$mb + ' MB to delete')
    }
    if (-not [bool](Get-WhProp -Object $State -Name 'exists' -Default $false)) { return '(not present)' }
    if ($Type -eq 'service') { return ([string](Get-WhProp -Object $State -Name 'startup') + ', ' + [string](Get-WhProp -Object $State -Name 'status')) }
    return [string](Get-WhProp -Object $State -Name 'state' -Default '')
}

# ---------------------------------------------------------------------------
# Entry level: applicability, hardware, gates
# ---------------------------------------------------------------------------
function Get-WhEditionName {
    param($Facts)
    $id = [string](Get-WhProp -Object $Facts -Name 'edition_id' -Default '')
    if ($id.StartsWith('Core', [System.StringComparison]::OrdinalIgnoreCase)) { return 'Home' }
    return $id
}

function Get-WhHardwareGap {
    # $null when the requirement is met, otherwise the reason.
    param([string]$Requirement, $Facts)
    $secure = [string](Get-WhProp -Object $Facts -Name 'secure_boot' -Default 'unknown')
    if ($Requirement -eq 'secure_boot') {
        if ($secure -ne 'enabled') { return ('Secure Boot is ' + $secure + '.') }
        return $null
    }
    if ($Requirement -eq 'uefi') {
        if ($secure -eq 'unsupported') { return 'The system does not boot in UEFI mode.' }
        return $null
    }
    if ($Requirement -eq 'tpm2') {
        $spec = [string](Get-WhProp -Object $Facts -Name 'tpm_spec' -Default '')
        $ok = [bool](Get-WhProp -Object $Facts -Name 'tpm_present' -Default $false) -and [bool](Get-WhProp -Object $Facts -Name 'tpm_enabled' -Default $false) -and $spec.StartsWith('2.0')
        if (-not $ok) { return 'No enabled TPM 2.0 was found.' }
        return $null
    }
    if ($Requirement -eq 'virtualization') {
        if (-not [bool](Get-WhProp -Object $Facts -Name 'virtualization' -Default $false)) { return 'Hardware virtualization is not available or not enabled in firmware.' }
        return $null
    }
    if ($Requirement -eq 'defender_active') {
        if (-not [bool](Get-WhProp -Object $Facts -Name 'defender_active' -Default $false)) { return 'Microsoft Defender Antivirus is not the active antivirus (another product may have taken over, or its service is not running).' }
        return $null
    }
    return ('Unknown hardware requirement ' + $Requirement + '.')
}

function Get-WhEntryGate {
    # $null when the entry may proceed; otherwise { status = skip|blocked; reason }.
    param($Entry, $Facts, $Gates)
    $app = Get-WhProp -Object $Entry -Name 'applicability'
    $minBuild = Get-WhProp -Object $app -Name 'min_build'
    if (($null -ne $minBuild) -and ([int]$Facts.build -lt [int]$minBuild)) {
        return [pscustomobject]@{ status = 'skip'; reason = ('Needs build ' + $minBuild + ' or newer (this system: ' + $Facts.build + ').') }
    }
    $editions = @(Get-WhProp -Object $app -Name 'editions' -Default @())
    if (($editions.Count -gt 0) -and ($editions -notcontains (Get-WhEditionName -Facts $Facts))) {
        return [pscustomobject]@{ status = 'skip'; reason = ('Applies to ' + ($editions -join ', ') + ' only.') }
    }
    $hardware = [string](Get-WhProp -Object $Entry -Name 'requires_hardware' -Default '')
    if ($hardware -ne '') {
        $gap = Get-WhHardwareGap -Requirement $hardware -Facts $Facts
        if ($null -ne $gap) { return [pscustomobject]@{ status = 'blocked'; reason = ('Hardware requirement ' + $hardware + ' is not met: ' + $gap) } }
    }
    $flags = Get-WhProp -Object $Entry -Name 'flags'
    if ([bool](Get-WhProp -Object $flags -Name 'deletes_user_data' -Default $false) -and (-not [bool]$Gates.accept_data_loss)) {
        return [pscustomobject]@{ status = 'blocked'; reason = 'Deletes user data that no rollback can restore. Plan with -AcceptDataLoss to include it.' }
    }
    if ([bool](Get-WhProp -Object $flags -Name 'servicing_adjacent' -Default $false) -and (-not [bool]$Gates.allow_servicing_adjacent)) {
        return [pscustomobject]@{ status = 'blocked'; reason = 'Touches a servicing-adjacent component. Plan with -AllowServicingAdjacent to include it.' }
    }
    return $null
}

function New-WhPlanEntry {
    param($Entry, $Facts, $Gates)
    $items = New-Object System.Collections.Generic.List[object]
    $pe = [ordered]@{
        id             = [string]$Entry.id
        title          = [string]$Entry.title
        module         = [string]$Entry.module
        tier           = [string]$Entry.tier
        min_profile    = [int]$Entry.min_profile
        risk           = [string]$Entry.risk
        home_effective = [string]$Entry.home_effective
        reboot         = [bool](Get-WhProp -Object (Get-WhProp -Object $Entry -Name 'flags') -Name 'requires_reboot' -Default $false)
        status         = 'ok'
        reason         = ''
        items          = @()
    }
    $gate = Get-WhEntryGate -Entry $Entry -Facts $Facts -Gates $Gates
    if ($null -ne $gate) {
        $pe['status'] = [string]$gate.status
        $pe['reason'] = [string]$gate.reason
        return $pe
    }
    $opIndex = 0
    foreach ($op in @($Entry.apply)) {
        foreach ($slot in @(Get-WhOpSlots -Op $op)) {
            $before = $null
            $verdict = $null
            try {
                $before = Read-WhSlotState -Slot $slot
                $verdict = Get-WhSlotVerdict -Op $op -State $before
            }
            catch {
                $verdict = New-WhVerdict -Status 'blocked' -Reason ('Cannot read the current state: ' + $_.Exception.Message)
            }
            $items.Add([pscustomobject]@{
                    id       = ([string]$Entry.id + '#' + $opIndex + ':' + $slot.label)
                    op_index = $opIndex
                    op_type  = [string]$op.type
                    label    = [string]$slot.label
                    ident    = $slot.ident
                    status   = [string]$verdict.status
                    reason   = [string]$verdict.reason
                    before   = $before
                    desired  = [string]$verdict.desired
                    data     = $verdict.data
                    op       = $op
                    slot     = $slot
                })
        }
        $opIndex++
    }
    $pe['items'] = $items.ToArray()
    $anyBlocked = @($items | Where-Object { $_.status -eq 'blocked' }).Count -gt 0
    $anyChange = @($items | Where-Object { $_.status -eq 'change' }).Count -gt 0
    if ($anyBlocked) {
        $pe['status'] = 'blocked'
        $pe['reason'] = ((@($items | Where-Object { $_.status -eq 'blocked' } | ForEach-Object { $_.label + ': ' + $_.reason })) -join ' | ')
    }
    elseif ($anyChange) { $pe['status'] = 'change' }
    elseif (@($items | Where-Object { $_.status -eq 'ok' }).Count -eq 0) {
        $pe['status'] = 'skip'
        $pe['reason'] = 'Nothing to do on this system: ' + ((@($items | ForEach-Object { $_.reason } | Select-Object -Unique)) -join ' ')
    }
    return $pe
}

# ---------------------------------------------------------------------------
# The plan
# ---------------------------------------------------------------------------
function Get-WhPlanHash {
    # Covers everything the approval is about: what will change, from what, to what, under which gates.
    param($Plan)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('level=' + $Plan.level + ';manifests=' + $Plan.manifest_hash + ';data_loss=' + $Plan.gates.accept_data_loss + ';servicing=' + $Plan.gates.allow_servicing_adjacent)
    foreach ($e in @($Plan.entries)) {
        if ($e.status -ne 'change') { continue }
        $lines.Add('entry=' + $e.id)
        foreach ($i in @($e.items)) {
            if ($i.status -ne 'change') { continue }
            $lines.Add((ConvertTo-WhCanonical -Value $i.ident) + '|' + (Get-WhStateKey -Type $i.op_type -State $i.before) + '|' + $i.desired + '|' + (ConvertTo-WhCanonical -Value $i.data))
        }
    }
    return (Get-WhSha256String -Text ($lines.ToArray() -join "`n"))
}

function New-WhPlan {
    param($Entries, $Facts, [int]$Level, $Gates, [string]$ManifestHash, $Excluded, $Optional = @())
    $planEntries = New-Object System.Collections.Generic.List[object]
    $attest = New-Object System.Collections.Generic.List[string]
    $manual = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Entries)) {
        if (@('enforce', 'once') -contains [string]$e.mode) { $planEntries.Add((New-WhPlanEntry -Entry $e -Facts $Facts -Gates $Gates)) }
        elseif ([string]$e.mode -eq 'attest') { $attest.Add([string]$e.id) }
        else { $manual.Add([string]$e.id) }
    }
    $plan = [ordered]@{
        created       = (Get-WhUtcStamp)
        engine        = $script:WhEngineVersion
        level         = $Level
        manifest_hash = $ManifestHash
        gates         = [ordered]@{ accept_data_loss = [bool]$Gates.accept_data_loss; allow_servicing_adjacent = [bool]$Gates.allow_servicing_adjacent }
        excluded      = @(@($Excluded) | ForEach-Object { [string]$_.id })
        optional      = @(@($Optional) | ForEach-Object { [string]$_.id + ' (opt-in ' + [string](Get-WhProp -Object $_ -Name 'opt_in') + ')' })
        attest        = $attest.ToArray()
        manual        = $manual.ToArray()
        entries       = $planEntries.ToArray()
    }
    $plan['hash'] = Get-WhPlanHash -Plan $plan
    $plan['id'] = $plan.hash.Substring(0, 12)
    return $plan
}

function Get-WhPlanSummary {
    param($Plan)
    $count = { param($status) @(@($Plan.entries) | Where-Object { $_.status -eq $status }).Count }
    $changes = 0
    $reboot = $false
    foreach ($e in @($Plan.entries)) {
        if ($e.status -ne 'change') { continue }
        $changes += @(@($e.items) | Where-Object { $_.status -eq 'change' }).Count
        if ($e.reboot) { $reboot = $true }
    }
    return [pscustomobject]@{
        entries_change  = (& $count 'change')
        entries_ok      = (& $count 'ok')
        entries_skip    = (& $count 'skip')
        entries_blocked = (& $count 'blocked')
        item_changes    = $changes
        reboot          = $reboot
    }
}

function Format-WhPlan {
    param($Plan)
    $s = Get-WhPlanSummary -Plan $Plan
    Write-WhLine ('Plan ' + $Plan.id + '  profile ' + $Plan.level + '  engine ' + $Plan.engine)
    Write-WhLine ('  to change: ' + $s.entries_change + ' entries (' + $s.item_changes + ' targets)   already compliant: ' + $s.entries_ok + '   not applicable: ' + $s.entries_skip + '   blocked: ' + $s.entries_blocked)
    foreach ($e in @($Plan.entries)) {
        if ($e.status -eq 'ok') { continue }
        $color = ''
        if ($e.status -eq 'blocked') { $color = 'Yellow' }
        Write-WhLine ('')
        Write-WhLine ('[' + $e.status.ToUpperInvariant() + '] ' + $e.id + '  (profile ' + $e.min_profile + ', risk ' + $e.risk + ', Home effect: ' + $e.home_effective + ')') $color
        Write-WhLine ('    ' + $e.title)
        if ($e.reason -ne '') { Write-WhLine ('    ' + $e.reason) $color }
        if ($e.status -eq 'change') {
            foreach ($i in @($e.items)) {
                if ($i.status -ne 'change') { continue }
                Write-WhLine ('    ' + $i.label + ':  ' + (Format-WhState -Type $i.op_type -State $i.before) + '  ->  ' + $i.desired)
            }
            if ($e.reboot) { Write-WhLine '    needs a restart to take effect' }
        }
    }
    if (@($Plan.optional).Count -gt 0) { Write-WhLine ('') ; Write-WhLine ('Not selected, needs an explicit -OptIn: ' + (@($Plan.optional) -join ', ')) }
    if ($Plan.attest.Count -gt 0) { Write-WhLine ('') ; Write-WhLine ('Checked only, never changed: ' + ($Plan.attest -join ', ')) }
    if ($Plan.manual.Count -gt 0) { Write-WhLine ('Manual steps for you (see the report): ' + ($Plan.manual -join ', ')) }
}

function Export-WhPlan {
    # JSON copy of the plan for review. The in-memory objects (op, slot) are left out.
    param($Plan, [string]$Path)
    $copy = [ordered]@{}
    foreach ($k in @($Plan.Keys)) { if ($k -ne 'entries') { $copy[$k] = $Plan[$k] } }
    $entries = @()
    foreach ($e in @($Plan.entries)) {
        $c = [ordered]@{}
        foreach ($k in @($e.Keys)) { if ($k -ne 'items') { $c[$k] = $e[$k] } }
        $c['items'] = @(@($e.items) | ForEach-Object {
                [ordered]@{ id = $_.id; label = $_.label; status = $_.status; reason = $_.reason; before = $_.before; desired = $_.desired }
            })
        $entries += , $c
    }
    $copy['entries'] = $entries
    Write-WhFile -Path $Path -Text (ConvertTo-WhJson -Object $copy -Depth 12 -Pretty)
}
