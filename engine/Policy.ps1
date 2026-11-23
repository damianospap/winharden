# winharden engine: Policy.ps1
# Runtime copy of two author-time checks that tools/validate_manifests.py runs in CI:
#   - the never-touch policy (R07, R12)
#   - the lint for audit commands (R10)
# Both are shared-vector tested: tests/vectors/*.json is read by the Python tests and by `winharden.ps1 selftest`.
# Windows PowerShell 5.1, ASCII only.

$script:WhAllowedVerbs = @('get', 'test', 'select', 'where', 'foreach', 'sort', 'measure', 'format', 'convertto', 'convertfrom', 'compare', 'group', 'join', 'split', 'resolve', 'out')
$script:WhAllowedOut = @('out-string', 'out-null')
# Read-only cmdlets whose verb is not on the list above. They are allowed by exact name, never by verb.
$script:WhAllowedExact = @('confirm-securebootuefi')
$script:WhAllowedMethods = @('tostring', 'trim', 'trimstart', 'trimend', 'split', 'contains', 'startswith', 'endswith', 'replace', 'tolower', 'toupper', 'substring', 'indexof', 'where', 'foreach', 'gettype')
$script:WhDeniedCmdlets = @('test-netconnection', 'test-connection', 'resolve-dnsname', 'test-wsman', 'get-windowsupdatelog')

$script:WhReStr = "'(?:[^']|'')*'"
$script:WhReCmdlet = '(?<![\w$.:\-])([A-Za-z]+)-([A-Za-z]+)\b'
$script:WhReMethod = '\.([A-Za-z_]\w*)\s*\('
$script:WhReNetwork = 'https?://|DownloadString|DownloadFile|WebClient|System\.Net|FromBase64String|-enc(?:odedcommand)?\b'
$script:WhReCmdPos = '(?:^|[|;({&=])\s*'
$script:WhReAlias = $script:WhReCmdPos + '(iex|iwr|irm|sc|rm|ri|del|erase|rd|rmdir|mv|mi|move|cp|cpi|copy|ni|si|sp|sv|rv|rni|ren|clc|clp|ac|saps|start|kill|spps|sasv|spsv|curl|wget|md|mkdir|cmd|powershell|pwsh|reg|net|schtasks|bcdedit|wmic|netsh|dism|setx|icacls|takeown|attrib|cacls|vssadmin|wevtutil|fsutil|diskpart|cipher|mountvol|robocopy|xcopy|mshta|rundll32|regsvr32)(?:\.exe)?(?![\w\-])'
$script:WhReDotSource = $script:WhReCmdPos + '\.\s'
# auditpol is the one native tool an audit may use, and only to read: auditpol /get ...
$script:WhReAuditpol = '(?<![\w\-])auditpol(?:\.exe)?(?![\w\-])'
$script:WhReAuditpolGet = '(?<![\w\-])auditpol(?:\.exe)?\s+/get\b'
$script:WhReAuditpolWrite = '/(?:set|clear|remove|restore|backup|resourcesacl|file)\b'

function Get-WhAuditLintReasons {
    # Reasons why a command is not an acceptable read-only audit command. Empty array = acceptable.
    param([string]$Command)
    $why = New-Object System.Collections.Generic.List[string]
    if ($Command.Contains("`n") -or $Command.Contains("`r")) { $why.Add('must be a single line') }
    if ($Command.Contains('"')) { $why.Add('use single-quoted strings only') }
    if ([regex]::IsMatch($Command, $script:WhReNetwork, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $why.Add('network or encoding primitive')
    }
    $bare = [regex]::Replace($Command, $script:WhReStr, "''")
    if ($bare.Contains('`')) { $why.Add('backtick not allowed') }
    if ($bare.Contains('&')) { $why.Add('call operator & not allowed') }
    if ($bare.Contains('>')) { $why.Add('redirection > not allowed') }
    if ($bare.Contains('::')) { $why.Add('.NET static call :: not allowed') }
    foreach ($m in [regex]::Matches($bare, $script:WhReCmdlet)) {
        $verb = $m.Groups[1].Value.ToLowerInvariant()
        $whole = $m.Value.ToLowerInvariant()
        if ($script:WhDeniedCmdlets -contains $whole) {
            $why.Add('command ' + $m.Value + ' touches the network or writes a file')
        }
        elseif ($script:WhAllowedExact -contains $whole) { continue }
        elseif (($script:WhAllowedVerbs -notcontains $verb) -or (($verb -eq 'out') -and ($script:WhAllowedOut -notcontains $whole))) {
            $why.Add('command ' + $m.Value + ' is not on the read-only allow-list')
        }
    }
    foreach ($m in [regex]::Matches($bare, $script:WhReAlias, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $why.Add('alias or native command ' + $m.Groups[1].Value + ' not allowed')
    }
    if ([regex]::IsMatch($bare, $script:WhReDotSource)) { $why.Add('dot-sourcing not allowed') }
    $ic = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    if ([regex]::IsMatch($bare, $script:WhReAuditpol, $ic)) {
        $all = [regex]::Matches($bare, $script:WhReAuditpol, $ic).Count
        $reads = [regex]::Matches($bare, $script:WhReAuditpolGet, $ic).Count
        if (($all -ne $reads) -or [regex]::IsMatch($bare, $script:WhReAuditpolWrite, $ic)) {
            $why.Add('auditpol is only allowed as auditpol /get without write options')
        }
    }
    foreach ($m in [regex]::Matches($bare, $script:WhReMethod)) {
        if ($script:WhAllowedMethods -notcontains $m.Groups[1].Value.ToLowerInvariant()) {
            $why.Add('method .' + $m.Groups[1].Value + '() not allowed')
        }
    }
    return $why.ToArray()
}

# ---------------------------------------------------------------------------
# Never-touch policy
# ---------------------------------------------------------------------------
function Import-WhPolicy {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ('The never-touch policy file is missing: ' + $Path) }
    $policy = ConvertFrom-WhJson -Text (Read-WhFile -Path $Path)
    foreach ($field in @('services', 'registry_prefixes', 'registry_values', 'appx_names', 'scheduled_tasks', 'optional_features', 'servicing_adjacent', 'settings', 'cleanup')) {
        if ($null -eq (Get-WhProp -Object $policy -Name $field)) { throw ('The never-touch policy has no field ' + $field + '. Refusing to continue without it.') }
    }
    return $policy
}

function ConvertTo-WhNormPath {
    param([string]$Path)
    return (($Path -replace '/', '\').Trim('\')).ToLowerInvariant()
}

function Test-WhHasWildcard {
    param([string]$Text)
    return ($Text.Contains('*') -or $Text.Contains('?'))
}

function Test-WhGlobOverlap {
    # True when a key matched by Path is the same as, or lies under, Prefix, or the other way round. Only the last
    # segment of Path may hold a wildcard (the validator enforces that); a pattern that could reach a protected key
    # counts as touching it.
    param([string]$Path, [string]$Prefix)
    $p = @((ConvertTo-WhNormPath -Path $Path).Split('\'))
    $q = @((ConvertTo-WhNormPath -Path $Prefix).Split('\'))
    $n = [Math]::Min($p.Count, $q.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $wild = (($i -eq ($p.Count - 1)) -and (Test-WhHasWildcard -Text $p[$i]))
        if ($wild) {
            if (-not ($q[$i] -like $p[$i])) { return $false }
        }
        elseif ($p[$i] -ne $q[$i]) { return $false }
    }
    return $true
}

function Test-WhPathUnder {
    param([string]$Path, [string]$Prefix)
    if (Test-WhHasWildcard -Text $Path) { return (Test-WhGlobOverlap -Path $Path -Prefix $Prefix) }
    $p = ConvertTo-WhNormPath -Path $Path
    $q = ConvertTo-WhNormPath -Path $Prefix
    return (($p -eq $q) -or $p.StartsWith($q + '\'))
}

function ConvertTo-WhValueText {
    # Text form used to compare manifest values with the policy lists and with provider states: 2 -> 2, $true -> true, Block -> block.
    param($Value)
    return ([string]$Value).ToLowerInvariant()
}

function Get-WhTaskFullName {
    param($Op)
    return (([string](Get-WhProp -Object $Op -Name 'path' -Default '')).TrimEnd('\') + '\' + [string](Get-WhProp -Object $Op -Name 'name' -Default '')).ToLowerInvariant()
}

function Get-WhOpViolations {
    # Never-touch violations of one apply operation. Empty array = allowed.
    param($Op, $Policy)
    $out = New-Object System.Collections.Generic.List[string]
    $type = [string](Get-WhProp -Object $Op -Name 'type' -Default '')
    $neverServices = @(@($Policy.services) | ForEach-Object { ([string]$_).ToLowerInvariant() })
    if ($type -eq 'service') {
        $name = [string](Get-WhProp -Object $Op -Name 'name' -Default '')
        if ($neverServices -contains $name.ToLowerInvariant()) { $out.Add('service ' + $name + ' is on the never-touch list') }
    }
    elseif ($type -eq 'registry') {
        $hive = ([string](Get-WhProp -Object $Op -Name 'hive' -Default '')).ToUpperInvariant()
        $path = [string](Get-WhProp -Object $Op -Name 'path' -Default '')
        $name = [string](Get-WhProp -Object $Op -Name 'name' -Default '')
        foreach ($rule in @($Policy.registry_prefixes)) {
            if (([string]$rule.hive).ToUpperInvariant() -eq $hive -and (Test-WhPathUnder -Path $path -Prefix ([string]$rule.path))) {
                $out.Add($hive + '\' + $path + ' is under never-touch prefix ' + $rule.path + ' (' + $rule.reason + ')')
            }
        }
        foreach ($rule in @($Policy.registry_values)) {
            $names = @(@($rule.names) | ForEach-Object { ([string]$_).ToLowerInvariant() })
            if (([string]$rule.hive).ToUpperInvariant() -eq $hive -and (Test-WhPathUnder -Path $path -Prefix ([string]$rule.path_prefix)) -and ($names -contains $name.ToLowerInvariant())) {
                $out.Add('value ' + $name + ' under ' + $rule.path_prefix + ' is never-touch (' + $rule.reason + ')')
            }
        }
        if ($hive -eq 'HKLM') {
            $m = [regex]::Match((ConvertTo-WhNormPath -Path $path), '^system\\(?:currentcontrolset|controlset\d{3})\\services\\([^\\]+)(\\.*)?$')
            if ($m.Success) {
                if (Test-WhHasWildcard -Text $m.Groups[1].Value) {
                    foreach ($svc in $neverServices) {
                        if ($svc -like $m.Groups[1].Value) { $out.Add('service key pattern ' + $m.Groups[1].Value + ' matches never-touch service ' + $svc) }
                    }
                }
                elseif ($neverServices -contains $m.Groups[1].Value) {
                    $out.Add('registry key of never-touch service ' + $m.Groups[1].Value)
                }
                elseif ((-not $m.Groups[2].Success) -and (@('start', 'delayedautostart') -contains $name.ToLowerInvariant())) {
                    $out.Add('service startup must use a service operation, not a raw registry write')
                }
            }
        }
    }
    elseif ($type -eq 'scheduled_task') {
        $full = Get-WhTaskFullName -Op $Op
        foreach ($pattern in @($Policy.scheduled_tasks)) {
            if ($full -like ([string]$pattern).ToLowerInvariant()) {
                $out.Add('scheduled task ' + $full + ' matches never-touch pattern ' + $pattern)
            }
        }
    }
    elseif ($type -eq 'appx') {
        $pkg = ([string](Get-WhProp -Object $Op -Name 'package_name' -Default '')).ToLowerInvariant()
        foreach ($pattern in @($Policy.appx_names)) {
            if ($pkg -like ([string]$pattern).ToLowerInvariant()) {
                $out.Add('AppX package ' + $pkg + ' matches never-remove pattern ' + $pattern)
            }
        }
    }
    elseif ($type -eq 'optional_feature') {
        $name = ([string](Get-WhProp -Object $Op -Name 'name' -Default '')).ToLowerInvariant()
        if (@(@($Policy.optional_features) | ForEach-Object { ([string]$_).ToLowerInvariant() }) -contains $name) {
            $out.Add('optional feature ' + $name + ' is on the never-touch list')
        }
    }
    elseif ($type -eq 'setting') {
        $kind = [string](Get-WhProp -Object $Op -Name 'kind' -Default '')
        $name = [string](Get-WhProp -Object $Op -Name 'name' -Default '')
        $table = Get-WhProp -Object (Get-WhProp -Object $Policy -Name 'settings') -Name $kind
        $allowed = $null
        if ($null -ne $table) {
            foreach ($prop in $table.PSObject.Properties) {
                if ([string]$prop.Name -ieq $name) { $allowed = @($prop.Value) }
            }
        }
        if ($null -eq $allowed) {
            $out.Add('setting ' + $kind + ' ' + $name + ' is not on the settings allow-list')
        }
        else {
            $want = ConvertTo-WhValueText -Value (Get-WhProp -Object $Op -Name 'value')
            $listed = $false
            foreach ($a in $allowed) {
                if ((ConvertTo-WhValueText -Value $a) -eq $want) { $listed = $true }
            }
            if (-not $listed) { $out.Add('value ' + $want + ' is not allowed for ' + $kind + ' ' + $name) }
        }
    }
    elseif ($type -eq 'file_cleanup') {
        $scope = [string](Get-WhProp -Object $Op -Name 'scope' -Default '')
        $root = ([string](Get-WhProp -Object $Op -Name 'root' -Default '')).ToLowerInvariant()
        $listed = $false
        foreach ($r in @($Policy.cleanup.roots)) {
            if (([string]$r.scope -eq $scope) -and (([string]$r.path).ToLowerInvariant() -eq $root)) { $listed = $true }
        }
        if (-not $listed) { $out.Add('cleanup folder ' + $root + ' (' + $scope + ') is not on the cleanup allow-list') }
    }
    return $out.ToArray()
}

function Test-WhServicingAdjacent {
    param($Op, $Policy)
    $type = [string](Get-WhProp -Object $Op -Name 'type' -Default '')
    $adj = $Policy.servicing_adjacent
    if ($type -eq 'service') {
        $name = ([string](Get-WhProp -Object $Op -Name 'name' -Default '')).ToLowerInvariant()
        return (@(@($adj.services) | ForEach-Object { ([string]$_).ToLowerInvariant() }) -contains $name)
    }
    if ($type -eq 'scheduled_task') {
        $full = Get-WhTaskFullName -Op $Op
        return (@(@($adj.scheduled_tasks) | ForEach-Object { ([string]$_).ToLowerInvariant() }) -contains $full)
    }
    return $false
}
