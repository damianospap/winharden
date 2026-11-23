# winharden engine: Core.ps1
# Shared helpers. Windows PowerShell 5.1 syntax. ASCII only: 5.1 reads a script file without a BOM as ANSI.
# Convention used in every engine file: callers wrap each call that can return a collection in @( ).

$script:WhEngineVersion = '0.1.0'
$script:WhStateDir = $null
$script:WhQuiet = $false
$script:WhLogEnabled = $true
$script:WhSkipAcl = $false
$script:WhFingerprint = ''
$script:WhUtf8 = New-Object System.Text.UTF8Encoding($false)

function Get-WhProp {
    # Optional property read for PSCustomObject, hashtable and ordered dictionary. Returns $Default when missing.
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    return $prop.Value
}

function ConvertTo-WhJson {
    param($Object, [int]$Depth = 12, [switch]$Pretty)
    if ($Pretty) { return (ConvertTo-Json -InputObject $Object -Depth $Depth) }
    return (ConvertTo-Json -InputObject $Object -Depth $Depth -Compress)
}

function ConvertFrom-WhJson {
    param([string]$Text)
    return ($Text | ConvertFrom-Json)
}

function ConvertTo-WhQuoted {
    param([string]$Text)
    return ('"' + $Text.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n') + '"')
}

function ConvertTo-WhCanonical {
    # Stable text form of a value (sorted keys, no whitespace). Used to compare states read at different times.
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return (ConvertTo-WhQuoted -Text $Value) }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    $list = $null
    if ($Value -is [System.Collections.IDictionary]) {
        # psbase: on a dictionary with an entry called keys, $Value.Keys returns that entry instead of the list of key names.
        $list = New-Object 'System.Collections.Generic.List[string]'
        foreach ($k in $Value.psbase.Keys) { $list.Add([string]$k) }
    }
    elseif ($Value -is [System.Management.Automation.PSCustomObject]) {
        $list = New-Object 'System.Collections.Generic.List[string]'
        foreach ($p in $Value.PSObject.Properties) { $list.Add([string]$p.Name) }
    }
    if ($null -ne $list) {
        $list.Sort([System.StringComparer]::Ordinal)
        $parts = @()
        foreach ($n in $list) {
            $parts += ((ConvertTo-WhQuoted -Text $n) + ':' + (ConvertTo-WhCanonical -Value (Get-WhProp -Object $Value -Name $n)))
        }
        return ('{' + ($parts -join ',') + '}')
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = @()
        foreach ($v in $Value) { $parts += (ConvertTo-WhCanonical -Value $v) }
        return ('[' + ($parts -join ',') + ']')
    }
    return ([string]$Value)
}

function Get-WhSha256Bytes {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    return ([System.BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant())
}

function Get-WhSha256String {
    param([string]$Text)
    return (Get-WhSha256Bytes -Bytes ([System.Text.Encoding]::UTF8.GetBytes($Text)))
}

function Get-WhSha256File {
    param([string]$Path)
    return (Get-WhSha256Bytes -Bytes ([System.IO.File]::ReadAllBytes($Path)))
}

function Read-WhFile {
    param([string]$Path)
    return [System.IO.File]::ReadAllText($Path, $script:WhUtf8)
}

function Write-WhFile {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, $script:WhUtf8)
}

function Add-WhFileLine {
    # Appends one line and forces it to disk before returning. The journal relies on this
    # (write-ahead: the before-state is on disk before the change is made).
    param([string]$Path, [string]$Line)
    $bytes = $script:WhUtf8.GetBytes($Line + "`n")
    $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Get-WhFingerprint {
    # SHA-256 over the CLI script, the engine files and the policy. It is printed in every plan and report, so a result
    # can be tied to the exact code that produced it.
    param([string]$Root)
    $files = New-Object System.Collections.Generic.List[string]
    $cli = Join-Path $Root 'winharden.ps1'
    if (Test-Path -LiteralPath $cli -PathType Leaf) { $files.Add($cli) }
    foreach ($sub in @('engine', 'policy')) {
        $dir = Join-Path $Root $sub
        if (Test-Path -LiteralPath $dir -PathType Container) {
            foreach ($f in @(Get-ChildItem -LiteralPath $dir -File | Sort-Object -Property Name)) { $files.Add($f.FullName) }
        }
    }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($path in $files) {
        $rel = $path.Substring($Root.Length).TrimStart('\', '/').Replace('\', '/')
        $lines.Add($rel + ':' + (Get-WhSha256File -Path $path))
    }
    return (Get-WhSha256String -Text ($lines.ToArray() -join "`n"))
}

function Get-WhUtcStamp {
    return [DateTime]::UtcNow.ToString('yyyy-MM-dd\THH:mm:ss.fff\Z', [System.Globalization.CultureInfo]::InvariantCulture)
}

function New-WhRunId {
    $t = [DateTime]::UtcNow.ToString('yyyyMMdd\THHmmss\Z', [System.Globalization.CultureInfo]::InvariantCulture)
    return ($t + '-' + [guid]::NewGuid().ToString('N').Substring(0, 4))
}

function Test-WhAdmin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-WhLine {
    param([string]$Text = '', [string]$Color = '')
    if ($script:WhQuiet) { return }
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

function Get-WhStateDir {
    if ($script:WhStateDir) { return $script:WhStateDir }
    $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($base) -or -not (Test-Path -LiteralPath $base -PathType Container)) {
        throw 'The ProgramData folder could not be found.'
    }
    return (Join-Path $base 'winharden')
}

function Protect-WhDirectory {
    # Only SYSTEM and Administrators (well-known SIDs, so it works on every UI language) may touch the folder.
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit,
            [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Initialize-WhDirectory {
    param([string]$Path, [switch]$Protect)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $Path -Force)
        if ($Protect -and (-not $script:WhSkipAcl)) { Protect-WhDirectory -Path $Path }
    }
    return $Path
}

function Initialize-WhStateDirectory {
    # Creates the state folder (journal, plans, reports, logs). Only SYSTEM and Administrators can touch it.
    $root = Get-WhStateDir
    [void](Initialize-WhDirectory -Path $root -Protect)
    foreach ($sub in @('journal', 'plans', 'reports', 'logs')) {
        [void](Initialize-WhDirectory -Path (Join-Path $root $sub) -Protect)
    }
    return $root
}

function Write-WhLog {
    # Structured log, one JSON object per line. A logging failure never stops the engine.
    param([string]$Level, [string]$EventName, $Data = $null)
    if (-not $script:WhLogEnabled) { return }
    try {
        $dir = Join-Path (Get-WhStateDir) 'logs'
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        $rec = [ordered]@{ ts = (Get-WhUtcStamp); level = $Level; event = $EventName; data = $Data }
        Add-WhFileLine -Path (Join-Path $dir 'winharden.jsonl') -Line (ConvertTo-WhJson -Object $rec -Depth 6)
    }
    catch {
        $script:WhLogEnabled = $false
    }
}

function ConvertTo-WhUInt64 {
    # .NET returns registry integers signed: a DWord as Int32, a QWord as Int64. Manifests use plain non-negative numbers.
    # An Int32 is masked to 32 bits (sign extension would turn -1 into 2^64-1); an Int64 is reinterpreted as 64 bits.
    param($Value)
    if ($Value -is [int32]) { return [uint64]([int64]$Value -band 4294967295) }
    if ($Value -is [int64]) { return [System.BitConverter]::ToUInt64([System.BitConverter]::GetBytes([int64]$Value), 0) }
    return [uint64]$Value
}

function ConvertTo-WhDWord {
    # uint32 value -> the int32 that RegistryKey.SetValue expects.
    param($Value)
    $n = [int64](ConvertTo-WhUInt64 -Value $Value)
    if ($n -lt 0 -or $n -gt 4294967295) { throw ('DWord out of range: ' + $n) }
    if ($n -gt 2147483647) { $n = $n - 4294967296 }
    return [int32]$n
}

function ConvertTo-WhQWord {
    # uint64 value -> the int64 that RegistryKey.SetValue expects.
    param($Value)
    $u = ConvertTo-WhUInt64 -Value $Value
    return [System.BitConverter]::ToInt64([System.BitConverter]::GetBytes([uint64]$u), 0)
}
