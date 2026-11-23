# winharden engine: Report.ps1
# Reports are local files, never uploaded: JSON (complete), HTML (for people), CSV (POA&M template for exceptions) and a
# minimal XCCDF 1.2 result export. Every report carries the Recall attestation line, whatever the profile.
# Windows PowerShell 5.1, ASCII only.

$script:WhRecallEntryId = 'ai-004-recall-attestation'

$script:WhLimits = @(
    'No entry in this tool has been verified on a real Windows 11 Home system. For entries whose Home effect is "unverified" (most policy values), PASS means the value is set and reads back correctly; it does not prove that Windows 11 Home acts on it.'
    'Audit commands that read HKCU describe the account that runs the tool. The state check reads every user profile.'
    'This is a check of this tool''s own settings. It is not a CIS, Microsoft security baseline or STIG scan, and the XCCDF file is a minimal result export that has not been validated with NIST tooling.'
    'Removed AppX packages can only be reinstalled from the Microsoft Store. Their local data is not restored.'
    'The journal is tamper-evident for everyone except an administrator, who can rewrite both the journal and its key.'
)

function Get-WhRecallAttestation {
    param($Results)
    $r = $null
    foreach ($x in @($Results)) { if ([string]$x.id -eq $script:WhRecallEntryId) { $r = $x } }
    if ($null -eq $r) {
        return [ordered]@{ status = 'not-checked'; text = ('NOT CHECKED: the Recall attestation entry (' + $script:WhRecallEntryId + ') was not part of this run.'); checks = @() }
    }
    $checks = @(@($r.audit_checks) | ForEach-Object { ([string]$_.status).ToUpperInvariant() + ': expected ' + $_.expected + ', found ' + $_.actual })
    if ([string]$r.status -eq 'pass') {
        return [ordered]@{ status = 'attested-off'; text = 'Recall is OFF and attested: the Recall Windows feature is not enabled, and the policies AllowRecallEnablement=0 and DisableAIDataAnalysis=1 are set.'; checks = $checks }
    }
    return [ordered]@{ status = 'not-attested'; text = ('Recall is NOT ATTESTED OFF. ' + [string]$r.reason); checks = $checks }
}

function New-WhReportModel {
    param($Results, $Facts, [int]$Level, [string]$ManifestHash, [string]$Kind, $Excluded, $ApplyResult, [string]$PlanId)
    $counts = Get-WhResultCounts -Results $Results
    $apply = $null
    if ($null -ne $ApplyResult) {
        $apply = [ordered]@{
            checkpoint = [string]$ApplyResult.checkpoint
            applied    = [int]$ApplyResult.applied
            failed     = [int]$ApplyResult.failed
            failures   = @(@($ApplyResult.results) | Where-Object { -not $_.ok } | ForEach-Object { [ordered]@{ entry = $_.entry; error = $_.error; manual = @($_.manual) } })
        }
    }
    return [ordered]@{
        tool          = 'winharden'
        engine        = $script:WhEngineVersion
        fingerprint   = [string]$script:WhFingerprint
        kind          = $Kind
        generated     = (Get-WhUtcStamp)
        computer      = [string](Get-WhProp -Object $Facts -Name 'computer' -Default '')
        profile_level = $Level
        plan          = $PlanId
        manifest_hash = $ManifestHash
        platform      = $Facts
        summary       = $counts
        recall        = (Get-WhRecallAttestation -Results $Results)
        apply         = $apply
        excluded      = @(@($Excluded) | ForEach-Object { [string]$_.id })
        limits        = $script:WhLimits
        entries       = @($Results)
    }
}

# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
function ConvertTo-WhHtml {
    param([string]$Text)
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function ConvertTo-WhHtmlReport {
    param($Model)
    $h = New-Object System.Text.StringBuilder
    [void]$h.AppendLine('<!DOCTYPE html>')
    [void]$h.AppendLine('<html lang="en"><head><meta charset="utf-8"><title>winharden report</title>')
    [void]$h.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:4px 8px;text-align:left;vertical-align:top;font-size:13px}th{background:#eee}.pass{color:#0a6b2d;font-weight:600}.fail{color:#a40000;font-weight:600}.error{color:#a45b00;font-weight:600}.na,.manual{color:#444;font-weight:600}.box{border:2px solid #333;padding:10px 14px;margin:14px 0}.ok{border-color:#0a6b2d}.bad{border-color:#a40000}code{font-size:12px}</style>')
    [void]$h.AppendLine('</head><body>')
    [void]$h.AppendLine('<h1>winharden report</h1>')
    [void]$h.AppendLine('<p>' + (ConvertTo-WhHtml ('Kind: ' + $Model.kind + '. Profile ' + $Model.profile_level + '. Generated ' + $Model.generated + ' (UTC). Computer ' + $Model.computer + '. Engine ' + $Model.engine + '.')) + '</p>')
    $boxClass = 'box bad'
    if ($Model.recall.status -eq 'attested-off') { $boxClass = 'box ok' }
    [void]$h.AppendLine('<div class="' + $boxClass + '"><h2>Recall attestation</h2><p><strong>' + (ConvertTo-WhHtml ([string]$Model.recall.text)) + '</strong></p>')
    foreach ($c in @($Model.recall.checks)) { [void]$h.AppendLine('<div><code>' + (ConvertTo-WhHtml ([string]$c)) + '</code></div>') }
    [void]$h.AppendLine('</div>')
    $s = $Model.summary
    [void]$h.AppendLine('<h2>Summary</h2><p>' + (ConvertTo-WhHtml ('pass ' + $s.pass + ', fail ' + $s.fail + ', error ' + $s.error + ', not applicable ' + $s.na + ', manual ' + $s.manual)) + '</p>')
    if ($null -ne $Model.apply) {
        [void]$h.AppendLine('<p>' + (ConvertTo-WhHtml ('Apply: checkpoint ' + $Model.apply.checkpoint + ', applied ' + $Model.apply.applied + ', failed and reverted ' + $Model.apply.failed + '.')) + '</p>')
    }
    [void]$h.AppendLine('<h2>Platform</h2><table><tr><th>Item</th><th>Value</th></tr>')
    foreach ($p in @($Model.platform.PSObject.Properties)) {
        [void]$h.AppendLine('<tr><td>' + (ConvertTo-WhHtml ([string]$p.Name)) + '</td><td>' + (ConvertTo-WhHtml ((@($p.Value) | ForEach-Object { [string]$_ }) -join ', ')) + '</td></tr>')
    }
    [void]$h.AppendLine('</table>')
    [void]$h.AppendLine('<h2>Entries</h2><table><tr><th>Id</th><th>Status</th><th>Mode</th><th>Profile</th><th>Risk</th><th>Home effect</th><th>Detail</th></tr>')
    foreach ($e in @($Model.entries)) {
        $detail = ConvertTo-WhHtml ([string]$e.reason)
        $more = New-Object System.Text.StringBuilder
        foreach ($c in @($e.state_checks)) { [void]$more.Append('<div>' + (ConvertTo-WhHtml ([string]$c.status + ': ' + [string]$c.label + ' - ' + [string]$c.detail)) + '</div>') }
        foreach ($c in @($e.audit_checks)) { [void]$more.Append('<div>' + (ConvertTo-WhHtml ('audit ' + [string]$c.status + ': expected ' + [string]$c.expected + ', found ' + [string]$c.actual)) + '</div>') }
        if ([string]$e.status -eq 'manual') {
            [void]$more.Append('<div>' + (ConvertTo-WhHtml ([string]$e.manual_check)) + '</div>')
            foreach ($step in @($e.manual_steps)) { [void]$more.Append('<div>- ' + (ConvertTo-WhHtml ([string]$step)) + '</div>') }
        }
        [void]$h.AppendLine('<tr><td><code>' + (ConvertTo-WhHtml ([string]$e.id)) + '</code><br>' + (ConvertTo-WhHtml ([string]$e.title)) + '</td><td class="' + $e.status + '">' + (ConvertTo-WhHtml ([string]$e.status).ToUpperInvariant()) + '</td><td>' + $e.mode + '</td><td>' + $e.min_profile + '</td><td>' + $e.risk + '</td><td>' + $e.home_effective + '</td><td>' + $detail + '<details><summary>checks</summary>' + $more.ToString() + '</details></td></tr>')
    }
    [void]$h.AppendLine('</table>')
    [void]$h.AppendLine('<h2>Limits of this report</h2><ul>')
    foreach ($l in @($Model.limits)) { [void]$h.AppendLine('<li>' + (ConvertTo-WhHtml ([string]$l)) + '</li>') }
    [void]$h.AppendLine('</ul></body></html>')
    return $h.ToString()
}

# ---------------------------------------------------------------------------
# CSV (POA&M template) and XCCDF
# ---------------------------------------------------------------------------
function ConvertTo-WhCsvField {
    # Quoted, and neutralised against spreadsheet formula injection.
    param([string]$Text)
    if ($Text -match '^[=+\-@]') { $Text = "'" + $Text }
    return ('"' + $Text.Replace('"', '""') + '"')
}

function ConvertTo-WhPoamCsv {
    param($Model)
    $expiry = ([DateTime]::UtcNow.AddDays(90)).ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('ID,Title,Status,Risk,Finding,Owner,Justification,Planned action,Expiry')
    foreach ($e in @($Model.entries)) {
        $st = [string]$e.status
        if (@('fail', 'error', 'na', 'manual') -notcontains $st) { continue }
        $finding = [string]$e.reason
        if (($st -eq 'manual') -and ([string]$e.manual_check -ne '')) { $finding = [string]$e.manual_check }
        $just = ''
        $action = 'Run apply again, or write down why this setting stays as it is.'
        if ($st -eq 'na') { $just = [string]$e.reason; $action = 'None: not applicable on this system.' }
        if ($st -eq 'manual') { $action = 'Follow the manual steps and confirm the result.' }
        $fields = @([string]$e.id, [string]$e.title, $st, [string]$e.risk, $finding, 'unassigned', $just, $action, $expiry)
        $lines.Add((@($fields | ForEach-Object { ConvertTo-WhCsvField -Text ([string]$_) }) -join ','))
    }
    return ($lines.ToArray() -join "`r`n") + "`r`n"
}

function Add-WhXmlChild {
    param($Doc, $Parent, [string]$Name, [string]$Text = '', $Attributes = $null)
    $el = $Doc.CreateElement($Name, 'http://checklists.nist.gov/xccdf/1.2')
    if ($Text -ne '') { $el.InnerText = $Text }
    if ($null -ne $Attributes) { foreach ($k in @($Attributes.Keys)) { $el.SetAttribute([string]$k, [string]$Attributes[$k]) } }
    [void]$Parent.AppendChild($el)
    return $el
}

function ConvertTo-WhXccdf {
    param($Model)
    $doc = New-Object System.Xml.XmlDocument
    [void]$doc.AppendChild($doc.CreateXmlDeclaration('1.0', 'UTF-8', $null))
    $bench = Add-WhXmlChild -Doc $doc -Parent $doc -Name 'Benchmark' -Attributes @{ id = 'xccdf_org.winharden_benchmark_win11home'; resolved = '1' }
    [void](Add-WhXmlChild -Doc $doc -Parent $bench -Name 'status' -Text 'draft')
    [void](Add-WhXmlChild -Doc $doc -Parent $bench -Name 'title' -Text 'winharden settings for Windows 11 Home')
    [void](Add-WhXmlChild -Doc $doc -Parent $bench -Name 'description' -Text 'Result export of the settings that winharden manages. Not a CIS, Microsoft baseline or STIG benchmark.')
    [void](Add-WhXmlChild -Doc $doc -Parent $bench -Name 'version' -Text ([string]$Model.engine))
    $prof = Add-WhXmlChild -Doc $doc -Parent $bench -Name 'Profile' -Attributes @{ id = ('xccdf_org.winharden_profile_' + $Model.profile_level) }
    [void](Add-WhXmlChild -Doc $doc -Parent $prof -Name 'title' -Text ('winharden profile ' + $Model.profile_level))
    foreach ($e in @($Model.entries)) {
        [void](Add-WhXmlChild -Doc $doc -Parent $prof -Name 'select' -Attributes @{ idref = ('xccdf_org.winharden_rule_' + $e.id); selected = 'true' })
    }
    foreach ($e in @($Model.entries)) {
        $rule = Add-WhXmlChild -Doc $doc -Parent $bench -Name 'Rule' -Attributes @{ id = ('xccdf_org.winharden_rule_' + $e.id); selected = 'true'; severity = [string]$e.risk }
        [void](Add-WhXmlChild -Doc $doc -Parent $rule -Name 'title' -Text ([string]$e.title))
        [void](Add-WhXmlChild -Doc $doc -Parent $rule -Name 'description' -Text ([string]$e.rationale))
        $check = Add-WhXmlChild -Doc $doc -Parent $rule -Name 'check' -Attributes @{ system = 'urn:winharden:powershell-audit' }
        $text = ((@($e.audit_checks) | ForEach-Object { [string]$_.command + ' => ' + [string]$_.expected }) -join "`n")
        if ($text -eq '') { $text = [string]$e.manual_check }
        if ($text -eq '') { $text = 'state check by the engine' }
        [void](Add-WhXmlChild -Doc $doc -Parent $check -Name 'check-content' -Text $text)
    }
    $stamp = ([string]$Model.generated).Substring(0, 19) + 'Z'
    $tr = Add-WhXmlChild -Doc $doc -Parent $bench -Name 'TestResult' -Attributes @{ id = 'xccdf_org.winharden_testresult_1'; 'start-time' = $stamp; 'end-time' = $stamp; version = [string]$Model.engine }
    [void](Add-WhXmlChild -Doc $doc -Parent $tr -Name 'title' -Text 'winharden run')
    [void](Add-WhXmlChild -Doc $doc -Parent $tr -Name 'target' -Text ([string]$Model.computer))
    $map = @{ pass = 'pass'; fail = 'fail'; error = 'error'; na = 'notapplicable'; manual = 'notchecked' }
    foreach ($e in @($Model.entries)) {
        $rr = Add-WhXmlChild -Doc $doc -Parent $tr -Name 'rule-result' -Attributes @{ idref = ('xccdf_org.winharden_rule_' + $e.id); time = $stamp; severity = [string]$e.risk }
        [void](Add-WhXmlChild -Doc $doc -Parent $rr -Name 'result' -Text ([string]$map[[string]$e.status]))
        if ([string]$e.reason -ne '') { [void](Add-WhXmlChild -Doc $doc -Parent $rr -Name 'message' -Text ([string]$e.reason) -Attributes @{ severity = 'info' }) }
    }
    return $doc.OuterXml
}

function Write-WhReports {
    param($Model, [string]$Directory)
    [void](Initialize-WhDirectory -Path $Directory)
    $paths = [ordered]@{
        json  = (Join-Path $Directory 'winharden-report.json')
        html  = (Join-Path $Directory 'winharden-report.html')
        poam  = (Join-Path $Directory 'winharden-poam.csv')
        xccdf = (Join-Path $Directory 'winharden-xccdf.xml')
    }
    Write-WhFile -Path $paths.json -Text (ConvertTo-WhJson -Object $Model -Depth 10 -Pretty)
    Write-WhFile -Path $paths.html -Text (ConvertTo-WhHtmlReport -Model $Model)
    Write-WhFile -Path $paths.poam -Text (ConvertTo-WhPoamCsv -Model $Model)
    Write-WhFile -Path $paths.xccdf -Text (ConvertTo-WhXccdf -Model $Model)
    return $paths
}

function Format-WhVerifySummary {
    param($Model)
    Write-WhLine ''
    Write-WhLine ('Result: pass ' + $Model.summary.pass + ', fail ' + $Model.summary.fail + ', error ' + $Model.summary.error + ', not applicable ' + $Model.summary.na + ', manual ' + $Model.summary.manual)
    $color = 'Yellow'
    if ($Model.recall.status -eq 'attested-off') { $color = 'Green' }
    Write-WhLine ($Model.recall.text) $color
    foreach ($e in @($Model.entries)) {
        if (@('fail', 'error') -contains [string]$e.status) { Write-WhLine ('  ' + ([string]$e.status).ToUpperInvariant() + '  ' + $e.id + '  ' + $e.reason) 'Yellow' }
    }
}
