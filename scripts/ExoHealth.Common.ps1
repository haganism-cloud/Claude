#Requires -Version 5.1
<#
.SYNOPSIS
    Shared helper functions for the Exchange Online tenant health scripts.

.DESCRIPTION
    Dot-source this file from the report scripts:

        . (Join-Path $PSScriptRoot 'ExoHealth.Common.ps1')

    Every report script returns a "section result": an object with a Section name,
    a list of Findings, and a Data dictionary (name -> rows) for export.

    Read-only. Nothing in this file changes tenant configuration.
#>

Set-StrictMode -Version 2.0

#region Findings and section results

function New-ExoFinding {
    <#
    .SYNOPSIS
        Creates a standard finding object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Section,
        [Parameter(Mandatory)] [string] $Check,
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Warning', 'Fail', 'Info')] [string] $Status,
        [ValidateSet('High', 'Medium', 'Low', 'Info')] [string] $Severity = 'Info',
        [string] $Target = '',
        [string] $Detail = '',
        [string] $Recommendation = ''
    )

    # Passing checks carry no risk, whatever severity the caller passed.
    if ($Status -eq 'Pass') { $Severity = 'Info' }

    [pscustomobject]@{
        Section        = $Section
        Check          = $Check
        Status         = $Status
        Severity       = $Severity
        Target         = $Target
        Detail         = $Detail
        Recommendation = $Recommendation
    }
}

function New-ExoSectionResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Section)

    [pscustomobject]@{
        Section  = $Section
        Findings = New-Object System.Collections.Generic.List[object]
        Data     = [ordered]@{}
    }
}

function Add-ExoFinding {
    <#
    .SYNOPSIS
        Creates a finding and appends it to a section result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] [string] $Check,
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Warning', 'Fail', 'Info')] [string] $Status,
        [ValidateSet('High', 'Medium', 'Low', 'Info')] [string] $Severity = 'Info',
        [string] $Target = '',
        [string] $Detail = '',
        [string] $Recommendation = ''
    )

    $finding = New-ExoFinding -Section $Result.Section -Check $Check -Status $Status -Severity $Severity `
        -Target $Target -Detail $Detail -Recommendation $Recommendation
    $Result.Findings.Add($finding)
}

#endregion

#region Safe execution

function Test-ExoCommand {
    <#
    .SYNOPSIS
        True when a cmdlet is available in the current session (licence / role / module dependent).
    #>
    param([Parameter(Mandatory)] [string] $Name)
    [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Invoke-ExoSafe {
    <#
    .SYNOPSIS
        Runs a script block, returning $Default and a warning instead of throwing.

    .DESCRIPTION
        Many Exchange Online cmdlets depend on licensing (for example Defender for
        Office 365) or RBAC. A report must keep going when one of them fails, so
        each data collection call is wrapped in this function.

        Returns an array (possibly empty) on success, or $Default (default $null) on
        failure, so callers can tell "nothing configured" from "could not read".
        With -Single, returns the first object only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [scriptblock] $ScriptBlock,
        [Parameter(Mandatory, Position = 1)] [string] $Description,
        $Default = $null,
        [switch] $Single
    )

    $ErrorActionPreference = 'Stop'
    try {
        Write-Verbose "Collecting: $Description"
        $output = @(& $ScriptBlock)
        if ($Single) { return $output | Select-Object -First 1 }
        , $output
    }
    catch {
        Write-Warning "Could not collect '$Description': $($_.Exception.Message)"
        if ($Default -is [array]) { , $Default } else { $Default }
    }
}

function Assert-ExoConnection {
    <#
    .SYNOPSIS
        Throws when there is no Exchange Online PowerShell connection.
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-ExoCommand 'Get-OrganizationConfig')) {
        throw 'Not connected to Exchange Online. Run .\Connect-ExoTenant.ps1 (or Connect-ExchangeOnline) first.'
    }
}

#endregion

#region Data shaping

function ConvertTo-ExoFlatValue {
    <#
    .SYNOPSIS
        Turns multi-valued properties into a single '; '-joined string for CSV / HTML.
    #>
    param($Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm') }
    if ($Value -is [System.Collections.IEnumerable]) {
        return (@($Value | ForEach-Object { "$_" }) -join '; ')
    }
    "$Value"
}

function ConvertTo-ExoFlatObject {
    <#
    .SYNOPSIS
        Projects objects onto the given properties and flattens multi-valued properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $InputObject,
        [string[]] $Property
    )

    process {
        if ($null -eq $InputObject) { return }
        $names = if ($Property) { $Property } else { $InputObject.PSObject.Properties.Name }
        $row = [ordered]@{}
        foreach ($name in $names) {
            $prop = $InputObject.PSObject.Properties[$name]
            $row[$name] = if ($prop) { ConvertTo-ExoFlatValue $prop.Value } else { '' }
        }
        [pscustomobject]$row
    }
}

function Get-ExoPropertyValue {
    <#
    .SYNOPSIS
        Reads a property that may not exist on older objects / tenants, returning $Default.
    #>
    param($InputObject, [string] $Name, $Default = $null)

    if ($null -eq $InputObject) { return $Default }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($prop) { $prop.Value } else { $Default }
}

function Get-ExoSmtpDomain {
    <#
    .SYNOPSIS
        Returns the domain part of an SMTP address ('smtp:' prefixes allowed), lower-cased.
    #>
    param([string] $Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return '' }
    $clean = $Address -replace '^(smtp|SMTP):', ''
    if ($clean -notmatch '@') { return '' }
    ($clean.Split('@')[-1]).Trim().ToLowerInvariant()
}

function Test-ExoExternalAddress {
    <#
    .SYNOPSIS
        True when an address is outside the tenant's accepted domains (subdomains count as internal
        only when the accepted domain has MatchSubDomains set).
    #>
    param(
        [string] $Address,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $AcceptedDomains
    )

    $domain = Get-ExoSmtpDomain $Address
    if (-not $domain) { return $false }
    foreach ($ad in $AcceptedDomains) {
        $name = "$($ad.DomainName)".ToLowerInvariant()
        if ($domain -eq $name) { return $false }
        if ((Get-ExoPropertyValue $ad 'MatchSubDomains' $false) -and $domain.EndsWith(".$name")) { return $false }
    }
    $true
}

#endregion

#region DNS

function Resolve-ExoDnsRecord {
    <#
    .SYNOPSIS
        Cross-platform DNS lookup returning normalised records.

    .DESCRIPTION
        Uses Resolve-DnsName on Windows. Elsewhere (PowerShell 7 on Linux / macOS) it falls
        back to Cloudflare DNS-over-HTTPS. Emits objects with Name, Type, Data and, for MX,
        Preference. Emits nothing when the name does not exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('TXT', 'MX', 'CNAME', 'A', 'TLSA')] [string] $Type,
        [string] $DohEndpoint = 'https://cloudflare-dns.com/dns-query'
    )

    $records = New-Object System.Collections.Generic.List[object]

    if (Test-ExoCommand 'Resolve-DnsName') {
        try {
            $answers = Resolve-DnsName -Name $Name -Type $Type -DnsOnly -ErrorAction Stop
        }
        catch {
            Write-Verbose "DNS $Type $Name : $($_.Exception.Message)"
            return
        }
        foreach ($a in $answers) {
            # Resolve-DnsName also returns CNAME hops and SOA records; keep only the requested type.
            if ("$($a.Type)" -ne $Type) { continue }
            switch ($Type) {
                'TXT'   { $records.Add([pscustomobject]@{ Name = $a.Name; Type = 'TXT'; Data = (@($a.Strings) -join ''); Preference = $null }) }
                'MX'    { $records.Add([pscustomobject]@{ Name = $a.Name; Type = 'MX'; Data = "$($a.NameExchange)".TrimEnd('.'); Preference = [int]$a.Preference }) }
                'CNAME' { $records.Add([pscustomobject]@{ Name = $a.Name; Type = 'CNAME'; Data = "$($a.NameHost)".TrimEnd('.'); Preference = $null }) }
                'A'     { $records.Add([pscustomobject]@{ Name = $a.Name; Type = 'A'; Data = "$($a.IPAddress)"; Preference = $null }) }
                default { $records.Add([pscustomobject]@{ Name = $a.Name; Type = $Type; Data = "$a"; Preference = $null }) }
            }
        }
        return $records.ToArray()
    }

    # DNS-over-HTTPS fallback (JSON API).
    $typeCodes = @{ A = 1; CNAME = 5; MX = 15; TXT = 16; TLSA = 52 }
    try {
        $uri = '{0}?name={1}&type={2}' -f $DohEndpoint, [uri]::EscapeDataString($Name), $Type
        $response = Invoke-RestMethod -Uri $uri -Headers @{ Accept = 'application/dns-json' } -TimeoutSec 15 -ErrorAction Stop
    }
    catch {
        Write-Warning "DNS-over-HTTPS lookup failed for $Type $Name : $($_.Exception.Message)"
        return
    }

    $answerProp = $response.PSObject.Properties['Answer']
    if (-not $answerProp) { return }
    foreach ($a in @($answerProp.Value)) {
        if ([int]$a.type -ne $typeCodes[$Type]) { continue }
        $data = "$($a.data)"
        switch ($Type) {
            'TXT' {
                # Long TXT records arrive as several quoted strings: "part1" "part2".
                $data = ($data.Trim() -replace '"\s+"', '').Trim('"')
                $records.Add([pscustomobject]@{ Name = $a.name.TrimEnd('.'); Type = 'TXT'; Data = $data; Preference = $null })
            }
            'MX' {
                $parts = $data.Split(' ', 2)
                $records.Add([pscustomobject]@{ Name = $a.name.TrimEnd('.'); Type = 'MX'; Data = $parts[1].TrimEnd('.'); Preference = [int]$parts[0] })
            }
            default {
                $records.Add([pscustomobject]@{ Name = $a.name.TrimEnd('.'); Type = $Type; Data = $data.TrimEnd('.'); Preference = $null })
            }
        }
    }
    $records.ToArray()
}

#endregion

#region Export and HTML report

function Export-ExoSectionResult {
    <#
    .SYNOPSIS
        Writes a section's findings and data tables to CSV files under $OutputPath.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] [string] $OutputPath
    )

    if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
    $prefix = $Result.Section -replace '[^A-Za-z0-9]', ''

    $Result.Findings | Export-Csv -Path (Join-Path $OutputPath "$prefix-Findings.csv") -NoTypeInformation -Encoding UTF8
    foreach ($key in $Result.Data.Keys) {
        $rows = @($Result.Data[$key])
        if ($rows.Count -eq 0) { continue }
        $file = Join-Path $OutputPath ('{0}-{1}.csv' -f $prefix, ($key -replace '[^A-Za-z0-9]', ''))
        $rows | ConvertTo-ExoFlatObject | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    }
}

function Get-ExoSeverityRank {
    param([string] $Status, [string] $Severity)
    $statusRank = @{ Fail = 0; Warning = 1; Info = 2; Pass = 3 }[$Status]
    $severityRank = @{ High = 0; Medium = 1; Low = 2; Info = 3 }[$Severity]
    ($statusRank * 10) + $severityRank
}

function ConvertTo-ExoHtmlTable {
    param([object[]] $Rows, [int] $MaxRows = 250)

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
    $rows = @($Rows | Where-Object { $null -ne $_ } | ConvertTo-ExoFlatObject)
    if ($rows.Count -eq 0) { return '<p class="muted">No rows.</p>' }

    $cols = $rows[0].PSObject.Properties.Name
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="scroll"><table><thead><tr>')
    foreach ($c in $cols) { [void]$sb.Append("<th>$(& $enc $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in ($rows | Select-Object -First $MaxRows)) {
        [void]$sb.Append('<tr>')
        foreach ($c in $cols) {
            $v = $r.$c
            $cls = ''
            if ($c -eq 'Status') { $cls = " class=""st-$v""" }
            [void]$sb.Append("<td$cls>$(& $enc $v)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($rows.Count -gt $MaxRows) {
        [void]$sb.Append("<p class=""muted"">Showing $MaxRows of $($rows.Count) rows. See the CSV export for the full list.</p>")
    }
    $sb.ToString()
}

function New-ExoHtmlReport {
    <#
    .SYNOPSIS
        Builds a single self-contained HTML report from one or more section results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Sections,
        [Parameter(Mandatory)] [string] $Path,
        [string] $TenantName = 'Exchange Online tenant'
    )

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
    $allFindings = @($Sections | ForEach-Object { $_.Findings })
    $sorted = @($allFindings | Sort-Object { Get-ExoSeverityRank $_.Status $_.Severity }, Section, Check)

    $count = { param($st) @($allFindings | Where-Object Status -eq $st).Count }
    $high = @($allFindings | Where-Object { $_.Status -in 'Fail', 'Warning' -and $_.Severity -eq 'High' }).Count

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exchange Online Health Report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#5d6675;--line:#dde1e7;--pass:#1f7a3d;--warn:#9a6200;--fail:#b3261e;--info:#2a5db0}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--fg:#e6e9ee;--muted:#9aa3b2;--line:#323843;--pass:#5cc584;--warn:#e7b04a;--fail:#f07b72;--info:#7fa8ef}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px;font-size:24px}h2{margin:32px 0 8px;font-size:19px}h3{margin:20px 0 6px;font-size:15px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}.tile b{display:block;font-size:26px}
.scroll{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{position:sticky;top:0;background:var(--card)}td{max-width:480px;overflow-wrap:anywhere}
.st-Pass{color:var(--pass);font-weight:600}.st-Warning{color:var(--warn);font-weight:600}.st-Fail{color:var(--fail);font-weight:600}.st-Info{color:var(--info)}
td[class^=st-]{white-space:nowrap}details{margin:6px 0}summary{cursor:pointer;font-weight:600}
</style></head><body><main>
<h1>Exchange Online Health Report</h1>
<p class="muted">$(& $enc $TenantName) &middot; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; read-only assessment</p>
<div class="tiles">
<div class="tile"><b class="st-Fail">$(& $count 'Fail')</b>Fail</div>
<div class="tile"><b class="st-Warning">$(& $count 'Warning')</b>Warning</div>
<div class="tile"><b class="st-Pass">$(& $count 'Pass')</b>Pass</div>
<div class="tile"><b class="st-Info">$(& $count 'Info')</b>Info</div>
<div class="tile"><b class="st-Fail">$high</b>High-severity issues</div>
</div>
<h2>Findings needing attention</h2>
"@)

    $issues = @($sorted | Where-Object Status -in 'Fail', 'Warning')
    if ($issues.Count -gt 0) {
        [void]$sb.Append((ConvertTo-ExoHtmlTable -Rows $issues -MaxRows 1000))
    }
    else {
        [void]$sb.Append('<p>No failing or warning checks.</p>')
    }

    foreach ($section in $Sections) {
        [void]$sb.Append("<h2>$(& $enc $section.Section)</h2>")
        $sf = @($section.Findings | Sort-Object { Get-ExoSeverityRank $_.Status $_.Severity }, Check)
        [void]$sb.Append('<h3>All checks</h3>')
        [void]$sb.Append((ConvertTo-ExoHtmlTable -Rows ($sf | Select-Object Check, Status, Severity, Target, Detail, Recommendation) -MaxRows 1000))
        foreach ($key in $section.Data.Keys) {
            $rows = @($section.Data[$key])
            [void]$sb.Append("<details><summary>$(& $enc $key) ($($rows.Count))</summary>")
            [void]$sb.Append((ConvertTo-ExoHtmlTable -Rows $rows))
            [void]$sb.Append('</details>')
        }
    }

    [void]$sb.Append('</main></body></html>')
    $sb.ToString() | Set-Content -Path $Path -Encoding UTF8
    Get-Item $Path
}

#endregion
