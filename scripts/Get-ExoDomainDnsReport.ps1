#Requires -Version 5.1
<#
.SYNOPSIS
    Checks MX, SPF, DKIM, DMARC, MTA-STS and TLS-RPT for every accepted domain.

.DESCRIPTION
    Read-only. Combines public DNS lookups with Get-DkimSigningConfig. Works on Windows
    (Resolve-DnsName) and on PowerShell 7 for Linux / macOS (DNS-over-HTTPS fallback).

    SPF is evaluated for: a single v=spf1 record, the Exchange Online include, the 'all'
    qualifier and the 10-DNS-lookup limit (counted recursively).

.PARAMETER Domain
    Domains to check. Defaults to all accepted domains except *.onmicrosoft.com (whose SPF and
    DKIM are managed by Microsoft). Can be used without an Exchange connection when given.

.PARAMETER OutputPath
    Folder for CSV exports. Omit to only return the result object.

.EXAMPLE
    .\Get-ExoDomainDnsReport.ps1 -OutputPath .\out

.EXAMPLE
    .\Get-ExoDomainDnsReport.ps1 -Domain contoso.com, fabrikam.com
#>
[CmdletBinding()]
param(
    [string[]] $Domain,
    [string] $OutputPath
)

. (Join-Path $PSScriptRoot 'ExoHealth.Common.ps1')

$result = New-ExoSectionResult -Section 'Email Authentication (DNS)'
$connected = Test-ExoCommand 'Get-AcceptedDomain'

if (-not $Domain) {
    Assert-ExoConnection
    $Domain = @(Get-AcceptedDomain | Where-Object { "$($_.DomainName)" -notmatch '\.onmicrosoft\.com$' } | ForEach-Object { "$($_.DomainName)" })
}

$dkimConfigs = @()
if ($connected) {
    $dkimConfigs = Invoke-ExoSafe { Get-DkimSigningConfig } 'DKIM signing config' -Default @()
    $dkimConfigs = @($dkimConfigs | Where-Object { $_ })
}

function Get-SpfLookupCount {
    <#
        Counts DNS-querying mechanisms (include, a, mx, ptr, exists, redirect) recursively.
        RFC 7208 limits this to 10.
    #>
    param([string] $Record, [int] $Depth = 0, [System.Collections.Generic.HashSet[string]] $Seen)

    if (-not $Seen) { $Seen = New-Object 'System.Collections.Generic.HashSet[string]' }
    if ($Depth -gt 10) { return 0 }
    $count = 0
    foreach ($term in ($Record -split '\s+')) {
        $t = $term.TrimStart('+', '-', '~', '?').ToLowerInvariant()
        if ($t -match '^(include:|redirect=)(.+)$') {
            $count++
            $target = $Matches[2]
            if ($Seen.Add($target)) {
                $child = @(Resolve-ExoDnsRecord -Name $target -Type TXT | Where-Object { $_.Data -match '^v=spf1' }) | Select-Object -First 1
                if ($child) { $count += Get-SpfLookupCount -Record $child.Data -Depth ($Depth + 1) -Seen $Seen }
            }
        }
        elseif ($t -match '^(a|mx|ptr|exists)([:/]|$)') {
            $count++
        }
    }
    $count
}

$rows = New-Object System.Collections.Generic.List[object]

foreach ($d in $Domain) {
    $d = $d.Trim().ToLowerInvariant()
    Write-Verbose "Checking DNS for $d"

    # Look everything up first. If DNS itself fails, report "could not check" rather than
    # "record missing", and skip the domain.
    try {
        $dns = @{
            MX     = @(Resolve-ExoDnsRecord -Name $d -Type MX | Sort-Object Preference)
            TXT    = @(Resolve-ExoDnsRecord -Name $d -Type TXT)
            DMARC  = @(Resolve-ExoDnsRecord -Name "_dmarc.$d" -Type TXT)
            MTASTS = @(Resolve-ExoDnsRecord -Name "_mta-sts.$d" -Type TXT)
            TLSRPT = @(Resolve-ExoDnsRecord -Name "_smtp._tls.$d" -Type TXT)
            DKIM1  = @(Resolve-ExoDnsRecord -Name "selector1._domainkey.$d" -Type CNAME)
            DKIM2  = @(Resolve-ExoDnsRecord -Name "selector2._domainkey.$d" -Type CNAME)
        }
    }
    catch {
        Add-ExoFinding $result -Check 'DNS lookup' -Status Warning -Severity Medium -Target $d `
            -Detail "Could not query DNS, so MX/SPF/DKIM/DMARC were not checked: $($_.Exception.Message)" `
            -Recommendation 'Re-run from a machine with normal DNS access (Windows uses Resolve-DnsName; PowerShell 7 elsewhere needs HTTPS to cloudflare-dns.com or dns.google).'
        $rows.Add([pscustomobject]@{ Domain = $d; MX = ''; MxToEOP = $null; SPF = ''; SpfLookups = $null; DMARC = ''; DKIM = 'NotChecked'; MtaSts = $null; TlsRpt = $null })
        continue
    }

    # MX
    $mx = $dns.MX
    $mxHosts = @($mx | ForEach-Object { $_.Data })
    $mxToEop = @($mxHosts | Where-Object { $_ -match '\.mail\.protection\.outlook\.com$|\.mx\.microsoft$' })
    if ($mx.Count -eq 0) {
        Add-ExoFinding $result -Check 'MX record' -Status Warning -Severity Low -Target $d `
            -Detail 'No MX record. The domain cannot receive internet mail.' `
            -Recommendation 'If the domain only sends mail, publish a null MX (0 .) and SPF -all for unused subdomains.'
    }
    elseif ($mxToEop.Count -eq $mx.Count) {
        Add-ExoFinding $result -Check 'MX record' -Status Pass -Target $d -Detail "MX points to Exchange Online Protection: $($mxHosts -join ', ')."
    }
    else {
        Add-ExoFinding $result -Check 'MX record' -Status Info -Target $d `
            -Detail "MX points to a non-Microsoft host: $($mxHosts -join ', ')." `
            -Recommendation 'Mail passes through a third-party / on-premises gateway first: configure Enhanced Filtering for Connectors on the inbound connector.'
    }

    # SPF
    $txt = $dns.TXT
    $spf = @($txt | Where-Object { $_.Data -match '^v=spf1(\s|$)' })
    $spfRecord = ''
    $spfLookups = $null
    if ($spf.Count -eq 0) {
        Add-ExoFinding $result -Check 'SPF' -Status Fail -Severity High -Target $d `
            -Detail 'No SPF record.' -Recommendation "Publish: v=spf1 include:spf.protection.outlook.com -all"
    }
    elseif ($spf.Count -gt 1) {
        Add-ExoFinding $result -Check 'SPF' -Status Fail -Severity High -Target $d `
            -Detail "$($spf.Count) SPF records published; receivers treat this as a permanent error." `
            -Recommendation 'Merge into a single v=spf1 record.'
    }
    else {
        $spfRecord = $spf[0].Data
        try { $spfLookups = Get-SpfLookupCount -Record $spfRecord }
        catch {
            $spfLookups = $null
            Add-ExoFinding $result -Check 'SPF DNS lookup limit' -Status Info -Target $d -Detail "Could not count SPF lookups: $($_.Exception.Message)"
        }
        $all = if ($spfRecord -match '(?:^|\s)([+\-~?]?)all\s*$') { $Matches[1] } else { $null }

        if ($spfRecord -notmatch 'include:spf\.protection\.outlook\.com') {
            Add-ExoFinding $result -Check 'SPF includes Exchange Online' -Status Warning -Severity Medium -Target $d `
                -Detail 'SPF does not include spf.protection.outlook.com.' `
                -Recommendation 'Add include:spf.protection.outlook.com if Exchange Online sends mail for this domain.'
        }
        if ($null -eq $all) {
            Add-ExoFinding $result -Check 'SPF all qualifier' -Status Warning -Severity Medium -Target $d `
                -Detail 'SPF has no terminating all mechanism (defaults to neutral).' -Recommendation 'End the record with -all (or ~all while DMARC is enforcing).'
        }
        elseif ($all -in '+', '', '?') {
            $label = if ($all) { "${all}all" } else { 'all' }
            Add-ExoFinding $result -Check 'SPF all qualifier' -Status Fail -Severity High -Target $d `
                -Detail "SPF ends with '$label', which authorises any server to send as this domain." -Recommendation 'Use -all.'
        }
        else {
            Add-ExoFinding $result -Check 'SPF all qualifier' -Status Pass -Target $d -Detail "SPF ends with ${all}all."
        }

        if ($spfLookups -gt 10) {
            Add-ExoFinding $result -Check 'SPF DNS lookup limit' -Status Fail -Severity High -Target $d `
                -Detail "SPF needs $spfLookups DNS lookups (limit 10) - receivers return permerror." `
                -Recommendation 'Remove unused includes or move senders to subdomains.'
        }
        elseif ($spfLookups -ge 8) {
            Add-ExoFinding $result -Check 'SPF DNS lookup limit' -Status Warning -Severity Low -Target $d -Detail "SPF needs $spfLookups of 10 DNS lookups."
        }
    }

    # DMARC
    $dmarc = @($dns.DMARC | Where-Object { $_.Data -match '^v=DMARC1' })
    $dmarcRecord = ''
    if ($dmarc.Count -eq 0) {
        Add-ExoFinding $result -Check 'DMARC' -Status Fail -Severity High -Target $d `
            -Detail 'No DMARC record.' `
            -Recommendation "Start with v=DMARC1; p=none; rua=mailto:dmarc@$d, review reports, then move to quarantine and reject."
    }
    else {
        $dmarcRecord = $dmarc[0].Data
        $tags = @{}
        foreach ($part in ($dmarcRecord -split ';')) {
            $kv = $part.Trim() -split '=', 2
            if ($kv.Count -eq 2) { $tags[$kv[0].Trim().ToLowerInvariant()] = $kv[1].Trim() }
        }
        $policy = "$($tags['p'])".ToLowerInvariant()
        switch ($policy) {
            'reject' { Add-ExoFinding $result -Check 'DMARC policy' -Status Pass -Target $d -Detail 'p=reject.' }
            'quarantine' { Add-ExoFinding $result -Check 'DMARC policy' -Status Pass -Target $d -Detail 'p=quarantine.' -Recommendation 'Move to p=reject when reports are clean.' }
            'none' {
                Add-ExoFinding $result -Check 'DMARC policy' -Status Warning -Severity Medium -Target $d `
                    -Detail 'p=none: monitoring only, spoofed mail is still delivered.' -Recommendation 'Move to p=quarantine, then p=reject.'
            }
            default {
                Add-ExoFinding $result -Check 'DMARC policy' -Status Fail -Severity High -Target $d -Detail "Invalid or missing p= tag: '$dmarcRecord'."
            }
        }
        if (-not $tags.ContainsKey('rua')) {
            Add-ExoFinding $result -Check 'DMARC reporting' -Status Warning -Severity Low -Target $d `
                -Detail 'No rua= aggregate report address; you cannot see who sends as this domain.' -Recommendation 'Add rua=mailto:<reporting mailbox or service>.'
        }
        if ($tags.ContainsKey('pct') -and [int]$tags['pct'] -lt 100) {
            Add-ExoFinding $result -Check 'DMARC pct' -Status Info -Target $d -Detail "Policy applies to $($tags['pct'])% of failing mail."
        }
    }

    # DKIM
    $dkim = $dkimConfigs | Where-Object { "$($_.Domain)" -eq $d } | Select-Object -First 1
    $dkimStatus = 'Unknown'
    if ($connected) {
        if (-not $dkim) {
            $dkimStatus = 'NotConfigured'
            Add-ExoFinding $result -Check 'DKIM signing' -Status Fail -Severity Medium -Target $d `
                -Detail 'No DKIM signing configuration; mail is signed with the onmicrosoft.com domain and fails DMARC alignment on DKIM.' `
                -Recommendation "New-DkimSigningConfig -DomainName $d -Enabled `$false; publish the two CNAMEs; then Set-DkimSigningConfig -Identity $d -Enabled `$true"
        }
        elseif (-not $dkim.Enabled) {
            $dkimStatus = 'Disabled'
            Add-ExoFinding $result -Check 'DKIM signing' -Status Fail -Severity Medium -Target $d `
                -Detail "DKIM is configured but disabled (status: $(Get-ExoPropertyValue $dkim 'Status' 'n/a'))." `
                -Recommendation "Publish selector1/selector2 CNAMEs, then Set-DkimSigningConfig -Identity $d -Enabled `$true"
        }
        else {
            $dkimStatus = 'Enabled'
            Add-ExoFinding $result -Check 'DKIM signing' -Status Pass -Target $d -Detail 'DKIM signing enabled.'
            $keySize = Get-ExoPropertyValue $dkim 'Selector1KeySize' (Get-ExoPropertyValue $dkim 'KeySize' $null)
            if ($keySize -and [int]$keySize -lt 2048) {
                Add-ExoFinding $result -Check 'DKIM key size' -Status Warning -Severity Low -Target $d `
                    -Detail "Active key is $keySize bits." -Recommendation "Rotate-DkimSigningConfig -Identity $d -KeySize 2048"
            }
        }
    }
    foreach ($selector in 'selector1', 'selector2') {
        $cname = @(if ($selector -eq 'selector1') { $dns.DKIM1 } else { $dns.DKIM2 })
        if ($connected -and $dkim -and $cname.Count -eq 0) {
            Add-ExoFinding $result -Check 'DKIM CNAME' -Status Warning -Severity Medium -Target $d `
                -Detail "$selector._domainkey.$d CNAME is missing; key rotation will break DKIM." `
                -Recommendation "Publish: $selector._domainkey.$d CNAME $(Get-ExoPropertyValue $dkim "$($selector)CNAME" '<value from Get-DkimSigningConfig>')"
        }
    }

    if (-not $connected -and $dns.DKIM1.Count -eq 0 -and $dns.DKIM2.Count -eq 0) {
        $dkimStatus = 'NoSelectorCNAMEs'
        Add-ExoFinding $result -Check 'DKIM signing' -Status Warning -Severity Medium -Target $d `
            -Detail 'selector1/selector2._domainkey CNAMEs are not published, so Exchange Online is almost certainly not DKIM-signing with this domain (mail is signed as *.onmicrosoft.com and DKIM does not align for DMARC).' `
            -Recommendation "Connect to Exchange Online and run: New-DkimSigningConfig -DomainName $d -Enabled `$false; publish the CNAMEs from Get-DkimSigningConfig; then Set-DkimSigningConfig -Identity $d -Enabled `$true"
    }

    # MTA-STS and TLS-RPT
    $mtaSts = @($dns.MTASTS | Where-Object { $_.Data -match '^v=STSv1' })
    $tlsRpt = @($dns.TLSRPT | Where-Object { $_.Data -match '^v=TLSRPTv1' })
    if ($mtaSts.Count -eq 0 -and $mxToEop.Count -gt 0) {
        Add-ExoFinding $result -Check 'MTA-STS' -Status Info -Target $d `
            -Detail 'No MTA-STS policy: senders may fall back to unencrypted delivery under a downgrade attack.' `
            -Recommendation 'Publish _mta-sts TXT and host https://mta-sts.<domain>/.well-known/mta-sts.txt (or enable inbound SMTP DANE with DNSSEC).'
    }
    if ($tlsRpt.Count -eq 0 -and $mxToEop.Count -gt 0) {
        Add-ExoFinding $result -Check 'TLS-RPT' -Status Info -Target $d -Detail 'No TLS reporting record (_smtp._tls).' `
            -Recommendation 'Publish v=TLSRPTv1; rua=mailto:<address> to receive TLS failure reports.'
    }

    $rows.Add([pscustomobject]@{
            Domain     = $d
            MX         = $mxHosts -join '; '
            MxToEOP    = ($mxToEop.Count -gt 0 -and $mxToEop.Count -eq $mx.Count)
            SPF        = $spfRecord
            SpfLookups = $spfLookups
            DMARC      = $dmarcRecord
            DKIM       = $dkimStatus
            MtaSts     = ($mtaSts.Count -gt 0)
            TlsRpt     = ($tlsRpt.Count -gt 0)
        })
}

$result.Data['DomainAuthentication'] = $rows.ToArray()
if ($dkimConfigs.Count -gt 0) {
    $result.Data['DkimSigningConfig'] = @($dkimConfigs | ConvertTo-ExoFlatObject -Property Domain, Enabled, Status,
        Selector1CNAME, Selector2CNAME, Selector1KeySize, Selector2KeySize, RotateOnDate, LastChecked)
}

if ($OutputPath) { Export-ExoSectionResult -Result $result -OutputPath $OutputPath }
$result
