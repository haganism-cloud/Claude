#Requires -Version 5.1
<#
.SYNOPSIS
    Compares a tenant against its recorded known-good baseline (a .psd1 tenant profile) and
    reports drift: wrong tenant, DNS records that changed, unexpected domains, connectors or
    mail flow rules.

.DESCRIPTION
    Read-only. The other reports judge a tenant against best practice; this one judges it against
    what YOU expect it to look like, so a new connector, a changed SPF record or a new transport
    rule shows up even when it is technically valid.

    Baseline keys (all optional except TenantName):

        @{
            TenantName  = 'contoso.com'
            TenantId    = '<guid>'                     # connected tenant must match
            Dns         = @{
                'contoso.com' = @{
                    Mx          = @('contoso-com.mail.protection.outlook.com')
                    Spf         = 'v=spf1 include:spf.protection.outlook.com -all'
                    DmarcPolicy = 'quarantine'           # minimum acceptable: none | quarantine | reject
                    DkimCnames  = $true                  # selector1/2 CNAMEs must exist
                }
            }
            Exchange    = @{
                AcceptedDomains    = @('contoso.com')    # custom domains; *.onmicrosoft.com ignored
                InboundConnectors  = @()                 # names allowed to exist; $null = do not check
                OutboundConnectors = @()
                TransportRules     = $null
            }
        }

.PARAMETER BaselinePath
    Path to the tenant profile .psd1.

.PARAMETER OutputPath
    Folder for CSV exports. Omit to only return the result object.

.EXAMPLE
    .\Get-ExoBaselineReport.ps1 -BaselinePath ..\tenants\haganism.net\haganism.net.psd1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $BaselinePath,
    [string] $OutputPath
)

. (Join-Path $PSScriptRoot 'ExoHealth.Common.ps1')

$baseline = Import-PowerShellDataFile -Path $BaselinePath
$result = New-ExoSectionResult -Section 'Baseline Drift'
$connected = Test-ExoCommand 'Get-OrganizationConfig'
$drift = New-Object System.Collections.Generic.List[object]

function Add-Drift {
    param([string] $Area, [string] $Item, $Expected, $Actual)
    $drift.Add([pscustomobject]@{
            Area     = $Area
            Item     = $Item
            Expected = ConvertTo-ExoFlatValue $Expected
            Actual   = ConvertTo-ExoFlatValue $Actual
        })
}

function Compare-ExoNameList {
    <# Flags names present but not in the allowed list, and allowed names that are missing. #>
    param([string] $Area, [string[]] $Allowed, [string[]] $Actual, [string] $Severity = 'Medium')

    $Allowed = @($Allowed | Where-Object { $_ })
    $Actual = @($Actual | Where-Object { $_ })
    $extra = @($Actual | Where-Object { $Allowed -notcontains $_ })
    $missing = @($Allowed | Where-Object { $Actual -notcontains $_ })

    foreach ($e in $extra) {
        Add-ExoFinding $result -Check "Unexpected $Area" -Status Warning -Severity $Severity -Target $e `
            -Detail "'$e' exists but is not in the baseline." `
            -Recommendation 'Confirm who created it and why (Search-UnifiedAuditLog). If approved, add it to the tenant profile.'
        Add-Drift $Area $e '(absent)' 'present'
    }
    foreach ($m in $missing) {
        Add-ExoFinding $result -Check "Missing $Area" -Status Warning -Severity Medium -Target $m `
            -Detail "'$m' is in the baseline but no longer exists." `
            -Recommendation 'Confirm the removal was intended, then update the tenant profile.'
        Add-Drift $Area $m 'present' '(absent)'
    }
    if ($extra.Count -eq 0 -and $missing.Count -eq 0) {
        Add-ExoFinding $result -Check "$Area match baseline" -Status Pass -Detail "$($Actual.Count) present, all expected."
    }
}

#region Tenant identity

if ($baseline.ContainsKey('TenantId') -and $connected -and (Test-ExoCommand 'Get-ConnectionInformation')) {
    $conn = Get-ConnectionInformation | Select-Object -First 1
    $actualId = "$(Get-ExoPropertyValue $conn 'TenantID' '')"
    if ($actualId -and $actualId -ne $baseline.TenantId) {
        Add-ExoFinding $result -Check 'Connected tenant' -Status Fail -Severity High -Target $actualId `
            -Detail "Connected to tenant $actualId, but the profile is for $($baseline.TenantName) ($($baseline.TenantId)). Every other result in this report describes the wrong tenant." `
            -Recommendation 'Disconnect-ExchangeOnline and sign in with an account from the correct tenant.'
    }
    elseif ($actualId) {
        Add-ExoFinding $result -Check 'Connected tenant' -Status Pass -Target $actualId -Detail "Matches $($baseline.TenantName)."
    }
}

#endregion

#region DNS

if ($baseline.ContainsKey('Dns')) {
    $rank = @{ none = 0; quarantine = 1; reject = 2 }
    foreach ($domain in $baseline.Dns.Keys) {
        $want = $baseline.Dns[$domain]
        try {
            if ($want.ContainsKey('Mx')) {
                $mx = @(Resolve-ExoDnsRecord -Name $domain -Type MX | ForEach-Object { $_.Data.ToLowerInvariant() } | Sort-Object)
                $expected = @($want.Mx | ForEach-Object { $_.ToLowerInvariant().TrimEnd('.') } | Sort-Object)
                if (($mx -join ',') -ne ($expected -join ',')) {
                    Add-ExoFinding $result -Check 'MX changed' -Status Fail -Severity High -Target $domain `
                        -Detail "MX is '$($mx -join ', ')'; baseline is '$($expected -join ', ')'. Inbound mail may be going somewhere else." `
                        -Recommendation 'Check the DNS host change history immediately; a hijacked MX diverts all inbound mail.'
                    Add-Drift 'MX' $domain $expected $mx
                }
                else { Add-ExoFinding $result -Check 'MX matches baseline' -Status Pass -Target $domain -Detail ($mx -join ', ') }
            }

            if ($want.ContainsKey('Spf')) {
                $spf = @(Resolve-ExoDnsRecord -Name $domain -Type TXT | Where-Object { $_.Data -match '^v=spf1(\s|$)' } | ForEach-Object { $_.Data })
                $norm = { param($v) ($v -replace '\s+', ' ').Trim().ToLowerInvariant() }
                if ($spf.Count -ne 1 -or (& $norm $spf[0]) -ne (& $norm $want.Spf)) {
                    Add-ExoFinding $result -Check 'SPF changed' -Status Warning -Severity High -Target $domain `
                        -Detail "SPF is '$($spf -join ' | ')'; baseline is '$($want.Spf)'." `
                        -Recommendation 'Confirm the change was approved: an added include authorises a new service to send as this domain.'
                    Add-Drift 'SPF' $domain $want.Spf $spf
                }
                else { Add-ExoFinding $result -Check 'SPF matches baseline' -Status Pass -Target $domain -Detail $spf[0] }
            }

            if ($want.ContainsKey('DmarcPolicy')) {
                $dmarc = @(Resolve-ExoDnsRecord -Name "_dmarc.$domain" -Type TXT | Where-Object { $_.Data -match '^v=DMARC1' }) | Select-Object -First 1
                $policy = if ($dmarc -and $dmarc.Data -match '(?:^|;)\s*p\s*=\s*(\w+)') { $Matches[1].ToLowerInvariant() } else { '(none published)' }
                $minimum = $want.DmarcPolicy.ToLowerInvariant()
                if (-not $rank.ContainsKey($policy) -or $rank[$policy] -lt $rank[$minimum]) {
                    Add-ExoFinding $result -Check 'DMARC weaker than baseline' -Status Fail -Severity High -Target $domain `
                        -Detail "DMARC policy is '$policy'; baseline minimum is '$minimum'." `
                        -Recommendation "Restore p=$minimum (or stronger) on _dmarc.$domain."
                    Add-Drift 'DMARC' $domain "p=$minimum or stronger" $policy
                }
                else { Add-ExoFinding $result -Check 'DMARC meets baseline' -Status Pass -Target $domain -Detail "p=$policy (minimum $minimum)." }
            }

            if ($want.ContainsKey('DkimCnames') -and $want.DkimCnames) {
                $missing = @('selector1', 'selector2' | Where-Object { @(Resolve-ExoDnsRecord -Name "$_._domainkey.$domain" -Type CNAME).Count -eq 0 })
                if ($missing.Count -gt 0) {
                    Add-ExoFinding $result -Check 'DKIM CNAMEs missing' -Status Fail -Severity Medium -Target $domain `
                        -Detail "Baseline requires DKIM, but these CNAMEs are not published: $(($missing | ForEach-Object { "$_._domainkey.$domain" }) -join ', ')." `
                        -Recommendation 'Publish the CNAME values from Get-DkimSigningConfig and keep signing enabled.'
                    Add-Drift 'DKIM' $domain 'selector1+selector2 CNAMEs' "missing: $($missing -join ', ')"
                }
                else { Add-ExoFinding $result -Check 'DKIM CNAMEs present' -Status Pass -Target $domain -Detail 'selector1 and selector2 published.' }
            }
        }
        catch {
            Add-ExoFinding $result -Check 'DNS baseline' -Status Warning -Severity Medium -Target $domain `
                -Detail "Could not compare DNS: $($_.Exception.Message)" -Recommendation 'Re-run from a machine with normal DNS access.'
        }
    }
}

#endregion

#region Exchange objects

if ($baseline.ContainsKey('Exchange')) {
    if (-not $connected) {
        Add-ExoFinding $result -Check 'Exchange baseline' -Status Info -Detail 'Skipped: not connected to Exchange Online.'
    }
    else {
        $ex = $baseline.Exchange

        if ($ex.ContainsKey('AcceptedDomains') -and $null -ne $ex.AcceptedDomains) {
            $domains = Invoke-ExoSafe { Get-AcceptedDomain } 'accepted domains'
            if ($null -ne $domains) {
                $custom = @($domains | ForEach-Object { "$($_.DomainName)".ToLowerInvariant() } | Where-Object { $_ -notmatch '\.onmicrosoft\.com$' })
                Compare-ExoNameList -Area 'accepted domains' -Allowed $ex.AcceptedDomains -Actual $custom
            }
        }

        $objectChecks = @(
            @{ Key = 'InboundConnectors'; Area = 'inbound connectors'; Get = { Get-InboundConnector }; Severity = 'High' }
            @{ Key = 'OutboundConnectors'; Area = 'outbound connectors'; Get = { Get-OutboundConnector }; Severity = 'High' }
            @{ Key = 'TransportRules'; Area = 'mail flow rules'; Get = { Get-TransportRule -ResultSize Unlimited }; Severity = 'Medium' }
        )
        foreach ($c in $objectChecks) {
            if (-not $ex.ContainsKey($c.Key) -or $null -eq $ex[$c.Key]) { continue }
            $objects = Invoke-ExoSafe $c.Get $c.Area
            if ($null -ne $objects) {
                Compare-ExoNameList -Area $c.Area -Allowed $ex[$c.Key] -Actual @($objects | ForEach-Object { "$($_.Name)" }) -Severity $c.Severity
            }
        }
    }
}

#endregion

$result.Data['Drift'] = $drift.ToArray()
if ($drift.Count -eq 0) {
    Add-ExoFinding $result -Check 'Baseline drift' -Status Pass -Detail "No drift from $(Split-Path $BaselinePath -Leaf)."
}

if ($OutputPath) { Export-ExoSectionResult -Result $result -OutputPath $OutputPath }
$result
