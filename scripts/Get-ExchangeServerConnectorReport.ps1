#Requires -Version 5.1
<#
.SYNOPSIS
    Inventories on-premises Exchange Server send/receive connectors and certificates in a hybrid
    deployment. Run in the Exchange Management Shell on an Exchange server.

.DESCRIPTION
    Read-only. Complements Get-ExoConnectorReport.ps1 (the Exchange Online side). Flags:
      - receive connectors that allow anonymous relay (Ms-Exch-SMTP-Accept-Any-Recipient for
        Anonymous Logon) from wide remote IP ranges;
      - hybrid send connectors whose TLS certificate is missing or expiring;
      - Exchange certificates expiring within -CertificateWarningDays (default 60), including the
        certificate used for hybrid mail flow.

.PARAMETER CertificateWarningDays
    Warn when a certificate expires within this many days.

.PARAMETER OutputPath
    Folder for CSV exports.

.EXAMPLE
    .\Get-ExchangeServerConnectorReport.ps1 -OutputPath C:\Reports\OnPrem
#>
[CmdletBinding()]
param(
    [int] $CertificateWarningDays = 60,
    [string] $OutputPath
)

. (Join-Path $PSScriptRoot 'ExoHealth.Common.ps1')

if (-not (Test-ExoCommand 'Get-ReceiveConnector')) {
    throw 'Get-ReceiveConnector not found. Run this script in the Exchange Management Shell on an Exchange server.'
}

$result = New-ExoSectionResult -Section 'On-Premises Connectors'

#region Certificates

$certs = New-Object System.Collections.Generic.List[object]
$servers = @(Invoke-ExoSafe { Get-ExchangeServer | Where-Object { $_.IsHubTransportServer -or $_.IsEdgeServer -or "$($_.ServerRole)" -match 'Mailbox' } } 'Exchange servers' -Default @())
foreach ($s in $servers) {
    foreach ($c in @(Invoke-ExoSafe { Get-ExchangeCertificate -Server $s.Name } "certificates on $($s.Name)" -Default @())) {
        if ($null -eq $c) { continue }
        $certs.Add([pscustomobject]@{
                Server     = $s.Name
                Thumbprint = $c.Thumbprint
                Subject    = $c.Subject
                Issuer     = $c.Issuer
                Services   = "$($c.Services)"
                NotAfter   = $c.NotAfter
                DaysLeft   = [int]([datetime]$c.NotAfter - (Get-Date)).TotalDays
                SelfSigned = $c.IsSelfSigned
            })
    }
}
$result.Data['ExchangeCertificates'] = $certs.ToArray()
foreach ($c in $certs | Where-Object { $_.Services -match 'SMTP' -and -not $_.SelfSigned }) {
    if ($c.DaysLeft -lt 0) {
        Add-ExoFinding $result -Check 'SMTP certificate expired' -Status Fail -Severity High -Target "$($c.Server) $($c.Thumbprint)" `
            -Detail "$($c.Subject) expired $(([datetime]$c.NotAfter).ToString('yyyy-MM-dd'))." `
            -Recommendation 'Install a renewed certificate, assign SMTP, then re-run the Hybrid Configuration Wizard.'
    }
    elseif ($c.DaysLeft -le $CertificateWarningDays) {
        Add-ExoFinding $result -Check 'SMTP certificate expiring' -Status Warning -Severity Medium -Target "$($c.Server) $($c.Thumbprint)" `
            -Detail "$($c.Subject) expires in $($c.DaysLeft) days." `
            -Recommendation 'Renew now; update TlsCertificateName on hybrid send/receive connectors and re-run HCW.'
    }
}

#endregion

#region Send connectors

$send = Invoke-ExoSafe { Get-SendConnector } 'send connectors'
if ($null -ne $send) {
    $result.Data['SendConnectors'] = @($send | ConvertTo-ExoFlatObject -Property Name, Enabled, AddressSpaces, SmartHosts,
        DNSRoutingEnabled, RequireTLS, TlsAuthLevel, TlsDomain, TlsCertificateName, CloudServicesMailEnabled,
        SourceTransportServers, MaxMessageSize, FrontendProxyEnabled)
    foreach ($c in $send) {
        if ($c.CloudServicesMailEnabled) {
            $certName = "$($c.TlsCertificateName)"
            if (-not $certName) {
                Add-ExoFinding $result -Check 'Hybrid send connector certificate' -Status Fail -Severity High -Target $c.Name `
                    -Detail 'Hybrid (CloudServicesMailEnabled) send connector has no TlsCertificateName.' -Recommendation 'Re-run the Hybrid Configuration Wizard.'
            }
            if (-not $c.RequireTLS) {
                Add-ExoFinding $result -Check 'Hybrid send connector TLS' -Status Fail -Severity Medium -Target $c.Name `
                    -Detail 'Hybrid send connector does not require TLS.' -Recommendation 'Set-SendConnector -RequireTLS $true'
            }
        }
    }
}

#endregion

#region Receive connectors

$receive = Invoke-ExoSafe { Get-ReceiveConnector } 'receive connectors'
if ($null -ne $receive) {
    $result.Data['ReceiveConnectors'] = @($receive | ConvertTo-ExoFlatObject -Property Identity, Enabled, TransportRole, Bindings,
        RemoteIPRanges, PermissionGroups, AuthMechanism, RequireTLS, TlsCertificateName, Fqdn, MaxMessageSize)

    foreach ($c in $receive) {
        $perms = Invoke-ExoSafe { Get-ADPermission -Identity $c.Identity | Where-Object {
                "$($_.User)" -match 'ANONYMOUS LOGON' -and "$($_.ExtendedRights)" -match 'ms-Exch-SMTP-Accept-Any-Recipient' -and -not $_.Deny } } "relay permissions on $($c.Identity)" -Default @()
        if (@($perms | Where-Object { $_ }).Count -gt 0) {
            $ranges = @($c.RemoteIPRanges | ForEach-Object { "$_" })
            $wide = @($ranges | Where-Object { $_ -match '0\.0\.0\.0|::-ffff|/([0-9]|1[0-9])$' })
            $sev = if ($wide.Count -gt 0) { 'High' } else { 'Medium' }
            $st = if ($wide.Count -gt 0) { 'Fail' } else { 'Warning' }
            Add-ExoFinding $result -Check 'Anonymous relay receive connector' -Status $st -Severity $sev -Target "$($c.Identity)" `
                -Detail "Anonymous relay allowed from: $($ranges -join ', ')." `
                -Recommendation 'Limit RemoteIPRanges to specific application hosts; move devices to authenticated SMTP where possible.'
        }
    }
}

#endregion

if ($OutputPath) { Export-ExoSectionResult -Result $result -OutputPath $OutputPath }
$result
