#Requires -Version 5.1
<#
.SYNOPSIS
    One-command health check of the haganism.net Microsoft 365 tenant: connectors, mail flow,
    security, email authentication and drift from the haganism.net tenant profile.

.DESCRIPTION
    Read-only. Wraps ..\..\scripts\Invoke-ExoTenantHealthCheck.ps1 with haganism.net settings:
      - connects (interactive or certificate) and refuses to continue if the session is signed in
        to any tenant other than haganism.net (tenant ID in haganism.net.psd1);
      - runs every section, including per-mailbox forwarding / SMTP AUTH / audit-bypass checks and
        the inbox-rule scan (cheap in a small tenant; use -SkipInboxRules to turn off);
      - adds the "Baseline Drift" section from haganism.net.psd1;
      - writes the report to reports\haganism.net\<timestamp> (git-ignored, contains tenant data).

    -DnsOnly runs the checks that need no sign-in (MX, SPF, DKIM CNAMEs, DMARC, MTA-STS, TLS-RPT
    and DNS drift), so you can check public posture from any machine.

    Recommended account: Global Reader + Security Reader (no admin rights needed).

.EXAMPLE
    .\Invoke-HaganismNetHealthCheck.ps1 -UserPrincipalName you@haganism.net

.EXAMPLE
    .\Invoke-HaganismNetHealthCheck.ps1 -DnsOnly

.EXAMPLE
    # Unattended (Entra app with Exchange.ManageAsApp + Global Reader, certificate in the cert store)
    .\Invoke-HaganismNetHealthCheck.ps1 -AppId <appId> -CertificateThumbprint <thumb> `
        -Organization <tenant>.onmicrosoft.com -FailOnHighSeverity
#>
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Interactive')]
    [string] $UserPrincipalName,

    [Parameter(Mandatory, ParameterSetName = 'AppOnly')] [string] $AppId,
    [Parameter(Mandatory, ParameterSetName = 'AppOnly')] [string] $CertificateThumbprint,
    [Parameter(Mandatory, ParameterSetName = 'AppOnly')] [string] $Organization,

    [Parameter(Mandatory, ParameterSetName = 'DnsOnly')] [switch] $DnsOnly,

    [string] $OutputRoot = (Join-Path $PSScriptRoot '..\..\reports\haganism.net'),
    [ValidateRange(1, 90)] [int] $MessageTraceDays,
    [switch] $SkipInboxRules,
    [switch] $FailOnHighSeverity
)

$ErrorActionPreference = 'Stop'
$scripts = (Resolve-Path (Join-Path $PSScriptRoot '..\..\scripts')).Path
$profilePath = Join-Path $PSScriptRoot 'haganism.net.psd1'
$tenantProfile = Import-PowerShellDataFile $profilePath
. (Join-Path $scripts 'ExoHealth.Common.ps1')

if (-not $MessageTraceDays) { $MessageTraceDays = $tenantProfile.Report.MessageTraceDays }
$outputPath = Join-Path $OutputRoot (Get-Date -Format 'yyyyMMdd-HHmm')
New-Item -Path $outputPath -ItemType Directory -Force | Out-Null

#region DNS-only mode

if ($DnsOnly) {
    Write-Host "haganism.net public email posture (no sign-in)" -ForegroundColor Cyan
    $sections = @(
        & (Join-Path $scripts 'Get-ExoDomainDnsReport.ps1') -Domain @($tenantProfile.Dns.Keys) -OutputPath $outputPath
        & (Join-Path $scripts 'Get-ExoBaselineReport.ps1') -BaselinePath $profilePath -OutputPath $outputPath
    )
    $report = New-ExoHtmlReport -Sections $sections -Path (Join-Path $outputPath 'ExoHealthReport.html') -TenantName 'haganism.net (DNS only)'
    $sections | ForEach-Object { $_.Findings } |
        Where-Object { $_.Status -ne 'Pass' } |
        Sort-Object { Get-ExoSeverityRank $_.Status $_.Severity } |
        Format-Table Status, Severity, Check, Target -AutoSize | Out-String -Width 200 | Write-Host
    Write-Host "Report: $($report.FullName)" -ForegroundColor Green
    return
}

#endregion

#region Connect and verify tenant

$connectParams = @{}
if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
    $connectParams = @{ AppId = $AppId; CertificateThumbprint = $CertificateThumbprint; Organization = $Organization }
}
elseif ($UserPrincipalName) {
    $connectParams = @{ UserPrincipalName = $UserPrincipalName }
}

$existing = $null
if (Test-ExoCommand 'Get-ConnectionInformation') {
    $existing = Get-ConnectionInformation | Where-Object { "$($_.State)" -eq 'Connected' -and "$($_.TenantID)" -eq $tenantProfile.TenantId } |
        Select-Object -First 1
}
if (-not $existing) {
    & (Join-Path $scripts 'Connect-ExoTenant.ps1') @connectParams
}

$connection = Get-ConnectionInformation | Where-Object { "$($_.State)" -eq 'Connected' } | Select-Object -Last 1
if ("$($connection.TenantID)" -ne $tenantProfile.TenantId) {
    throw ("Signed in to tenant '{0}', not haganism.net ({1}). Run Disconnect-ExchangeOnline and sign in with a haganism.net account." -f
        $connection.TenantID, $tenantProfile.TenantId)
}

#endregion

$params = @{
    OutputPath                = $outputPath
    MessageTraceDays          = $MessageTraceDays
    IncludeMailboxLevelChecks = $true
    IncludeInboxRules         = -not $SkipInboxRules
    BaselinePath              = $profilePath
    FailOnHighSeverity        = $FailOnHighSeverity
}
$global:LASTEXITCODE = 0
& (Join-Path $scripts 'Invoke-ExoTenantHealthCheck.ps1') @params
exit $global:LASTEXITCODE   # 2 = high-severity findings with -FailOnHighSeverity
