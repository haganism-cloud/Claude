#Requires -Version 5.1
<#
.SYNOPSIS
    Connects to Exchange Online PowerShell (and optionally Security & Compliance / Microsoft Graph)
    for the tenant health scripts.

.DESCRIPTION
    Supports interactive (delegated) sign-in and unattended app-only sign-in with a certificate.

    Least-privilege roles for running the health reports:
      - Global Reader, or Exchange "View-Only Organization Management", for configuration reads.
      - Security Reader for Defender for Office 365 policies and quarantine.
      - A role with Message Tracking for message trace (included in View-Only Organization Management
        in most tenants - verify with Get-ManagementRoleAssignment if trace calls are denied).

.PARAMETER UserPrincipalName
    Admin account for interactive sign-in.

.PARAMETER AppId
    Entra ID application (client) ID for app-only sign-in.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate (in the CurrentUser or LocalMachine store) registered on the app.

.PARAMETER Organization
    The tenant's initial domain, for example contoso.onmicrosoft.com. Required for app-only sign-in.

.PARAMETER IncludeSecurityCompliance
    Also runs Connect-IPPSSession (needed for some Purview / compliance follow-up work, not for the
    core health reports).

.PARAMETER IncludeGraph
    Also connects to Microsoft Graph with ServiceHealth.Read.All for the service-health section of
    the overview report. Requires the Microsoft.Graph.Authentication and
    Microsoft.Graph.Devices.ServiceAnnouncement modules.

.EXAMPLE
    .\Connect-ExoTenant.ps1 -UserPrincipalName admin@contoso.onmicrosoft.com

.EXAMPLE
    .\Connect-ExoTenant.ps1 -AppId 00000000-0000-0000-0000-000000000000 `
        -CertificateThumbprint ABCDEF0123456789ABCDEF0123456789ABCDEF01 -Organization contoso.onmicrosoft.com
#>
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Interactive')]
    [string] $UserPrincipalName,

    [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
    [string] $AppId,

    [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
    [string] $CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
    [string] $Organization,

    [switch] $IncludeSecurityCompliance,

    [switch] $IncludeGraph
)

$ErrorActionPreference = 'Stop'

$minimumVersion = [version]'3.4.0'
$module = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
    Sort-Object Version -Descending | Select-Object -First 1

if (-not $module) {
    throw "ExchangeOnlineManagement is not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser -MinimumVersion $minimumVersion"
}
if ($module.Version -lt $minimumVersion) {
    Write-Warning "ExchangeOnlineManagement $($module.Version) found; $minimumVersion or later is recommended (Update-Module ExchangeOnlineManagement)."
}
Import-Module ExchangeOnlineManagement -MinimumVersion $module.Version

$exoParams = @{ ShowBanner = $false }
if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
    $exoParams.AppId = $AppId
    $exoParams.CertificateThumbprint = $CertificateThumbprint
    $exoParams.Organization = $Organization
}
elseif ($UserPrincipalName) {
    $exoParams.UserPrincipalName = $UserPrincipalName
}

Write-Host 'Connecting to Exchange Online...' -ForegroundColor Cyan
Connect-ExchangeOnline @exoParams

if ($IncludeSecurityCompliance) {
    Write-Host 'Connecting to Security & Compliance PowerShell...' -ForegroundColor Cyan
    $ippsParams = $exoParams.Clone()
    $ippsParams.Remove('ShowBanner')
    Connect-IPPSSession @ippsParams
}

if ($IncludeGraph) {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Warning 'Microsoft.Graph.Authentication is not installed; skipping Graph. Install-Module Microsoft.Graph -Scope CurrentUser'
    }
    else {
        Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
        if ($PSCmdlet.ParameterSetName -eq 'AppOnly') {
            Connect-MgGraph -ClientId $AppId -CertificateThumbprint $CertificateThumbprint -TenantId $Organization -NoWelcome
        }
        else {
            Connect-MgGraph -Scopes 'ServiceHealth.Read.All' -NoWelcome
        }
    }
}

$org = Get-OrganizationConfig
$info = Get-ConnectionInformation | Select-Object -First 1
Write-Host ("Connected to {0} as {1}" -f $org.DisplayName, $info.UserPrincipalName) -ForegroundColor Green
