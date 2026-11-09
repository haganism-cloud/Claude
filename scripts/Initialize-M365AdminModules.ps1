#Requires -Version 5.1
<#
.SYNOPSIS
    Installs, updates and loads the PowerShell modules used to manage Microsoft 365: users,
    groups, licences, reports and queries through Microsoft Graph, plus Exchange Online, Teams,
    SharePoint and Excel export. Optionally connects to each service.

.DESCRIPTION
    Safe to re-run. For each module in the selected profile it:
      1. installs it for the current user if missing (no admin rights needed);
      2. optionally updates it (-Update);
      3. imports it into the session (Graph is imported per sub-module, which is much faster
         than importing the whole Microsoft.Graph meta-module);
      4. prints a summary table of name, version and status.

    Retired modules are NOT installed. If MSOnline or AzureAD are present the script warns:
    Microsoft retired both; use Microsoft.Graph (or Microsoft.Entra) instead.

    Profiles (-Profile):
      Core   Microsoft Graph (users, groups, licences, directory, sign-ins/audit, reports),
             Exchange Online, ImportExcel.                                       [default]
      Full   Core + Graph applications/devices/security/Teams/mail/sites, Graph Beta
             (selected), Microsoft Teams, SharePoint (PnP.PowerShell on PS 7 or
             Microsoft.Online.SharePoint.PowerShell on Windows PowerShell 5.1), Microsoft.Entra.

.PARAMETER Profile
    Core (default) or Full.

.PARAMETER Update
    Update modules that are already installed to the latest gallery version.

.PARAMETER SkipImport
    Install/update only; do not import into this session.

.PARAMETER Connect
    After loading, connect: Microsoft Graph (with -GraphScopes), Exchange Online, and with
    -Profile Full also Microsoft Teams. SharePoint needs a site URL, so it is not connected.

.PARAMETER GraphScopes
    Delegated Graph permissions requested by -Connect. The default is read-mostly user and
    group administration; remove ReadWrite scopes for read-only reporting.

.PARAMETER UserPrincipalName
    Admin account used by -Connect (pre-fills the sign-in prompts).

.PARAMETER TenantId
    Tenant ID or domain for Connect-MgGraph (useful when the account is a guest in several tenants).

.EXAMPLE
    .\Initialize-M365AdminModules.ps1
    # Installs (if needed) and imports the Core modules.

.EXAMPLE
    .\Initialize-M365AdminModules.ps1 -Profile Full -Update -Connect -UserPrincipalName admin@contoso.com

.EXAMPLE
    .\Initialize-M365AdminModules.ps1 -WhatIf
    # Shows what would be installed or updated without changing anything.

.NOTES
    Read-only towards the tenant: it only installs modules locally and, with -Connect, signs in.
    Graph and Exchange Online both ship MSAL; if a connect fails with an assembly/MSAL error,
    start a new PowerShell session and connect to one service at a time.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Core', 'Full')]
    [string] $Profile = 'Core',

    [switch] $Update,
    [switch] $SkipImport,
    [switch] $Connect,

    [string[]] $GraphScopes = @(
        'User.ReadWrite.All',
        'Group.ReadWrite.All',
        'Directory.Read.All',
        'Organization.Read.All',
        'AuditLog.Read.All',
        'Reports.Read.All',
        'Policy.Read.All',
        'RoleManagement.Read.Directory',
        'UserAuthenticationMethod.Read.All'
    ),

    [string] $UserPrincipalName,
    [string] $TenantId
)

$ErrorActionPreference = 'Stop'
$isPS7 = $PSVersionTable.PSVersion.Major -ge 7
$onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Get-Variable IsWindows -ValueOnly -ErrorAction SilentlyContinue) -eq $true)

#region Module catalogue

# Name, minimum version, profile, and (for Graph sub-modules) the area it covers.
$catalogue = @(
    @{ Name = 'Microsoft.Graph.Authentication';               Min = '2.25.0'; Profile = 'Core'; Purpose = 'Connect-MgGraph, Invoke-MgGraphRequest (any Graph query)' }
    @{ Name = 'Microsoft.Graph.Users';                        Min = '2.25.0'; Profile = 'Core'; Purpose = 'Users: Get/New/Update-MgUser, managers, photos' }
    @{ Name = 'Microsoft.Graph.Users.Actions';                Min = '2.25.0'; Profile = 'Core'; Purpose = 'Licence assignment (Set-MgUserLicense), revoke sessions' }
    @{ Name = 'Microsoft.Graph.Groups';                       Min = '2.25.0'; Profile = 'Core'; Purpose = 'Groups and membership' }
    @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; Min = '2.25.0'; Profile = 'Core'; Purpose = 'Directory roles, domains, subscribed SKUs, devices' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns';             Min = '2.25.0'; Profile = 'Core'; Purpose = 'Conditional Access, auth methods, named locations' }
    @{ Name = 'Microsoft.Graph.Reports';                      Min = '2.25.0'; Profile = 'Core'; Purpose = 'Sign-in and audit logs, usage reports' }
    @{ Name = 'ExchangeOnlineManagement';                     Min = '3.4.0';  Profile = 'Core'; Purpose = 'Exchange Online and Security & Compliance PowerShell' }
    @{ Name = 'ImportExcel';                                  Min = '7.8.0';  Profile = 'Core'; Purpose = 'Export-Excel without Excel installed' }

    @{ Name = 'Microsoft.Graph.Applications';                 Min = '2.25.0'; Profile = 'Full'; Purpose = 'App registrations, service principals, consent' }
    @{ Name = 'Microsoft.Graph.Identity.Governance';          Min = '2.25.0'; Profile = 'Full'; Purpose = 'PIM, access reviews, entitlement management' }
    @{ Name = 'Microsoft.Graph.DeviceManagement';             Min = '2.25.0'; Profile = 'Full'; Purpose = 'Intune managed devices and policies' }
    @{ Name = 'Microsoft.Graph.Security';                     Min = '2.25.0'; Profile = 'Full'; Purpose = 'Security alerts, incidents, secure score' }
    @{ Name = 'Microsoft.Graph.Teams';                        Min = '2.25.0'; Profile = 'Full'; Purpose = 'Teams, channels, members via Graph' }
    @{ Name = 'Microsoft.Graph.Mail';                         Min = '2.25.0'; Profile = 'Full'; Purpose = 'Mailbox items via Graph' }
    @{ Name = 'Microsoft.Graph.Sites';                        Min = '2.25.0'; Profile = 'Full'; Purpose = 'SharePoint sites and lists via Graph' }
    @{ Name = 'Microsoft.Graph.Beta.Identity.SignIns';        Min = '2.25.0'; Profile = 'Full'; Purpose = 'Beta-only identity features' }
    @{ Name = 'Microsoft.Graph.Beta.Reports';                 Min = '2.25.0'; Profile = 'Full'; Purpose = 'Beta-only reports (e.g. MFA registration details)' }
    @{ Name = 'Microsoft.Entra';                              Min = '1.0.0';  Profile = 'Full'; Purpose = 'Entra cmdlets (AzureAD-style names on top of Graph)' }
    @{ Name = 'MicrosoftTeams';                               Min = '6.0.0';  Profile = 'Full'; Purpose = 'Teams policies, voice, meetings' }
)

# SharePoint: PnP.PowerShell targets PowerShell 7; the Microsoft SPO module is the classic choice on 5.1.
if ($isPS7) {
    $catalogue += @{ Name = 'PnP.PowerShell'; Min = '2.12.0'; Profile = 'Full'; Purpose = 'SharePoint Online and OneDrive (PowerShell 7)' }
}
elseif ($onWindows) {
    $catalogue += @{ Name = 'Microsoft.Online.SharePoint.PowerShell'; Min = '16.0.0'; Profile = 'Full'; Purpose = 'SharePoint Online admin (Windows PowerShell 5.1)' }
}

$selected = @($catalogue | Where-Object { $Profile -eq 'Full' -or $_.Profile -eq 'Core' })

#endregion

#region Prerequisites

Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)) - profile: $Profile" -ForegroundColor Cyan

if (-not $isPS7) {
    # Windows PowerShell 5.1 defaults to old TLS versions; the PowerShell Gallery needs TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Host 'Tip: PowerShell 7 is recommended (winget install Microsoft.PowerShell).' -ForegroundColor DarkYellow

    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue | Where-Object Version -ge '2.8.5.201')) {
        if ($PSCmdlet.ShouldProcess('NuGet package provider', 'Install (CurrentUser)')) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
        }
    }
}

foreach ($retired in 'MSOnline', 'AzureAD', 'AzureADPreview') {
    if (Get-Module -ListAvailable -Name $retired) {
        Write-Warning "$retired is installed but retired by Microsoft. Replace its scripts with Microsoft.Graph / Microsoft.Entra, then: Uninstall-Module $retired -AllVersions"
    }
}

# A fresh or locked-down machine may have no PSGallery repository registered.
try {
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess('PSGallery', 'Register-PSRepository -Default')) {
            Write-Host 'Registering the PowerShell Gallery repository...' -ForegroundColor Yellow
            Register-PSRepository -Default -ErrorAction Stop
        }
    }
}
catch {
    Write-Warning "PowerShell Gallery not available ($($_.Exception.Message)). Missing modules cannot be installed; already-installed ones will still load."
}

$execPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($onWindows -and $execPolicy -in 'Restricted', 'AllSigned', 'Undefined' -and (Get-ExecutionPolicy) -in 'Restricted', 'AllSigned') {
    Write-Warning "Execution policy is '$(Get-ExecutionPolicy)'. Modules may not load. Consider: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"
}

#endregion

#region Install / update

$results = New-Object System.Collections.Generic.List[object]

foreach ($m in $selected) {
    $status = 'OK'
    $installed = Get-Module -ListAvailable -Name $m.Name | Sort-Object Version -Descending | Select-Object -First 1
    try {
        if (-not $installed) {
            if ($PSCmdlet.ShouldProcess($m.Name, 'Install-Module (CurrentUser)')) {
                Write-Host "Installing $($m.Name)..." -ForegroundColor Yellow
                Install-Module -Name $m.Name -Repository PSGallery -Scope CurrentUser -MinimumVersion $m.Min -AllowClobber -Force -ErrorAction Stop
                $status = 'Installed'
            }
            else { $status = 'Would install' }
        }
        elseif ($installed.Version -lt [version]$m.Min -or $Update) {
            if ($PSCmdlet.ShouldProcess($m.Name, "Update from $($installed.Version)")) {
                Write-Host "Updating $($m.Name) (installed $($installed.Version))..." -ForegroundColor Yellow
                Install-Module -Name $m.Name -Repository PSGallery -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                $status = 'Updated'
            }
            else { $status = 'Would update' }
        }
    }
    catch {
        $status = "FAILED: $($_.Exception.Message)"
    }

    $now = Get-Module -ListAvailable -Name $m.Name | Sort-Object Version -Descending | Select-Object -First 1
    if ($status -in 'Installed', 'Updated' -and -not $now) {
        $status = 'FAILED: not found after install'
    }
    $results.Add([pscustomobject]@{
            Module  = $m.Name
            Version = if ($now) { "$($now.Version)" } else { '-' }
            Status  = $status
            Purpose = $m.Purpose
        })
}

# All Graph sub-modules must be the same version or imports fail with assembly errors.
$graphVersions = @($results | Where-Object { $_.Module -like 'Microsoft.Graph.*' -and $_.Module -notlike 'Microsoft.Graph.Beta.*' -and $_.Version -ne '-' } |
    Select-Object -ExpandProperty Version -Unique)
if ($graphVersions.Count -gt 1) {
    Write-Warning "Microsoft Graph sub-modules are at different versions ($($graphVersions -join ', ')). Re-run with -Update so they match."
}

#endregion

#region Import

if (-not $SkipImport -and -not $WhatIfPreference) {
    # Graph authentication first: it loads the shared MSAL/Azure.Identity assemblies once.
    $importOrder = @($selected | Sort-Object { if ($_.Name -eq 'Microsoft.Graph.Authentication') { 0 } elseif ($_.Name -like 'Microsoft.Graph*') { 1 } else { 2 } })
    foreach ($m in $importOrder) {
        $row = $results | Where-Object Module -eq $m.Name
        if ($row.Status -like 'FAILED*' -or $row.Version -eq '-') { continue }
        try {
            Import-Module -Name $m.Name -MinimumVersion $m.Min -ErrorAction Stop -WarningAction SilentlyContinue -DisableNameChecking
            if ($row.Status -eq 'OK') { $row.Status = 'Loaded' } else { $row.Status = "$($row.Status), loaded" }
        }
        catch {
            $row.Status = "Import failed: $($_.Exception.Message)"
        }
    }
}

$results | Format-Table Module, Version, Status -AutoSize | Out-String -Width 200 | Write-Host

#endregion

#region Connect (optional)

if ($Connect -and -not $WhatIfPreference) {
    $loaded = { param($n) [bool](Get-Module -Name $n) }

    if (& $loaded 'Microsoft.Graph.Authentication') {
        Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
        $mg = @{ Scopes = $GraphScopes; NoWelcome = $true }
        if ($TenantId) { $mg.TenantId = $TenantId }
        Connect-MgGraph @mg
        $ctx = Get-MgContext
        Write-Host ("  Graph: {0} in tenant {1}; scopes: {2}" -f $ctx.Account, $ctx.TenantId, ($ctx.Scopes -join ', ')) -ForegroundColor Green
    }

    if (& $loaded 'ExchangeOnlineManagement') {
        Write-Host 'Connecting to Exchange Online...' -ForegroundColor Cyan
        $exo = @{ ShowBanner = $false }
        if ($UserPrincipalName) { $exo.UserPrincipalName = $UserPrincipalName }
        Connect-ExchangeOnline @exo
        Write-Host "  Exchange Online: $((Get-ConnectionInformation | Select-Object -First 1).UserPrincipalName)" -ForegroundColor Green
    }

    if ($Profile -eq 'Full' -and (& $loaded 'MicrosoftTeams')) {
        Write-Host 'Connecting to Microsoft Teams...' -ForegroundColor Cyan
        $teams = @{}
        if ($TenantId) { $teams.TenantId = $TenantId }
        Connect-MicrosoftTeams @teams | Out-Null
        Write-Host '  Microsoft Teams: connected' -ForegroundColor Green
    }

    Write-Host ''
    Write-Host 'SharePoint is not connected automatically (needs your admin URL):' -ForegroundColor DarkYellow
    if ($isPS7) { Write-Host '  Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive -ClientId <your Entra app ID>' }
    else { Write-Host '  Connect-SPOService -Url https://<tenant>-admin.sharepoint.com' }
}

#endregion

Write-Host ''
Write-Host 'Quick reference:' -ForegroundColor Cyan
Write-Host '  Get-MgUser -All -Property DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses | Select DisplayName,UserPrincipalName,AccountEnabled'
Write-Host '  Get-MgSubscribedSku | Select SkuPartNumber,ConsumedUnits,@{n=''Total'';e={$_.PrepaidUnits.Enabled}}'
Write-Host '  Invoke-MgGraphRequest -Method GET -Uri ''v1.0/users?$top=5'''
Write-Host '  Find-MgGraphCommand -Uri ''/users/{id}/memberOf''   # which cmdlet + permission a Graph URL needs'
Write-Host '  Get-EXOMailbox -ResultSize 10 | Export-Excel .\mailboxes.xlsx -AutoSize'
Write-Host '  Disconnect-MgGraph; Disconnect-ExchangeOnline -Confirm:$false'

$failed = @($results | Where-Object { $_.Status -like 'FAILED*' -or $_.Status -like 'Import failed*' })
if ($failed.Count -gt 0) {
    Write-Warning "$($failed.Count) module(s) failed. Check network access to www.powershellgallery.com and re-run."
}
