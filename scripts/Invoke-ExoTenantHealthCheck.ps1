#Requires -Version 5.1
<#
.SYNOPSIS
    Runs every Exchange Online health report and produces a single HTML report plus CSV/JSON exports.

.DESCRIPTION
    Read-only. Runs, in order:
      Get-ExoTenantOverview.ps1    - tenant inventory, domains, recipients, RBAC, service health
      Get-ExoConnectorReport.ps1   - inbound/outbound connectors, hybrid, migration endpoints
      Get-ExoMailFlowReport.ps1    - message trace statistics, mail flow rules, journaling
      Get-ExoSecurityReport.ps1    - auth, auditing, forwarding, EOP/Defender policies, quarantine
      Get-ExoDomainDnsReport.ps1   - MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT
      Get-ExoBaselineReport.ps1    - drift from a tenant profile (only with -BaselinePath)

    Output folder contents:
      ExoHealthReport.html         - the report
      AllFindings.csv              - every finding, sorted by severity
      Summary.json                 - counts for trending / alerting
      <Section>-*.csv              - raw data per section

.PARAMETER OutputPath
    Output folder. Default: .\ExoHealth-<yyyyMMdd-HHmm>

.PARAMETER Sections
    Subset of sections to run. Default: all.

.PARAMETER MessageTraceDays
    Days of message trace to analyse (default 2, max 90).

.PARAMETER IncludeMailboxLevelChecks
    Per-mailbox forwarding / SMTP AUTH / audit-bypass checks (slower).

.PARAMETER IncludeInboxRules
    Also scan every mailbox's inbox rules for external forwarding (slowest).

.PARAMETER Connect
    Run Connect-ExoTenant.ps1 first. Pass connection parameters with -ConnectParameters.

.PARAMETER ConnectParameters
    Hashtable splatted to Connect-ExoTenant.ps1, e.g. @{ UserPrincipalName = 'admin@contoso.com' }.

.PARAMETER BaselinePath
    Tenant profile (.psd1) describing the expected state. Adds a "Baseline Drift" section and
    checks that you are connected to the right tenant. See tenants\haganism.net for an example.

.PARAMETER FailOnHighSeverity
    Exit with code 2 when any High-severity Fail/Warning exists (for scheduled runs / pipelines).

.EXAMPLE
    .\Connect-ExoTenant.ps1 -UserPrincipalName admin@contoso.onmicrosoft.com
    .\Invoke-ExoTenantHealthCheck.ps1

.EXAMPLE
    .\Invoke-ExoTenantHealthCheck.ps1 -Connect -ConnectParameters @{ AppId = $appId; CertificateThumbprint = $thumb; Organization = 'contoso.onmicrosoft.com' } `
        -MessageTraceDays 7 -IncludeMailboxLevelChecks -OutputPath D:\Reports\Exo -FailOnHighSeverity
#>
[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path (Get-Location) ("ExoHealth-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmm'))),

    [ValidateSet('Overview', 'Connectors', 'MailFlow', 'Security', 'Dns')]
    [string[]] $Sections = @('Overview', 'Connectors', 'MailFlow', 'Security', 'Dns'),

    [ValidateRange(1, 90)] [int] $MessageTraceDays = 2,

    [switch] $IncludeMailboxLevelChecks,
    [switch] $IncludeInboxRules,

    [switch] $Connect,
    [hashtable] $ConnectParameters = @{},

    [string] $BaselinePath,

    [switch] $FailOnHighSeverity
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ExoHealth.Common.ps1')

if ($Connect) { & (Join-Path $PSScriptRoot 'Connect-ExoTenant.ps1') @ConnectParameters }
Assert-ExoConnection

if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
$OutputPath = (Resolve-Path $OutputPath).Path

$org = Get-OrganizationConfig
$tenantName = "$($org.DisplayName) ($($org.Name))"
Write-Host "Exchange Online health check: $tenantName" -ForegroundColor Cyan

$run = @($Sections)
if ($BaselinePath) {
    $BaselinePath = (Resolve-Path $BaselinePath).Path
    $run = @('Baseline') + $run
}

$plan = [ordered]@{
    Baseline   = @{ Script = 'Get-ExoBaselineReport.ps1'; Params = @{ BaselinePath = $BaselinePath } }
    Overview   = @{ Script = 'Get-ExoTenantOverview.ps1'; Params = @{} }
    Connectors = @{ Script = 'Get-ExoConnectorReport.ps1'; Params = @{} }
    MailFlow   = @{ Script = 'Get-ExoMailFlowReport.ps1'; Params = @{ Days = $MessageTraceDays } }
    Security   = @{ Script = 'Get-ExoSecurityReport.ps1'; Params = @{ IncludeMailboxLevelChecks = $IncludeMailboxLevelChecks; IncludeInboxRules = $IncludeInboxRules } }
    Dns        = @{ Script = 'Get-ExoDomainDnsReport.ps1'; Params = @{} }
}

$results = New-Object System.Collections.Generic.List[object]
$step = 0
foreach ($name in $plan.Keys) {
    if ($run -notcontains $name) { continue }
    $step++
    $entry = $plan[$name]
    Write-Progress -Activity 'Exchange Online health check' -Status $name -PercentComplete (100 * $step / $run.Count)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $params = $entry.Params
        $sectionResult = & (Join-Path $PSScriptRoot $entry.Script) @params -OutputPath $OutputPath
        $results.Add($sectionResult)
        Write-Host ("  {0,-11} {1,4} findings  ({2:n0}s)" -f $name, $sectionResult.Findings.Count, $timer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Warning "$name section failed: $($_.Exception.Message)"
        $failed = New-ExoSectionResult -Section $name
        Add-ExoFinding $failed -Check 'Section execution' -Status Warning -Severity Medium -Detail $_.Exception.Message `
            -Recommendation 'Check RBAC permissions and module version, then re-run this section on its own with -Verbose.'
        $results.Add($failed)
    }
}
Write-Progress -Activity 'Exchange Online health check' -Completed

$allFindings = @($results | ForEach-Object { $_.Findings } | Sort-Object { Get-ExoSeverityRank $_.Status $_.Severity }, Section, Check)
$allFindings | Export-Csv -Path (Join-Path $OutputPath 'AllFindings.csv') -NoTypeInformation -Encoding UTF8

$summary = [ordered]@{
    Tenant       = $tenantName
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Sections     = @($results | ForEach-Object { $_.Section })
    Fail         = @($allFindings | Where-Object Status -eq 'Fail').Count
    Warning      = @($allFindings | Where-Object Status -eq 'Warning').Count
    Pass         = @($allFindings | Where-Object Status -eq 'Pass').Count
    Info         = @($allFindings | Where-Object Status -eq 'Info').Count
    HighSeverity = @($allFindings | Where-Object { $_.Status -in 'Fail', 'Warning' -and $_.Severity -eq 'High' }).Count
}
$summary | ConvertTo-Json | Set-Content -Path (Join-Path $OutputPath 'Summary.json') -Encoding UTF8

$report = New-ExoHtmlReport -Sections $results.ToArray() -Path (Join-Path $OutputPath 'ExoHealthReport.html') -TenantName $tenantName

Write-Host ''
Write-Host ("Fail: {0}  Warning: {1}  Pass: {2}  Info: {3}  (High severity: {4})" -f
    $summary.Fail, $summary.Warning, $summary.Pass, $summary.Info, $summary.HighSeverity) -ForegroundColor Yellow
Write-Host "Report: $($report.FullName)" -ForegroundColor Green

$allFindings | Where-Object { $_.Status -in 'Fail', 'Warning' -and $_.Severity -in 'High', 'Medium' } |
    Select-Object -First 15 Section, Check, Severity, Target |
    Format-Table -AutoSize | Out-String -Width 200 | Write-Host

if ($FailOnHighSeverity -and $summary.HighSeverity -gt 0) { exit 2 }
