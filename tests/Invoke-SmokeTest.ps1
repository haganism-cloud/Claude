#Requires -Version 7.0
<#
.SYNOPSIS
    Offline smoke test: parses every script, then runs the full health check against stubbed
    Exchange Online cmdlets (ExoStubs.ps1) and asserts the expected findings are produced.

.EXAMPLE
    pwsh ./tests/Invoke-SmokeTest.ps1
#>
[CmdletBinding()]
param([string] $OutputPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'exo-smoke'))

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$scripts = Join-Path $root 'scripts'
$failures = New-Object System.Collections.Generic.List[string]

# 1. Syntax
foreach ($file in Get-ChildItem $scripts, $PSScriptRoot -Filter *.ps1) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    foreach ($e in $errors) { $failures.Add("Parse error in $($file.Name):$($e.Extent.StartLineNumber) $($e.Message)") }
}

# 2. End-to-end run against stubs
. (Join-Path $PSScriptRoot 'ExoStubs.ps1')
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Recurse -Force }

& (Join-Path $scripts 'Invoke-ExoTenantHealthCheck.ps1') -OutputPath $OutputPath -MessageTraceDays 3 `
    -BaselinePath (Join-Path $PSScriptRoot 'contoso.baseline.psd1') `
    -IncludeMailboxLevelChecks -IncludeInboxRules -WarningAction SilentlyContinue | Out-Null

foreach ($f in 'ExoHealthReport.html', 'AllFindings.csv', 'Summary.json', 'Connectors-InboundConnectors.csv', 'MailFlow-TraceByStatus.csv') {
    if (-not (Test-Path (Join-Path $OutputPath $f))) { $failures.Add("Missing output file $f") }
}

$findings = Import-Csv (Join-Path $OutputPath 'AllFindings.csv')

# Each stub is built to trigger these findings: Check, Status, Target (substring) or '' for any.
$expected = @(
    , @('Partner connector restriction', 'Fail', 'From Fabrikam partner')
    , @('Partner connector TLS', 'Warning', 'From Fabrikam partner')
    , @('On-premises connector identification', 'Pass', 'Inbound from contoso-onprem')
    , @('Outbound connector TLS', 'Warning', 'Egress via filtering service')
    , @('Outbound connector scope', 'Warning', 'Egress via filtering service')
    , @('Hybrid connector reference', 'Fail', 'contoso-onprem')
    , @('Delivery failure rate', 'Fail', '')
    , @('Spam bypass on spoofable condition', 'Fail', 'Whitelist payroll vendor')
    , @('Rule copies mail externally', 'Fail', 'Copy CFO mail')
    , @('Rule references missing connector', 'Fail', 'Route legal via encryption gateway')
    , @('Journaling NDR mailbox', 'Fail', '')
    , @('Direct Send', 'Warning', '')
    , @('SMTP AUTH (organisation)', 'Warning', '')
    , @('Restricted users (blocked from sending)', 'Fail', '')
    , @('Anti-spam allowed sender domains', 'Fail', 'Default')
    , @('Phish action', 'Warning', 'Default')
    , @('Connection filter IP allow list', 'Warning', 'Default')
    , @('Mailboxes forwarding externally', 'Fail', '')
    , @('Inbox rules forwarding externally', 'Fail', '')
    , @('Mailbox audit bypass', 'Warning', '')
    , @('Released malware / high-confidence phish', 'Warning', '')
    , @('Organization Management membership', 'Warning', '')
    , @('SPF', 'Fail', 'fabrikam.com')
    , @('DMARC policy', 'Warning', 'contoso.com')
    , @('DMARC', 'Fail', 'fabrikam.com')
    , @('DKIM key size', 'Warning', 'contoso.com')
    , @('DKIM CNAME', 'Warning', 'contoso.com')
    , @('MX record', 'Info', 'fabrikam.com')
    , @('MX record', 'Pass', 'contoso.com')
    , @('SPF all qualifier', 'Pass', 'contoso.com')
)
foreach ($e in $expected) {
    $hit = $findings | Where-Object { $_.Check -eq $e[0] -and $_.Status -eq $e[1] -and ($e[2] -eq '' -or $_.Target -like "*$($e[2])*") }
    if (-not $hit) { $failures.Add("Expected finding not produced: $($e[0]) / $($e[1]) / $($e[2])") }
}

# Baseline drift (tests/contoso.baseline.psd1 differs from the stub tenant on purpose).
foreach ($e in @(
        , @('Connected tenant', 'Pass', '')
        , @('MX matches baseline', 'Pass', 'contoso.com')
        , @('SPF changed', 'Warning', 'contoso.com')
        , @('DMARC weaker than baseline', 'Fail', 'contoso.com')
        , @('Unexpected inbound connectors', 'Warning', 'From Fabrikam partner')
        , @('Missing mail flow rules', 'Warning', 'Retired rule')
        , @('accepted domains match baseline', 'Pass', '')
    )) {
    $hit = $findings | Where-Object { $_.Section -eq 'Baseline Drift' -and $_.Check -eq $e[0] -and $_.Status -eq $e[1] -and ($e[2] -eq '' -or $_.Target -like "*$($e[2])*") }
    if (-not $hit) { $failures.Add("Expected baseline finding not produced: $($e[0]) / $($e[1]) / $($e[2])") }
}

# A DNS resolver failure must be reported as "could not check", never as missing records.
$dnsFail = & (Join-Path $scripts 'Get-ExoDomainDnsReport.ps1') -Domain broken.example -WarningAction SilentlyContinue
$checks = @($dnsFail.Findings | ForEach-Object { "$($_.Check)/$($_.Status)" })
if ($checks -notcontains 'DNS lookup/Warning' -or ($checks -match '^(SPF|DMARC|MX record)/')) {
    $failures.Add("DNS failure handling wrong: $($checks -join ', ')")
}

# Wrong tenant: the baseline must flag a tenant ID mismatch.
$wrong = Join-Path ([System.IO.Path]::GetTempPath()) 'wrong-tenant.psd1'
"@{ TenantName = 'other'; TenantId = '99999999-9999-9999-9999-999999999999' }" | Set-Content $wrong
$wrongResult = & (Join-Path $scripts 'Get-ExoBaselineReport.ps1') -BaselinePath $wrong
if (-not ($wrongResult.Findings | Where-Object { $_.Check -eq 'Connected tenant' -and $_.Status -eq 'Fail' })) {
    $failures.Add('Wrong-tenant baseline did not produce a Fail')
}

# Tenant profiles in the repo must load and only use known keys.
foreach ($p in Get-ChildItem (Join-Path $root 'tenants') -Filter *.psd1 -Recurse) {
    $data = Import-PowerShellDataFile $p.FullName
    $unknown = @($data.Keys | Where-Object { $_ -notin 'TenantName', 'TenantId', 'Dns', 'Exchange', 'Report' })
    if (-not $data.TenantName -or $unknown) { $failures.Add("Tenant profile $($p.Name) invalid (unknown keys: $($unknown -join ', '))") }
}

# Guard against false positives on correctly configured items.
$unexpected = @(
    , @('Partner connector restriction', 'Fail', 'Inbound from contoso-onprem')
    , @('Outbound connector TLS', 'Warning', 'Outbound to contoso-onprem')
    , @('Mailboxes forwarding externally', 'Fail', 'carol')
)
foreach ($e in $unexpected) {
    $hit = $findings | Where-Object { $_.Check -eq $e[0] -and $_.Status -eq $e[1] -and ($_.Target -like "*$($e[2])*" -or $_.Detail -like "*$($e[2])*") }
    if ($hit) { $failures.Add("Unexpected finding: $($e[0]) / $($e[1]) / $($e[2])") }
}

$html = Get-Content (Join-Path $OutputPath 'ExoHealthReport.html') -Raw
if ($html -notmatch 'Findings needing attention' -or $html -notmatch 'Contoso Lab') { $failures.Add('HTML report content missing') }

$summary = Get-Content (Join-Path $OutputPath 'Summary.json') -Raw | ConvertFrom-Json
Write-Host ("Findings: {0} total - Fail {1}, Warning {2}, Pass {3}, Info {4}, High {5}" -f $findings.Count,
    $summary.Fail, $summary.Warning, $summary.Pass, $summary.Info, $summary.HighSeverity)

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host "FAIL: $_" -ForegroundColor Red }
    exit 1
}
Write-Host "Smoke test passed. Report: $(Join-Path $OutputPath 'ExoHealthReport.html')" -ForegroundColor Green
