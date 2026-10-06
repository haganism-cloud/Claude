# Exchange Online Engineer Training & Tenant Health Toolkit

- **[Two-week training plan](training-plan/Exchange-Online-Engineer-Training-Plan.md)** for a
  Microsoft 365 Exchange Online engineer: 10 days of concepts, hands-on labs, knowledge checks and
  a capstone.
- **[PowerShell scripts](scripts/)** that analyse an Exchange Online tenant and report on its
  overall status: **all connectors, mail flow and security**. They produce an HTML report plus CSV and
  JSON exports.

- **[BYOD security remediation plan](byod/)**: issues that personal devices create for a cloud-only
  Microsoft 365 tenant, ordered by criticality with remediation steps (`.numbers` and `.xlsx`).

## Quick start

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -MinimumVersion 3.4.0
cd scripts
.\Connect-ExoTenant.ps1 -UserPrincipalName reader@contoso.onmicrosoft.com    # Global Reader + Security Reader is enough
.\Invoke-ExoTenantHealthCheck.ps1 -MessageTraceDays 7 -IncludeMailboxLevelChecks
# -> .\ExoHealth-<timestamp>\ExoHealthReport.html
```

Run one area on its own:

```powershell
.\Get-ExoConnectorReport.ps1   -OutputPath .\out
.\Get-ExoMailFlowReport.ps1    -Days 7 -OutputPath .\out
.\Get-ExoSecurityReport.ps1    -IncludeMailboxLevelChecks -IncludeInboxRules -OutputPath .\out
.\Get-ExoDomainDnsReport.ps1   -Domain contoso.com           # works without a connection when -Domain is given
```

Unattended (certificate auth; exit code 2 on high-severity findings):

```powershell
.\Invoke-ExoTenantHealthCheck.ps1 -Connect -ConnectParameters @{
    AppId = '<appId>'; CertificateThumbprint = '<thumbprint>'; Organization = 'contoso.onmicrosoft.com' } -FailOnHighSeverity
```

## Tenant profiles

A tenant profile (`.psd1`) records what a specific tenant *should* look like: tenant ID,
expected MX/SPF/DMARC, and allowed domains, connectors and mail flow rules. Pass it with
`-BaselinePath` to add a **Baseline Drift** section that flags changes and stops you from reporting on
the wrong tenant.

- **[haganism.net](tenants/haganism.net/)**: profile, one-command runner
  (`Invoke-HaganismNetHealthCheck.ps1`, with a `-DnsOnly` mode that needs no sign-in) and the
  current public email-authentication findings.

## What it checks

| Area | Highlights |
|---|---|
| **Connectors** | Unrestricted partner inbound connectors (spoofing bypass), on-prem connector identification, RequireTls, Enhanced Filtering, outbound TLS validation, egress scope, validation age, hybrid objects referencing missing connectors, IOC / organization relationships, migration endpoints; on-premises send/receive connectors, open relay and certificate expiry (`Get-ExchangeServerConnectorReport.ps1`) |
| **Mail flow** | Message trace V2 volume by status / direction / day, failure rate, pending messages, top senders and failing domains, transport rules (SCL -1 on spoofable conditions, external BCC/redirect, missing connectors, test mode, expired), journaling NDR mailbox, reply-all storm protection |
| **Security** | Modern auth, unified audit log, mailbox auditing and bypass, SMTP AUTH, Direct Send, external tagging, auto-forwarding (policy, mailbox, inbox rules), restricted users, anti-spam/malware/phish settings, allow lists, Safe Links / Safe Attachments, presets, Tenant Allow/Block List hygiene, quarantine releases, RBAC for Applications |
| **Email authentication** | MX target, SPF (single record, EXO include, `all` qualifier, recursive 10-lookup limit), DKIM enabled / key size / CNAMEs, DMARC policy and reporting, MTA-STS, TLS-RPT |
| **Baseline drift** | Connected tenant ID, MX / SPF / DMARC / DKIM changes, unexpected or missing accepted domains, connectors and mail flow rules (`Get-ExoBaselineReport.ps1`, with `-BaselinePath`) |
| **Tenant overview** | Org config, accepted / remote domains, recipient and mailbox inventory, holds and archives, Organization Management membership, Exchange Online service health (Graph) |

Every check yields a finding with **Status** (Fail / Warning / Pass / Info), **Severity**
(High / Medium / Low), the affected object, details and a remediation recommendation.

The scripts are **read-only**: they only call `Get-*` cmdlets and public DNS. They run on Windows
PowerShell 5.1 and PowerShell 7 (Windows, macOS, Linux).

## Testing without a tenant

```powershell
pwsh ./tests/Invoke-SmokeTest.ps1
```

The smoke test parses every script, then runs the full health check against stubbed Exchange cmdlets
(`tests/ExoStubs.ps1`), which model a misconfigured lab tenant. It asserts that the expected findings appear (including baseline drift,
wrong-tenant detection and DNS-failure handling) and that correctly configured objects produce no false positives. The stubs also serve as
training material: each one notes which finding it is meant to trigger.

## Layout

```
training-plan/Exchange-Online-Engineer-Training-Plan.md
scripts/
  ExoHealth.Common.ps1                  shared helpers (findings, safe calls, DNS, CSV/HTML export)
  Connect-ExoTenant.ps1
  Get-ExoTenantOverview.ps1
  Get-ExoConnectorReport.ps1
  Get-ExoMailFlowReport.ps1
  Get-ExoSecurityReport.ps1
  Get-ExoDomainDnsReport.ps1
  Get-ExchangeServerConnectorReport.ps1 run in the on-premises Exchange Management Shell
  Get-ExoBaselineReport.ps1             drift from a tenant profile
  Invoke-ExoTenantHealthCheck.ps1       runs everything and writes the report
tenants/
  haganism.net/                         profile, runner and current findings for haganism.net
tests/
  ExoStubs.ps1
  contoso.baseline.psd1
  Invoke-SmokeTest.ps1
```
