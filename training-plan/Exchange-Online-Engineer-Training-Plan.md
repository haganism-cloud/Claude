# Microsoft 365 Exchange Online Engineer — Two-Week Training Plan

A 10-working-day plan that takes an engineer from Exchange Online fundamentals to running,
interpreting and acting on a full tenant health assessment covering **connectors, mail flow and
security**. Every day pairs concepts with hands-on PowerShell labs and ends with one of the report
scripts in [`../scripts`](../scripts).

| | |
|---|---|
| **Audience** | Engineers with general Microsoft 365 / Windows admin experience who are new to, or want to formalise, Exchange Online engineering |
| **Duration** | 10 days, ~6 hours/day (concepts 1.5h, guided lab 2.5h, script work 1.5h, review 0.5h) |
| **Outcome** | Can administer Exchange Online with PowerShell, design and troubleshoot mail flow and connectors, harden EOP / Defender for Office 365, and deliver a tenant health report with a remediation plan |
| **Final assessment** | Day 10 capstone: run `Invoke-ExoTenantHealthCheck.ps1` against the lab tenant, present findings and fix the top five |

---

## Before Day 1: prerequisites and lab setup

**Accounts and licences**

- A **lab tenant** you are allowed to break: a Microsoft 365 E5 (or Business Premium + Defender for
  Office 365 Plan 2) trial works. Never practise configuration changes on production.
- One Global Administrator account for setup, plus a second account with **Global Reader** and
  **Security Reader** only — use this one for every report script to prove they run least-privilege.
- A custom domain you control DNS for (cheap registrar domain is fine). SPF/DKIM/DMARC labs need it.
- Optional for Day 9: an Exchange Server SE VM joined to a lab AD, for hybrid.

**Workstation**

```powershell
# PowerShell 7.4+ recommended (Windows PowerShell 5.1 also works)
Install-Module ExchangeOnlineManagement -Scope CurrentUser -MinimumVersion 3.4.0
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Devices.ServiceAnnouncement -Scope CurrentUser   # optional
Install-Module Pester -Scope CurrentUser -MinimumVersion 5.5.0                                                # optional

git clone <this repo>; Set-Location .\scripts
Get-Help .\Invoke-ExoTenantHealthCheck.ps1 -Full
```

**Offline practice:** `pwsh ./tests/Invoke-SmokeTest.ps1` runs every report against stubbed cmdlets
(`tests/ExoStubs.ps1`) that model a deliberately misconfigured tenant. Use it to read the scripts and
see sample output before you have a tenant.

**Seed the lab tenant (Day 0, ~1h):** create 10 users, 2 shared mailboxes, 1 room, 2 distribution
groups, 1 Microsoft 365 group; add the custom domain; send a few dozen messages between users and to
an external mailbox so message trace has data.

---

## Week 1 — Platform, recipients and mail flow

### Day 1 — Exchange Online architecture and PowerShell tooling

**Objectives**

- Explain where Exchange Online sits in Microsoft 365: Entra ID identity, EOP in front of every
  mailbox, Defender for Office 365 layered on EOP, Purview for compliance.
- Connect with the EXO V3 module (REST-based; Remote PowerShell is retired) interactively and
  app-only with a certificate.
- Use Exchange RBAC: role groups, management roles, scopes; know which admin portals own what
  (Exchange admin center, Defender portal, Purview portal, Microsoft 365 admin center).

**Concepts**

- `Get-EXOMailbox`, `Get-EXORecipient`, `Get-EXOMailboxStatistics`, `Get-EXOCASMailbox`,
  `Get-EXOMailboxPermission` (fast REST cmdlets, property sets, `-Properties`) vs. the older
  `Get-Mailbox` family.
- Server-side filtering (`-Filter` with OPATH) vs. client-side `Where-Object`; `-ResultSize Unlimited`.
- Throttling and why scripts should batch and retry.
- RBAC: `Get-RoleGroup`, `Get-ManagementRole`, `Get-ManagementRoleAssignment`, View-Only
  Organization Management, Global Reader; PIM for Entra roles.

**Lab**

```powershell
.\Connect-ExoTenant.ps1 -UserPrincipalName reader@lab.contoso.com
Get-ConnectionInformation | Format-List Name, UserPrincipalName, TokenStatus, ConnectionUri

# What can I do?
Get-ManagementRoleAssignment -RoleAssignee reader@lab.contoso.com -Delegating:$false |
    Select-Object Role, RoleAssigneeName, RecipientWriteScope

# Fast vs classic cmdlets
Measure-Command { Get-EXOMailbox -ResultSize Unlimited } | Select-Object TotalSeconds
Measure-Command { Get-Mailbox -ResultSize Unlimited }    | Select-Object TotalSeconds

# Server-side filter
Get-EXOMailbox -Filter "RecipientTypeDetails -eq 'SharedMailbox'" -Properties GrantSendOnBehalfTo
```

App-only lab: register an Entra app, upload a self-signed certificate, grant the
`Exchange.ManageAsApp` application permission and assign the app the **Global Reader** role, then:

```powershell
.\Connect-ExoTenant.ps1 -AppId <appId> -CertificateThumbprint <thumb> -Organization lab.onmicrosoft.com
```

**Script exercise:** run `Get-ExoTenantOverview.ps1 -OutputPath .\day1`. Read the script top to
bottom: note `Invoke-ExoSafe`, the section-result object, and how CSVs are exported.

**Knowledge check**

1. Why does `Get-EXOMailbox` return fewer properties by default than `Get-Mailbox`?
2. Which role lets an auditor read configuration but change nothing?
3. What are the two pieces an unattended script needs for app-only auth?

---

### Day 2 — Recipients, domains and organisation configuration

**Objectives**

- Manage every recipient type: user, shared, room/equipment, mail users/contacts, distribution
  groups, Microsoft 365 groups, dynamic groups.
- Configure accepted domains (Authoritative vs. InternalRelay), remote domains and organisation
  settings.
- Understand mailbox permissions (FullAccess, SendAs, SendOnBehalf), archives, retention and holds.

**Concepts**

- Directory-Based Edge Blocking (DBEB) and why Authoritative domains reject unknown recipients.
- Remote domains: auto-reply, auto-forward, TNEF, NDR settings per external domain.
- `Get-OrganizationConfig` highlights: `OAuth2ClientProfileEnabled`, `AuditDisabled`,
  MailTips, `IsDehydrated` / `Enable-OrganizationCustomization`.
- Inactive mailboxes, litigation hold, retention policies (MRM) vs. Purview retention.

**Lab**

```powershell
New-Mailbox -Shared -Name 'Helpdesk' -PrimarySmtpAddress helpdesk@lab.contoso.com
Add-MailboxPermission helpdesk -User alex -AccessRights FullAccess -AutoMapping $false
Add-RecipientPermission helpdesk -Trustee alex -AccessRights SendAs -Confirm:$false

New-DynamicDistributionGroup -Name 'All Sales' -RecipientFilter "(Department -eq 'Sales') -and (RecipientTypeDetails -eq 'UserMailbox')"
Get-DynamicDistributionGroupMember 'All Sales'

Get-AcceptedDomain | Format-Table DomainName, DomainType, Default
Get-RemoteDomain | Format-Table Name, DomainName, AutoForwardEnabled, AutoReplyEnabled

# Permissions audit for one mailbox
Get-EXOMailboxPermission helpdesk | Where-Object { $_.User -notlike 'NT AUTHORITY*' }
Get-EXORecipientPermission helpdesk
```

**Script exercise:** extend your Day 1 run with `-Verbose`. Add one new check to
`Get-ExoTenantOverview.ps1` in your own branch, e.g. "shared mailboxes with a licence" or
"mailboxes over 90% of quota" (`Get-EXOMailboxStatistics`), using `Add-ExoFinding`. Add a matching
stub to `tests/ExoStubs.ps1` and an assertion to `tests/Invoke-SmokeTest.ps1`.

**Knowledge check**

1. A domain is InternalRelay. What happens to mail sent to a non-existent address in it?
2. Difference between `SendAs` and `SendOnBehalf` — which cmdlet sets each?
3. Where do you stop users from auto-forwarding to one specific partner domain only?

---

### Day 3 — Mail flow architecture and connectors (part 1)

**Objectives**

- Trace a message's path: DNS MX → EOP connection filtering → anti-malware → mail flow rules →
  content filtering → Defender (Safe Attachments / Links) → mailbox.
- Know when connectors are needed and when they are not.
- Read and explain every property of an inbound and outbound connector.

**Concepts**

- Default routing: with no connectors, EOP accepts from the internet and delivers outbound by MX.
- Connector types: **Partner** (organisations / services you trust) vs. **OnPremises** (your own
  servers). Identification by sender IP or TLS certificate (`TlsSenderCertificateName`).
- `RestrictDomainsToIPAddresses` / `RestrictDomainsToCertificate` — without them a partner
  connector can be matched by anyone spoofing the partner's domain.
- Outbound: smart hosts vs. MX, `TlsSettings` (`EncryptionOnly`, `CertificateValidation`,
  `DomainValidation`), scoping by `RecipientDomains` or by transport rule (`IsTransportRuleScoped`).
- Centralized mail transport (`RouteAllMessagesViaOnPremises`).

**Lab**

```powershell
# Partner that must use TLS and come from known IPs
New-InboundConnector -Name 'From Fabrikam' -ConnectorType Partner -SenderDomains fabrikam.example `
    -SenderIPAddresses 203.0.113.10 -RestrictDomainsToIPAddresses $true -RequireTls $true

# Force TLS with certificate validation to a partner
New-OutboundConnector -Name 'To Fabrikam (forced TLS)' -ConnectorType Partner -RecipientDomains fabrikam.example `
    -UseMXRecord $true -TlsSettings DomainValidation -TlsDomain '*.fabrikam.example'

Get-InboundConnector | Format-List Name, ConnectorType, SenderDomains, SenderIPAddresses, Restrict*, RequireTls
Get-OutboundConnector | Format-List Name, RecipientDomains, SmartHosts, TlsSettings, TlsDomain, IsValidated
```

Then deliberately weaken the inbound connector (`-RestrictDomainsToIPAddresses $false`).

**Script exercise:** run `Get-ExoConnectorReport.ps1 -OutputPath .\day3`. Confirm it raises
*Partner connector restriction — Fail* for the weakened connector, fix it, re-run, confirm *Pass*.

**Knowledge check**

1. Why is `SenderDomains *` with no IP/cert restriction a spoofing risk?
2. What does `DomainValidation` check that `EncryptionOnly` does not?
3. Name two reasons to scope an outbound connector by transport rule.

---

### Day 4 — Connectors (part 2): relay scenarios, third-party filtering, validation

**Objectives**

- Choose the right method for devices and applications that send mail: SMTP AUTH client
  submission, Direct Send, or SMTP relay via a connector — and their security trade-offs.
- Configure Exchange Online behind a third-party filter or gateway correctly (Enhanced Filtering
  for Connectors).
- Validate and troubleshoot connectors.

**Concepts**

- SMTP AUTH (port 587, authenticated mailbox): Basic auth for SMTP AUTH client submission is being
  retired by Microsoft — plan OAuth or alternatives and check Message Center for current dates.
  `Set-TransportConfig -SmtpClientAuthenticationDisabled` and per-mailbox
  `Set-CASMailbox -SmtpClientAuthenticationDisabled`.
- Direct Send (unauthenticated to your MX, internal recipients only) and
  `Set-OrganizationConfig -RejectDirectSend $true` to stop abuse once devices are moved.
- Connector relay: inbound OnPremises/Partner connector identified by static IP or certificate.
- MX pointing elsewhere: EOP sees the gateway IP as the sender → SPF/DMARC and IP reputation
  break unless `EFSkipLastIP` / `EFSkipIPs` (Enhanced Filtering) is set on the inbound connector.
- `Validate-OutboundConnector` and the `IsValidated` / `LastValidationTimestamp` properties.

**Lab**

```powershell
# Enhanced filtering in front of a (simulated) third-party gateway
Set-InboundConnector 'From Gateway' -EFSkipLastIP $true -EFTestMode $true

# Device relay via certificate-identified connector
New-InboundConnector -Name 'MFP relay' -ConnectorType OnPremises -SenderDomains * `
    -TlsSenderCertificateName relay.lab.contoso.com -RequireTls $true

# Who still uses SMTP AUTH? (requires the report in the Defender / Exchange admin center or:)
Get-EXOCASMailbox -ResultSize Unlimited -Properties SmtpClientAuthenticationDisabled |
    Where-Object SmtpClientAuthenticationDisabled -eq $false

Validate-OutboundConnector -Identity 'To Fabrikam (forced TLS)' -Recipients test@fabrikam.example
```

**Script exercise:** re-run `Get-ExoConnectorReport.ps1` and `Get-ExoSecurityReport.ps1
-IncludeMailboxLevelChecks`. Map each Direct Send / SMTP AUTH / Enhanced Filtering finding to a
written remediation step.

**Knowledge check**

1. A multifunction printer must email external recipients. Which of the three methods works, and why
   not the others?
2. MX points to a third-party filter and DMARC fails for legitimate mail. What is missing?
3. What does `RejectDirectSend` break if enabled too early?

---

### Day 5 — Mail flow rules, journaling and message trace troubleshooting

**Objectives**

- Build, order, test and audit mail flow (transport) rules.
- Troubleshoot delivery end to end with message trace, NDR codes and header analysis.
- Configure journaling correctly.

**Concepts**

- Rule anatomy: conditions, exceptions, actions, priority, `Mode` (`Audit`, `AuditAndNotify`,
  `Enforce`), `StopRuleProcessing`, activation/expiry dates.
- Risky rules: `SetSCL -1` keyed on sender domain (spoofable), BCC/redirect to external addresses
  (classic post-compromise persistence), rules pointing at deleted connectors.
- **Message trace V2**: `Get-MessageTraceV2` / `Get-MessageTraceDetailV2` (the legacy
  `Get-MessageTrace` is deprecated). 90 days of data, up to 10 days per query, 5,000 rows per call,
  paging with `StartingRecipientAddress` + `EndDate`. `Start-HistoricalSearch` for large exports.
- NDR anatomy: `5.1.10` (recipient not found), `5.4.1` (DBEB / relay denied), `5.7.1` / `5.7.23`
  (SPF / authentication), `5.7.509` (DMARC reject), `5.7.705`/`5.7.708` (tenant/IP blocked for
  spam), `4.4.7` (expired, delivery delay).
- Tools: Message Header Analyzer, Microsoft Remote Connectivity Analyzer, Get-MailflowStatusReport.
- Journaling: `New-JournalRule`, and why `JournalingReportNdrTo` must be a non-journaled mailbox.

**Lab**

```powershell
New-TransportRule -Name 'Tag external' -FromScope NotInOrganization -PrependSubject '[EXT] ' -Mode Audit
New-TransportRule -Name 'BAD - bypass vendor' -SenderDomainIs vendor.example -SetSCL -1      # for the report to catch

$t = Get-MessageTraceV2 -StartDate (Get-Date).AddDays(-2) -EndDate (Get-Date) -ResultSize 5000
$t | Group-Object Status | Sort-Object Count -Descending
$f = $t | Where-Object Status -eq Failed | Select-Object -First 1
Get-MessageTraceDetailV2 -MessageTraceId $f.MessageTraceId -RecipientAddress $f.RecipientAddress |
    Format-List Date, Event, Action, Detail

# Long-range export (results arrive by email / in the portal)
Start-HistoricalSearch -ReportTitle 'Lab 30d' -ReportType MessageTrace -StartDate (Get-Date).AddDays(-30) `
    -EndDate (Get-Date) -NotifyAddress you@lab.contoso.com
```

Send mail to a non-existent address in your Authoritative domain, to a non-existent external
domain, and with a 40 MB attachment; trace each and identify the NDR code.

**Script exercise:** run `Get-ExoMailFlowReport.ps1 -Days 7 -OutputPath .\day5`. Confirm the
*Spam bypass on spoofable condition* finding for the "BAD" rule. Read `TraceByDirection.csv` and
`TopFailedRecipientDomains.csv`. Remove the bad rule.

**Week 1 review (last hour):** 20-question quiz on Days 1–5; each learner explains one connector
and one transport rule from the lab tenant to the group.

**Knowledge check**

1. Why is `SetSCL -1` on `SenderDomainIs` dangerous, and what is the safer alternative?
2. How do you page through more than 5,000 trace results with V2?
3. A user reports "5.7.509 Access denied". Whose configuration do you check?

---

## Week 2 — Security, hybrid and automation

### Day 6 — Email authentication: SPF, DKIM, DMARC, ARC, MTA-STS, DANE

**Objectives**

- Publish and validate SPF, DKIM and DMARC for a custom domain and take DMARC to enforcement.
- Understand how Exchange Online evaluates inbound authentication (composite authentication,
  `compauth`), ARC and trusted ARC sealers.
- Protect inbound SMTP transport with MTA-STS / TLS-RPT and SMTP DANE with DNSSEC.

**Concepts**

- SPF: single record, `include:spf.protection.outlook.com`, `-all` vs `~all`, the 10-lookup limit.
- DKIM: selector1/selector2 CNAMEs, `New-DkimSigningConfig`, `Rotate-DkimSigningConfig`, 2048-bit
  keys. Without custom DKIM, mail is signed by the onmicrosoft.com domain (no DMARC alignment).
- DMARC: `p=none` → `quarantine` → `reject`, `rua` reports, `pct`, `sp`, alignment;
  `HonorDmarcPolicy` in anti-phishing policy.
- ARC: `Set-ArcConfig -ArcTrustedSealers` for intermediaries (mailing lists, third-party filters).
- MTA-STS + TLS-RPT; inbound SMTP DANE with DNSSEC (`Enable-DnssecForVerifiedDomain`,
  `Enable-SmtpDaneInbound`) and the newer `*.mx.microsoft` MX endpoints.

**Lab**

```powershell
New-DkimSigningConfig -DomainName lab.contoso.com -Enabled $false
Get-DkimSigningConfig lab.contoso.com | Format-List Selector1CNAME, Selector2CNAME
# publish the two CNAMEs at your registrar, wait for DNS, then:
Set-DkimSigningConfig -Identity lab.contoso.com -Enabled $true

# Inspect authentication results on a received message header:
#   Authentication-Results: spf=pass ... dkim=pass ... dmarc=pass action=none ... compauth=pass reason=100
```

Publish `v=DMARC1; p=none; rua=mailto:dmarc@lab.contoso.com`, send test mail to an external
mailbox, inspect headers, then move to `p=quarantine`.

**Script exercise:** run `Get-ExoDomainDnsReport.ps1` before and after each DNS change. On a
non-Windows machine, note it falls back to DNS-over-HTTPS. Explain each SPF lookup the script
counted for your domain.

**Knowledge check**

1. Why does DKIM need two selectors?
2. SPF passes but DMARC fails. Give two possible reasons.
3. What does `compauth=fail reason=601` tell you?

---

### Day 7 — EOP and Defender for Office 365 policies

**Objectives**

- Configure and evaluate anti-spam, anti-malware, anti-phishing, Safe Links and Safe Attachments.
- Use preset security policies and Configuration analyzer; understand policy precedence.
- Manage quarantine, quarantine policies, Tenant Allow/Block List, user submissions and ZAP.

**Concepts**

- Policy order: Strict preset → Standard preset → custom policies (by priority) → default /
  Built-in protection.
- Anti-spam actions per verdict (spam, high-confidence spam, phish, high-confidence phish, bulk)
  and `BulkThreshold`. Why `AllowedSenderDomains` and the connection-filter `IPAllowList` are
  dangerous.
- Anti-phishing: spoof intelligence, impersonation (users, domains), mailbox intelligence,
  first-contact safety tip, phishing threshold.
- Defender: Safe Links (URL detonation, wait for scan, click-through), Safe Attachments (Block /
  Dynamic Delivery), Safe Attachments for SharePoint/OneDrive/Teams, Safe Documents.
- Quarantine policies (`AdminOnlyAccessPolicy`), release workflows, `Get-QuarantineMessage`.
- Advanced delivery policy for phishing simulations and SecOps mailboxes (instead of SCL -1 rules).
- Outbound spam policy: recipient limits, `AutoForwardingMode`, restricted users
  (`Get-BlockedSenderAddress`).

**Lab**

```powershell
Get-HostedContentFilterPolicy | Format-List Name, *Action, BulkThreshold, Allowed*
Get-AntiPhishPolicy | Format-List Name, EnableSpoofIntelligence, HonorDmarcPolicy, EnableFirstContactSafetyTips, PhishThresholdLevel
Get-SafeLinksPolicy | Format-List Name, EnableSafeLinksForEmail, DeliverMessageAfterScan, AllowClickThrough
Get-EOPProtectionPolicyRule; Get-ATPProtectionPolicyRule        # preset policy assignment

# Turn on the Standard preset for a pilot group in the Defender portal, then compare:
Get-HostedContentFilterPolicy | Select-Object Name, RecommendedPolicyType

New-TenantAllowBlockListItems -ListType Sender -Block -Entries baddomain.example -NoExpiration
Get-QuarantineMessage -StartReceivedDate (Get-Date).AddDays(-7) | Group-Object QuarantineTypes
```

Send an EICAR test file and a GTUBE test message from an external mailbox; find each in
quarantine and in message trace.

**Script exercise:** run `Get-ExoSecurityReport.ps1 -OutputPath .\day7`. Add `partner.example`
to `AllowedSenderDomains` in a custom anti-spam policy and confirm the *High* finding appears. Fix
it using the recommended approach. Compare your custom policy to the Standard preset with
Configuration analyzer.

**Knowledge check**

1. A user is in both the Standard preset and a custom anti-phish policy. Which applies?
2. Why prefer a Tenant Allow/Block List entry with an expiry over `AllowedSenders`?
3. What must be true for Safe Links to protect URLs in Teams?

---

### Day 8 — Identity, access, auditing and compromise response

**Objectives**

- Harden client access: modern auth, authentication policies, POP/IMAP/EWS/SMTP AUTH exposure,
  Conditional Access interplay.
- Lock down external forwarding at every layer.
- Ensure auditing is on and use it to investigate; respond to a compromised mailbox.
- Control application access with RBAC for Applications.

**Concepts**

- `OAuth2ClientProfileEnabled`, authentication policies (`New-AuthenticationPolicy`), CAS mailbox
  plans; EWS retirement in Exchange Online (Microsoft's announced timeline begins October 2026 —
  inventory EWS apps and move them to Microsoft Graph; check Message Center for current dates).
- Forwarding controls: outbound spam policy `AutoForwardingMode`, remote domain
  `AutoForwardEnabled`, mailbox `ForwardingSmtpAddress`, inbox rules, transport rules.
- Auditing: unified audit log (`Get-AdminAuditLogConfig`), mailbox auditing on by default,
  `Get-MailboxAuditBypassAssociation`, `Search-UnifiedAuditLog` (and the Purview audit search).
- Compromise playbook: block sign-in / revoke sessions (Entra), reset password + MFA, remove
  malicious inbox rules / forwarding / delegates, check sent items and `MailItemsAccessed`, review
  `Get-BlockedSenderAddress`, `Remove-BlockedSenderAddress` after clean-up.
- RBAC for Applications: `New-ManagementScope` + `New-ManagementRoleAssignment -App` to restrict an
  app's Graph mail permissions to specific mailboxes (replaces Application Access Policies).

**Lab**

```powershell
Set-RemoteDomain Default -AutoForwardEnabled $false
Set-HostedOutboundSpamFilterPolicy Default -AutoForwardingMode Off

# Simulated BEC: as a test user create an inbox rule forwarding to an external address and marking as read,
# then hunt for it:
Get-InboxRule -Mailbox testuser | Format-List Name, Enabled, ForwardTo, RedirectTo, MarkAsRead, MoveToFolder
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -Operations New-InboxRule, Set-InboxRule

# Scope an app to one mailbox group with RBAC for Applications
New-ManagementScope -Name 'Notifier mailboxes' -RecipientRestrictionFilter "CustomAttribute1 -eq 'notifier'"
New-ServicePrincipal -AppId <appId> -ObjectId <enterpriseAppObjectId> -DisplayName 'Notifier'
New-ManagementRoleAssignment -App <appId> -Role 'Application Mail.Send' -CustomResourceScope 'Notifier mailboxes'
Test-ServicePrincipalAuthorization -Identity <appId> -Resource someone@lab.contoso.com
```

**Script exercise:** run `Get-ExoSecurityReport.ps1 -IncludeMailboxLevelChecks -IncludeInboxRules`.
It must flag the simulated BEC rule and any external `ForwardingSmtpAddress`. Write a one-page
incident note from the output.

**Knowledge check**

1. List four places external forwarding can be configured and the control for each.
2. Which audit record proves an attacker read a mailbox item?
3. How does RBAC for Applications differ from granting `Mail.Send` in Entra alone?

---

### Day 9 — Hybrid, migrations and on-premises connectors

**Objectives**

- Describe hybrid components: Hybrid Configuration Wizard (Classic vs. Modern/Hybrid Agent),
  OAuth/IntraOrganizationConnector, organisation relationships, hybrid mail flow connectors,
  migration endpoints.
- Run and troubleshoot remote move migrations.
- Maintain hybrid safely: certificate renewals, Exchange Server SE updates, the dedicated Exchange
  hybrid application in Entra ID, decommissioning the last Exchange server.

**Concepts**

- Exchange Server 2016/2019 reached end of support in October 2025; Exchange Server Subscription
  Edition (SE) is the supported on-premises version.
- Hybrid mail flow: `Outbound to <org>` and `Inbound from <org>` connectors created by HCW;
  certificate-based identification; centralized mail transport.
- Free/busy and OAuth: `Get-IntraOrganizationConnector`, `Test-OAuthConnectivity`,
  `Get-OrganizationRelationship`; Microsoft's guidance to move hybrid to a dedicated Entra app
  instead of the shared Exchange Online service principal.
- Migrations: `New-MigrationBatch`, `Get-MigrationUser`, `Get-MoveRequestStatistics -IncludeReport`,
  bad item limits, completion.
- Certificate expiry is the #1 cause of sudden hybrid mail-flow outages.

**Lab** (with an on-premises VM; otherwise read through using the stub data)

```powershell
# Exchange Online side
Get-OnPremisesOrganization | Format-List
Get-IntraOrganizationConnector | Format-List
Test-OAuthConnectivity -Service EWS -TargetUri https://mail.lab.contoso.com/ews/exchange.asmx -Mailbox clouduser@lab.contoso.com

# On-premises Exchange Management Shell
Get-ExchangeCertificate | Format-Table Thumbprint, Services, NotAfter, Subject
Get-SendConnector | Format-List Name, AddressSpaces, SmartHosts, TlsCertificateName, CloudServicesMailEnabled
Get-ReceiveConnector | Format-Table Identity, Bindings, RemoteIPRanges, PermissionGroups

# Migration
New-MigrationBatch -Name Pilot -SourceEndpoint 'Hybrid Migration Endpoint - EWS' -TargetDeliveryDomain lab.mail.onmicrosoft.com `
    -CSVData ([IO.File]::ReadAllBytes('.\pilot.csv')) -AutoStart
Get-MigrationUser -BatchId Pilot | Get-MigrationUserStatistics | Format-Table Identity, Status, PercentageComplete
```

**Script exercise:** run `Get-ExoConnectorReport.ps1` (cloud side) and, in the Exchange Management
Shell, `Get-ExchangeServerConnectorReport.ps1` (on-premises side). Reconcile: does every
`OnPremisesOrganization` connector reference exist? Is any SMTP certificate expiring within 60 days?
Are any receive connectors open relays?

**Knowledge check**

1. Hybrid free/busy fails one way only. Which objects and tests do you check first?
2. A certificate was renewed on-premises and cloud-to-on-prem mail stopped. Why, and what fixes it?
3. What must remain on-premises after moving all mailboxes if you still use AD as the source of
   authority?

---

### Day 10 — Automation, monitoring and capstone

**Objectives**

- Run the full health check unattended on a schedule and alert on high-severity findings.
- Turn findings into a prioritised remediation plan and execute it with change control.
- Demonstrate end-to-end competence in the capstone.

**Concepts**

- Unattended runs: app-only certificate auth, Azure Automation (managed identity with
  `Connect-ExchangeOnline -ManagedIdentity`), or a scheduled task on a hardened admin host.
- Exit codes (`-FailOnHighSeverity`) and `Summary.json` for trending and alerting.
- Baselines: keep each run's output; diff `AllFindings.csv` week over week.
- Change management: test in lab, use `-WhatIf` where supported, record before/after state.

**Lab: schedule it**

```powershell
# Azure Automation runbook body (managed identity has Exchange.ManageAsApp + Global Reader)
Connect-ExchangeOnline -ManagedIdentity -Organization lab.onmicrosoft.com
.\Invoke-ExoTenantHealthCheck.ps1 -OutputPath "$env:TEMP\exo" -MessageTraceDays 1 -FailOnHighSeverity

# Or locally with a certificate:
.\Invoke-ExoTenantHealthCheck.ps1 -Connect -ConnectParameters @{
    AppId = '<appId>'; CertificateThumbprint = '<thumb>'; Organization = 'lab.onmicrosoft.com' } `
    -IncludeMailboxLevelChecks -OutputPath "D:\Reports\EXO\$(Get-Date -f yyyyMMdd)"
```

**Capstone (4 hours)**

The trainer seeds the lab tenant with 10 hidden misconfigurations covering connectors, mail flow
and security (examples: unrestricted partner connector, opportunistic-TLS egress connector,
`SetSCL -1` sender-domain rule, BCC-to-external rule, `AllowedSenderDomains`, external
auto-forwarding on, a forwarding mailbox, DKIM disabled, DMARC `p=none`, journaling without an NDR
mailbox). The learner:

1. Runs `Invoke-ExoTenantHealthCheck.ps1 -IncludeMailboxLevelChecks -IncludeInboxRules` with the
   least-privilege account.
2. Triages the HTML report into a remediation plan: risk, business impact, fix, rollback, owner.
3. Fixes the top five with an admin account, documenting each command.
4. Re-runs the report and shows the delta.
5. Presents (15 minutes) to the trainer acting as the IT manager.

**Assessment rubric**

| Area | Meets standard |
|---|---|
| Discovery | Finds ≥ 8 of 10 seeded issues from the report and manual checks |
| Prioritisation | High-severity security and mail-loss issues fixed first, with justification |
| Remediation | Correct cmdlets, no collateral breakage (mail flow verified by trace after each change) |
| Least privilege | Reports run without admin rights; changes made with a separate account |
| Communication | Plain-language summary a manager can act on; evidence attached (before/after CSVs) |

---

## Script reference

| Script | Covers | Typical runtime* |
|---|---|---|
| `Connect-ExoTenant.ps1` | Interactive or app-only connection; optional IPPS and Graph | seconds |
| `Get-ExoTenantOverview.ps1` | Org config, domains, recipient/mailbox inventory, Organization Management, service health | 1–5 min |
| `Get-ExoConnectorReport.ps1` | Inbound/outbound connectors, Enhanced Filtering, TLS, validation, hybrid objects, IOC, org relationships, migration endpoints | < 1 min |
| `Get-ExoMailFlowReport.ps1` | Message trace V2 statistics, failure rates, top senders/failed domains, mail flow rules, journaling, transport config | 1–10 min |
| `Get-ExoSecurityReport.ps1` | Modern auth, auditing, SMTP AUTH, Direct Send, forwarding, anti-spam/malware/phish, Safe Links/Attachments, presets, TABL, quarantine, restricted users, app access, optional mailbox & inbox-rule checks | 1 min – hours with inbox rules |
| `Get-ExoDomainDnsReport.ps1` | MX, SPF (incl. lookup count), DKIM config + CNAMEs, DMARC, MTA-STS, TLS-RPT | < 1 min |
| `Invoke-ExoTenantHealthCheck.ps1` | Runs all of the above → HTML + CSV + JSON | sum of above |
| `Get-ExchangeServerConnectorReport.ps1` | On-premises send/receive connectors, open relay, certificate expiry (Exchange Management Shell) | < 1 min |

\*Depends on tenant size; inbox-rule scanning is roughly one call per mailbox.

All scripts are **read-only**: they only call `Get-*` cmdlets (plus public DNS lookups). Every
remediation is a recommendation for a human to apply.

## Cheat sheet

```powershell
# Connect / context
Connect-ExchangeOnline -UserPrincipalName admin@contoso.com ; Get-ConnectionInformation

# Mail flow
Get-MessageTraceV2 -SenderAddress a@contoso.com -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date)
Get-MessageTraceDetailV2 -MessageTraceId <id> -RecipientAddress <addr>
Get-TransportRule | Sort-Object Priority | Format-Table Priority, Name, State, Mode
Get-InboundConnector; Get-OutboundConnector; Validate-OutboundConnector -Identity <name> -Recipients <addr>

# Security
Get-HostedContentFilterPolicy; Get-AntiPhishPolicy; Get-MalwareFilterPolicy; Get-SafeLinksPolicy; Get-SafeAttachmentPolicy
Get-TenantAllowBlockListItems -ListType Sender; Get-QuarantineMessage; Get-BlockedSenderAddress
Get-DkimSigningConfig; Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled
Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress | ? ForwardingSmtpAddress

# Hybrid
Get-OnPremisesOrganization; Get-IntraOrganizationConnector; Get-OrganizationRelationship; Get-MigrationEndpoint
```

## Further reading (Microsoft Learn)

- Exchange Online PowerShell: <https://learn.microsoft.com/powershell/exchange/exchange-online-powershell>
- Mail flow and connectors: <https://learn.microsoft.com/exchange/mail-flow-best-practices/mail-flow-best-practices>
- Mail flow rules: <https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules>
- Email authentication (SPF, DKIM, DMARC): <https://learn.microsoft.com/defender-office-365/email-authentication-about>
- Recommended EOP / Defender for Office 365 settings: <https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365>
- Exchange hybrid deployments: <https://learn.microsoft.com/exchange/exchange-hybrid>

> Product timelines (SMTP AUTH Basic auth, EWS, Exchange Server support) change. Confirm current
> dates in the Microsoft 365 Message Center before planning work around them.
