"""Builds Exchange-Online-Security-Checks.xlsx: every Exchange Online security check as
(1) PowerShell commands and (2) the same check in the web admin consoles, matched by ID.

Requires: openpyxl
"""

from pathlib import Path

OUT = Path(__file__).parent / "Exchange-Online-Security-Checks.xlsx"

NO_GUI = "No admin-center setting - PowerShell only (see the PowerShell sheet)."

# Each check: id, category, check, severity, ps_check, secure, risk, ps_fix, gui_console,
# gui_view, gui_fix. Severity = impact if the check fails.
CHECKS = [
    # ---------------------------------------------------------------- Connect
    dict(id="C-01", cat="Connect", check="Install / update the Exchange Online module", sev="-",
         ps="Install-Module ExchangeOnlineManagement -Scope CurrentUser -MinimumVersion 3.4.0\nUpdate-Module ExchangeOnlineManagement",
         secure="Version 3.4.0 or later (Get-Module ExchangeOnlineManagement -ListAvailable)",
         risk="Older modules lack Get-MessageTraceV2 and newer security cmdlets.",
         fix="-", console="-", view="Not applicable - the web consoles need no installation.", gfix="-"),
    dict(id="C-02", cat="Connect", check="Connect to Exchange Online (read-only account)", sev="-",
         ps="Connect-ExchangeOnline -UserPrincipalName reader@yourdomain.com -ShowBanner:$false\nGet-ConnectionInformation | fl TenantID, UserPrincipalName",
         secure="Connected; TenantID is your tenant. Use Global Reader + Security Reader for checks.",
         risk="Running checks as Global Admin is unnecessary risk.",
         fix="-", console="Microsoft 365 admin center",
         view="Sign in at https://admin.microsoft.com, https://admin.exchange.microsoft.com and https://security.microsoft.com with a Global Reader + Security Reader account.",
         gfix="Microsoft 365 admin center > Users > Active users > user > Manage roles: assign Global Reader and Security Reader."),
    dict(id="C-03", cat="Connect", check="Connect to Security & Compliance PowerShell (for alert policies)", sev="-",
         ps="Connect-IPPSSession -UserPrincipalName reader@yourdomain.com",
         secure="Connected (needed only for check A-05).", risk="-", fix="-",
         console="Microsoft Purview portal", view="https://purview.microsoft.com", gfix="-"),

    # ---------------------------------------------------------------- Authentication
    dict(id="AU-01", cat="Authentication", check="Modern authentication enabled for Outlook", sev="High",
         ps="Get-OrganizationConfig | Format-List OAuth2ClientProfileEnabled",
         secure="True", risk="Outlook falls back to legacy authentication that cannot do MFA.",
         fix="Set-OrganizationConfig -OAuth2ClientProfileEnabled $true",
         console="Microsoft 365 admin center",
         view="Settings > Org settings > Services > Modern authentication",
         gfix="Tick 'Turn on modern authentication for Outlook 2013 for Windows and later' > Save."),
    dict(id="AU-02", cat="Authentication", check="SMTP AUTH disabled tenant-wide", sev="Medium",
         ps="Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled",
         secure="True (enable per mailbox only where an app/device requires it)",
         risk="Every mailbox accepts authenticated SMTP submission - a password-spray and spam relay target.",
         fix="Set-TransportConfig -SmtpClientAuthenticationDisabled $true",
         console="Exchange admin center", view="Settings > Mail flow",
         gfix="Tick 'Turn off SMTP AUTH protocol for your organization' > Save."),
    dict(id="AU-03", cat="Authentication", check="Per-mailbox POP, IMAP, SMTP AUTH and ActiveSync exceptions", sev="Medium",
         ps="Get-EXOCASMailbox -ResultSize Unlimited -Properties PopEnabled,ImapEnabled,SmtpClientAuthenticationDisabled,ActiveSyncEnabled |\n  Where-Object { $_.PopEnabled -or $_.ImapEnabled -or $_.SmtpClientAuthenticationDisabled -eq $false } |\n  Select-Object PrimarySmtpAddress,PopEnabled,ImapEnabled,SmtpClientAuthenticationDisabled,ActiveSyncEnabled",
         secure="Only documented service accounts listed",
         risk="Protocols without MFA left open on user mailboxes.",
         fix="Set-CASMailbox <user> -PopEnabled $false -ImapEnabled $false -SmtpClientAuthenticationDisabled $true",
         console="Microsoft 365 admin center",
         view="Users > Active users > select user > Mail tab > Manage email apps",
         gfix="Untick POP, IMAP and Authenticated SMTP (and Exchange ActiveSync if not needed) > Save changes. Per user only."),
    dict(id="AU-04", cat="Authentication", check="Default protocol settings for new mailboxes (CAS mailbox plans)", sev="Low",
         ps="Get-CASMailboxPlan | Format-Table Name,PopEnabled,ImapEnabled,ActiveSyncEnabled",
         secure="PopEnabled False, ImapEnabled False",
         risk="New users get POP/IMAP turned on by default.",
         fix="Get-CASMailboxPlan | Set-CASMailboxPlan -PopEnabled $false -ImapEnabled $false",
         console="-", view=NO_GUI, gfix=NO_GUI + " In the GUI, fix each new user via check AU-03."),
    dict(id="AU-05", cat="Authentication", check="Direct Send (unauthenticated mail to your MX from your own domain)", sev="Medium",
         ps="Get-OrganizationConfig | Format-List RejectDirectSend",
         secure="True (after printers/apps moved to SMTP AUTH or a connector)",
         risk="Attackers send internal-looking phishing to your users through your MX.",
         fix="Set-OrganizationConfig -RejectDirectSend $true",
         console="-", view=NO_GUI, gfix=NO_GUI),
    dict(id="AU-06", cat="Authentication", check="Legacy TLS 1.0/1.1 clients allowed", sev="Low",
         ps="Get-TransportConfig | Format-List AllowLegacyTLSClients",
         secure="False", risk="Old devices negotiate weak TLS.",
         fix="Set-TransportConfig -AllowLegacyTLSClients $false",
         console="Exchange admin center", view="Settings > Mail flow",
         gfix="Turn off 'Turn on use of legacy TLS clients' > Save."),
    dict(id="AU-07", cat="Authentication", check="Authentication policies (Basic auth blocks)", sev="Low",
         ps="Get-AuthenticationPolicy | Format-List Name,AllowBasicAuth*\nGet-OrganizationConfig | Format-List DefaultAuthenticationPolicy",
         secure="Basic auth not allowed for any protocol (Microsoft has retired most Basic auth)",
         risk="Remaining Basic auth paths bypass MFA.",
         fix="New-AuthenticationPolicy -Name 'Block Basic Auth'; Set-OrganizationConfig -DefaultAuthenticationPolicy 'Block Basic Auth'",
         console="Microsoft Entra admin center",
         view="Conditional Access > Policies: look for a policy blocking 'Exchange ActiveSync clients' and 'Other clients'.",
         gfix="Conditional Access > New policy from template > 'Block legacy authentication' > Report-only, then On."),

    # ---------------------------------------------------------------- Auditing
    dict(id="A-01", cat="Auditing", check="Unified audit log on", sev="High",
         ps="Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled",
         secure="True", risk="No audit trail for investigations.",
         fix="Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true",
         console="Microsoft Purview portal", view="Solutions > Audit",
         gfix="If a banner shows 'Start recording user and admin activity', select it. No banner = already on."),
    dict(id="A-02", cat="Auditing", check="Mailbox auditing on by default", sev="High",
         ps="Get-OrganizationConfig | Format-List AuditDisabled",
         secure="False", risk="Mailbox access (including by attackers) is not recorded.",
         fix="Set-OrganizationConfig -AuditDisabled $false",
         console="-", view=NO_GUI, gfix=NO_GUI),
    dict(id="A-03", cat="Auditing", check="Accounts that bypass mailbox auditing", sev="Medium",
         ps="Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object AuditBypassEnabled | Select-Object Name",
         secure="None (or documented backup/service accounts)", risk="Actions by these accounts are invisible.",
         fix="Set-MailboxAuditBypassAssociation -Identity <account> -AuditBypassEnabled $false",
         console="-", view=NO_GUI, gfix=NO_GUI),
    dict(id="A-04", cat="Auditing", check="Mailboxes using default audit actions", sev="Low",
         ps="Get-EXOMailbox -ResultSize Unlimited -Properties AuditEnabled,DefaultAuditSet |\n  Where-Object { -not $_.AuditEnabled -or $_.DefaultAuditSet.Count -lt 3 } |\n  Select-Object UserPrincipalName,AuditEnabled,DefaultAuditSet",
         secure="No rows (AuditEnabled True; DefaultAuditSet = Admin, Delegate, Owner)",
         risk="Customised audit sets may omit actions such as MailItemsAccessed.",
         fix="Set-Mailbox <user> -DefaultAuditSet Admin,Delegate,Owner",
         console="-", view=NO_GUI, gfix=NO_GUI),
    dict(id="A-05", cat="Auditing", check="Alert policies for forwarding and suspicious mail activity", sev="Medium",
         ps="# In Connect-IPPSSession\nGet-ProtectionAlert | Where-Object { $_.Name -match 'forward|redirect|suspicious' } | Format-Table Name,Disabled,NotifyUser",
         secure="Enabled (Disabled = False) and NotifyUser set to a monitored mailbox",
         risk="Forwarding set up by an attacker goes unnoticed.",
         fix="Set-ProtectionAlert -Identity '<name>' -NotifyUser secops@yourdomain.com",
         console="Microsoft Defender portal",
         view="Email & collaboration > Policies & rules > Alert policy",
         gfix="Open 'Suspicious email forwarding activity' and 'Creation of forwarding/redirect rule' > ensure On > Edit policy > set email recipients."),

    # ---------------------------------------------------------------- Forwarding / exfiltration
    dict(id="F-01", cat="Forwarding", check="Automatic external forwarding (outbound spam policy)", sev="High",
         ps="Get-HostedOutboundSpamFilterPolicy | Format-Table Name,AutoForwardingMode",
         secure="Off or Automatic (Automatic = Off)", risk="Users or attackers can auto-forward all mail to outside addresses.",
         fix="Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off",
         console="Microsoft Defender portal",
         view="Email & collaboration > Policies & rules > Threat policies > Anti-spam > 'Anti-spam outbound policy (Default)'",
         gfix="Edit protection settings > Forwarding rules > Automatic forwarding rules = 'Off - Forwarding is disabled' > Save. Create a separate custom policy for approved exceptions."),
    dict(id="F-02", cat="Forwarding", check="Default remote domain allows auto-forward", sev="Low",
         ps="Get-RemoteDomain Default | Format-List AutoForwardEnabled,AutoReplyEnabled",
         secure="AutoForwardEnabled False (defence in depth)", risk="Second layer of forwarding control missing.",
         fix="Set-RemoteDomain Default -AutoForwardEnabled $false",
         console="Exchange admin center", view="Mail flow > Remote domains > Default",
         gfix="Edit reply types > untick 'Allow automatic forwarding' > Save."),
    dict(id="F-03", cat="Forwarding", check="Mailboxes with forwarding set", sev="High",
         ps="Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward |\n  Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |\n  Select-Object UserPrincipalName,ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward",
         secure="No external addresses (or documented and approved)", risk="Silent data exfiltration; common after account compromise.",
         fix="Set-Mailbox <user> -ForwardingSmtpAddress $null -ForwardingAddress $null",
         console="Exchange admin center",
         view="Reports > Mail flow > Auto forwarded messages report (who forwards where); per user: Recipients > Mailboxes > user > Mailbox > Email forwarding",
         gfix="Recipients > Mailboxes > user > Mailbox > Manage email forwarding > turn forwarding Off > Save. (Also: Microsoft 365 admin center > Active users > user > Mail > Email forwarding.)"),
    dict(id="F-04", cat="Forwarding", check="Inbox rules that forward, redirect or delete", sev="High",
         ps="Get-EXOMailbox -ResultSize Unlimited | ForEach-Object {\n  Get-InboxRule -Mailbox $_.UserPrincipalName |\n  Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo -or $_.DeleteMessage } |\n  Select-Object MailboxOwnerId,Name,Enabled,ForwardTo,RedirectTo,DeleteMessage }",
         secure="No rules forwarding outside the organisation", risk="Classic business-email-compromise persistence.",
         fix="Remove-InboxRule -Mailbox <user> -Identity '<rule name>'",
         console="Microsoft Purview portal / Outlook on the web",
         view="Purview: Solutions > Audit > New search > Activities: 'New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules'. Admins cannot list inbox rules in a console.",
         gfix="With the user (or delegated access): Outlook on the web > Settings > Mail > Rules > delete the rule. Treat as a compromised account (sign out sessions, reset password)."),
    dict(id="F-05", cat="Forwarding", check="Mail flow rules that copy, redirect or bypass spam filtering", sev="High",
         ps="Get-TransportRule | Format-List Name,State,Mode,Priority,SetSCL,SenderDomainIs,RedirectMessageTo,BlindCopyTo,AddToRecipients,CopyTo,RouteMessageOutboundConnector",
         secure="No external BCC/redirect; no SetSCL -1 based only on sender domain", risk="Exfiltration or spam/phish bypass via spoofable conditions.",
         fix="Disable-TransportRule '<name>' or Set-TransportRule '<name>' to add SenderIpRanges / remove action",
         console="Exchange admin center", view="Mail flow > Rules: open each rule and read its conditions and actions",
         gfix="Select the rule > Disable (or Edit rule conditions / actions) > Save."),
    dict(id="F-06", cat="Forwarding", check="Journal rules and undeliverable-journal mailbox", sev="Medium",
         ps="Get-JournalRule | Format-Table Name,Enabled,Scope,JournalEmailAddress\nGet-TransportConfig | Format-List JournalingReportNdrTo",
         secure="Every journal destination is expected; JournalingReportNdrTo (alternate journaling mailbox) is set - it must be an on-premises or third-party address, not an Exchange Online mailbox",
         risk="Journal copies of all mail sent to an unknown address; lost journal reports.",
         fix="Remove-JournalRule '<name>'; Set-TransportConfig -JournalingReportNdrTo <external or on-premises address>",
         console="Microsoft Purview portal",
         view="Solutions > Data lifecycle management > Exchange (legacy) > Journal rules",
         gfix="Select unknown rules > Delete (or Disable). Set the address for undeliverable journal reports on the same page (Exchange Online mailboxes are not supported)."),
    dict(id="F-07", cat="Forwarding", check="External calendar sharing policy", sev="Low",
         ps="Get-SharingPolicy | Format-List Name,Default,Enabled,Domains",
         secure="Free/busy only (CalendarSharingFreeBusySimple) or disabled for '*'",
         risk="Users share full calendar details with anyone.",
         fix="Set-SharingPolicy 'Default Sharing Policy' -Domains '*:CalendarSharingFreeBusySimple'",
         console="Exchange admin center", view="Organization > Sharing > Individual sharing",
         gfix="Edit the default policy > Sharing with all domains = 'Calendar free/busy information with time only' > Save."),

    # ---------------------------------------------------------------- Connectors
    dict(id="CN-01", cat="Connectors", check="Inbound connectors restricted by IP or certificate and requiring TLS", sev="High",
         ps="Get-InboundConnector | Format-List Name,Enabled,ConnectorType,SenderDomains,SenderIPAddresses,RestrictDomainsToIPAddresses,RestrictDomainsToCertificate,RequireTls,TlsSenderCertificateName",
         secure="Partner connectors: RestrictDomainsToIPAddresses or RestrictDomainsToCertificate True; RequireTls True",
         risk="Anyone spoofing the partner domain matches the connector.",
         fix="Set-InboundConnector '<name>' -RestrictDomainsToIPAddresses $true -RequireTls $true",
         console="Exchange admin center", view="Mail flow > Connectors > select each 'From' connector",
         gfix="Edit 'How to identify your partner organization' > choose 'By verifying that the IP address...' or certificate; Security restrictions > Reject email messages if they aren't sent over TLS > Save."),
    dict(id="CN-02", cat="Connectors", check="Outbound connectors validate TLS and are validated", sev="Medium",
         ps="Get-OutboundConnector | Format-List Name,Enabled,ConnectorType,RecipientDomains,SmartHosts,TlsSettings,TlsDomain,IsValidated,LastValidationTimestamp",
         secure="TlsSettings CertificateValidation or DomainValidation; IsValidated True",
         risk="Mail to partners sent unencrypted or to an impersonating host.",
         fix="Set-OutboundConnector '<name>' -TlsSettings DomainValidation -TlsDomain <host>; Validate-OutboundConnector",
         console="Exchange admin center", view="Mail flow > Connectors > select each 'To' connector",
         gfix="Edit security restrictions > 'Always use TLS' and 'Issued by a trusted CA' (+ domain name) > then 'Validate connector' with a test address > Save."),
    dict(id="CN-03", cat="Connectors", check="Enhanced Filtering when MX points to a third-party gateway", sev="Medium",
         ps="Get-InboundConnector | Format-List Name,EFSkipLastIP,EFSkipIPs,EFTestMode",
         secure="Configured if MX is not *.mail.protection.outlook.com; not needed otherwise",
         risk="SPF/DMARC and IP reputation evaluate the gateway, not the real sender.",
         fix="Set-InboundConnector '<name>' -EFSkipLastIP $true",
         console="Microsoft Defender portal", view="Email & collaboration > Policies & rules > Threat policies > Enhanced filtering",
         gfix="Select the connector > Automatically detect and skip the last IP address > apply to all users > Save."),
    dict(id="CN-04", cat="Connectors", check="Accepted domains", sev="Low",
         ps="Get-AcceptedDomain | Format-Table DomainName,DomainType,Default",
         secure="Only domains you own; Authoritative unless a hybrid/relay need exists",
         risk="InternalRelay domains bypass recipient validation (DBEB).",
         fix="Set-AcceptedDomain <domain> -DomainType Authoritative",
         console="Exchange admin center", view="Mail flow > Accepted domains",
         gfix="Select domain > change to 'Authoritative' > Save. Remove unused domains in Microsoft 365 admin center > Settings > Domains."),
    dict(id="CN-05", cat="Connectors", check="Hybrid and organisation relationships", sev="Low",
         ps="Get-OnPremisesOrganization | Format-List\nGet-OrganizationRelationship | Format-List Name,Enabled,DomainNames,FreeBusyAccessLevel\nGet-IntraOrganizationConnector | Format-List",
         secure="Only expected relationships; nothing left from decommissioned hybrid",
         risk="Stale relationships share free/busy or allow moves to old endpoints.",
         fix="Remove-OrganizationRelationship / Set-OrganizationRelationship -Enabled $false",
         console="Exchange admin center", view="Organization > Sharing > Organization sharing",
         gfix="Disable or delete unknown relationships. Hybrid objects (on-premises organisation, IOC) are managed by the Hybrid Configuration Wizard."),

    # ---------------------------------------------------------------- Email authentication
    dict(id="EA-01", cat="Email authentication", check="DKIM signing for every custom domain", sev="High",
         ps="Get-DkimSigningConfig | Format-Table Domain,Enabled,Status,Selector1KeySize,Selector2KeySize",
         secure="Enabled True for every custom domain; key size 2048",
         risk="Mail is signed as onmicrosoft.com; DMARC relies on SPF only and breaks on forwarding.",
         fix="New-DkimSigningConfig -DomainName <domain> -Enabled $false; publish CNAMEs; Set-DkimSigningConfig <domain> -Enabled $true",
         console="Microsoft Defender portal",
         view="Email & collaboration > Policies & rules > Threat policies > Email authentication settings > DKIM tab",
         gfix="Select the domain > publish the two CNAME records shown > toggle 'Sign messages for this domain with DKIM signatures' to Enabled."),
    dict(id="EA-02", cat="Email authentication", check="SPF and DMARC DNS records", sev="High",
         ps="Resolve-DnsName <domain> -Type TXT | Where-Object Strings -match 'v=spf1'\nResolve-DnsName _dmarc.<domain> -Type TXT\n# Windows only; on macOS/Linux use: dig TXT <domain>",
         secure="One SPF record including spf.protection.outlook.com ending -all; DMARC p=quarantine or p=reject with rua",
         risk="Your domain can be spoofed; recipients reject or junk your mail.",
         fix="Edit the TXT records at your DNS host",
         console="Microsoft 365 admin center",
         view="Settings > Domains > select domain > DNS records (shows MX/SPF status). DMARC is not shown: check at your DNS host.",
         gfix="Update the TXT records at your DNS host (registrar). Start DMARC at p=none, then quarantine, then reject."),
    dict(id="EA-03", cat="Email authentication", check="Trusted ARC sealers (third-party filters / mailing lists)", sev="Low",
         ps="Get-ArcConfig | Format-List ArcTrustedSealers",
         secure="Only services that actually modify your inbound mail", risk="Legitimate forwarded mail fails authentication.",
         fix="Set-ArcConfig -Identity Default -ArcTrustedSealers <domain>",
         console="Microsoft Defender portal", view="Threat policies > Email authentication settings > ARC tab",
         gfix="Add trusted ARC sealer > enter the sealing domain > Save."),
    dict(id="EA-04", cat="Email authentication", check="Inbound SMTP DANE with DNSSEC", sev="Low",
         ps="Get-SmtpDaneInboundStatus -DomainName <domain>",
         secure="Enabled (optional hardening)", risk="Senders can be downgraded to unencrypted delivery.",
         fix="Enable-DnssecForVerifiedDomain -DomainName <domain>; Enable-SmtpDaneInbound -DomainName <domain>",
         console="-", view=NO_GUI, gfix=NO_GUI),

    # ---------------------------------------------------------------- Threat protection (EOP / Defender)
    dict(id="T-01", cat="Threat protection", check="Anti-spam inbound policy actions and allow lists", sev="High",
         ps="Get-HostedContentFilterPolicy | Format-List Name,BulkThreshold,SpamAction,HighConfidenceSpamAction,PhishSpamAction,HighConfidencePhishAction,AllowedSenderDomains,AllowedSenders,QuarantineRetentionPeriod",
         secure="HighConfidencePhish/Phish = Quarantine; BulkThreshold 6 or lower; AllowedSenderDomains empty",
         risk="Phish reaches inboxes; allowed domains are trivially spoofed.",
         fix="Set-HostedContentFilterPolicy Default -PhishSpamAction Quarantine -HighConfidencePhishAction Quarantine -AllowedSenderDomains $null",
         console="Microsoft Defender portal", view="Threat policies > Anti-spam > 'Anti-spam inbound policy (Default)' and custom policies",
         gfix="Edit actions: Phishing and High confidence phishing = Quarantine message; Edit allowed and blocked senders and domains > remove allowed domains > Save."),
    dict(id="T-02", cat="Threat protection", check="Connection filter IP allow list", sev="Medium",
         ps="Get-HostedConnectionFilterPolicy | Format-List IPAllowList,IPBlockList,EnableSafeList",
         secure="IPAllowList empty or only IPs you control; EnableSafeList False",
         risk="All mail from those IPs skips spam filtering.",
         fix="Set-HostedConnectionFilterPolicy Default -IPAllowList @{} -EnableSafeList $false",
         console="Microsoft Defender portal", view="Threat policies > Anti-spam > 'Connection filter policy (Default)'",
         gfix="Edit connection filter policy > remove IPs from 'Always allow messages from the following IP addresses'; untick 'Turn on safe list' > Save."),
    dict(id="T-03", cat="Threat protection", check="Outbound spam limits and actions", sev="Medium",
         ps="Get-HostedOutboundSpamFilterPolicy | Format-List Name,RecipientLimitExternalPerHour,RecipientLimitInternalPerHour,RecipientLimitPerDay,ActionWhenThresholdReached,NotifyOutboundSpamRecipients",
         secure="ActionWhenThresholdReached BlockUser; notifications to a monitored mailbox",
         risk="A compromised account keeps sending spam and damages your sending reputation.",
         fix="Set-HostedOutboundSpamFilterPolicy Default -ActionWhenThresholdReached BlockUser",
         console="Microsoft Defender portal", view="Threat policies > Anti-spam > 'Anti-spam outbound policy (Default)'",
         gfix="Edit protection settings > set message limits > 'Restriction placed on users who reach the message limit' = Restrict the user from sending mail > add notification recipients > Save."),
    dict(id="T-04", cat="Threat protection", check="Anti-malware policy", sev="Medium",
         ps="Get-MalwareFilterPolicy | Format-List Name,EnableFileFilter,FileTypeAction,ZapEnabled,QuarantineTag",
         secure="EnableFileFilter True; ZapEnabled True; QuarantineTag AdminOnlyAccessPolicy",
         risk="Dangerous file types delivered; malware not removed after delivery.",
         fix="Set-MalwareFilterPolicy Default -EnableFileFilter $true -ZapEnabled $true",
         console="Microsoft Defender portal", view="Threat policies > Anti-malware > Default (and custom) policy",
         gfix="Edit protection settings > tick 'Enable the common attachments filter' and 'Enable zero-hour auto purge for malware' > Save."),
    dict(id="T-05", cat="Threat protection", check="Anti-phishing policy", sev="High",
         ps="Get-AntiPhishPolicy | Format-List Name,EnableSpoofIntelligence,HonorDmarcPolicy,EnableFirstContactSafetyTips,EnableUnauthenticatedSender,PhishThresholdLevel,EnableTargetedUserProtection,EnableOrganizationDomainsProtection,EnableMailboxIntelligenceProtection",
         secure="Spoof intelligence, Honor DMARC, first contact tip True; (Defender) threshold 3+, impersonation protection on",
         risk="Spoofed and impersonation phish delivered.",
         fix="Set-AntiPhishPolicy '<name>' -EnableSpoofIntelligence $true -HonorDmarcPolicy $true -EnableFirstContactSafetyTips $true",
         console="Microsoft Defender portal", view="Threat policies > Anti-phishing > 'Office365 AntiPhish Default' (and custom)",
         gfix="Edit protection settings: Phishing email threshold = 3 - More aggressive; enable user/domain impersonation and mailbox intelligence; enable spoof intelligence, Honor DMARC; Edit actions: show first contact safety tip > Save."),
    dict(id="T-06", cat="Threat protection", check="Safe Links (Defender for Office 365)", sev="Medium",
         ps="Get-SafeLinksPolicy | Format-List Name,EnableSafeLinksForEmail,EnableSafeLinksForTeams,EnableSafeLinksForOffice,ScanUrls,DeliverMessageAfterScan,EnableForInternalSenders,AllowClickThrough\nGet-SafeLinksRule | Format-Table Name,State,Priority",
         secure="Enabled for email, Teams, Office; DeliverMessageAfterScan True; AllowClickThrough False",
         risk="Malicious links reach users unchecked.",
         fix="Set-SafeLinksPolicy '<name>' -DeliverMessageAfterScan $true -AllowClickThrough $false",
         console="Microsoft Defender portal", view="Threat policies > Safe Links",
         gfix="Create or edit a policy for all users: URL & click protection settings = On for email, Teams, Office apps; 'Wait for URL scanning to complete' on; 'Let users click through' off > Submit."),
    dict(id="T-07", cat="Threat protection", check="Safe Attachments and SharePoint/OneDrive/Teams protection", sev="Medium",
         ps="Get-SafeAttachmentPolicy | Format-List Name,Enable,Action,QuarantineTag\nGet-AtpPolicyForO365 | Format-List EnableATPForSPOTeamsODB,EnableSafeDocs,AllowSafeDocsOpen",
         secure="Action Block (or DynamicDelivery); EnableATPForSPOTeamsODB True; AllowSafeDocsOpen False",
         risk="Zero-day malware attachments delivered or shared in files.",
         fix="Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true -EnableSafeDocs $true -AllowSafeDocsOpen $false",
         console="Microsoft Defender portal", view="Threat policies > Safe Attachments (and 'Global settings' at the top of that page)",
         gfix="Create/edit a policy for all users with response = Block; Global settings > turn on Defender for Office 365 for SharePoint, OneDrive and Teams, and Safe Documents; do not allow click through > Save."),
    dict(id="T-08", cat="Threat protection", check="Preset security policies (Standard / Strict)", sev="Medium",
         ps="Get-EOPProtectionPolicyRule | Format-Table Identity,State\nGet-ATPProtectionPolicyRule | Format-Table Identity,State",
         secure="Standard (or Strict) preset applied to all users",
         risk="Custom policies drift from Microsoft's recommended settings.",
         fix="Easier in the portal (see GUI sheet)",
         console="Microsoft Defender portal", view="Threat policies > Preset security policies",
         gfix="Standard protection > Manage protection settings > apply to All recipients > Confirm. Then Threat policies > Configuration analyzer to review custom policies."),
    dict(id="T-09", cat="Threat protection", check="Tenant Allow/Block List hygiene", sev="Medium",
         ps="Get-TenantAllowBlockListItems -ListType Sender -Allow | Format-Table Value,ExpirationDate,LastUsedDate\nGet-TenantAllowBlockListItems -ListType Url -Allow\nGet-TenantAllowBlockListSpoofItems | Format-Table SpoofedUser,SendingInfrastructure,Action",
         secure="Allow entries have an expiry date and are still used; spoof allows are known partners",
         risk="Permanent allows bypass filtering for senders that may now be malicious.",
         fix="Remove-TenantAllowBlockListItems -ListType Sender -Ids <id>",
         console="Microsoft Defender portal", view="Threat policies > Tenant Allow/Block Lists (Domains & addresses, Spoofed senders, URLs, Files tabs)",
         gfix="Select stale allow entries > Delete, or Edit > set 'Remove allow entry after' a date."),
    dict(id="T-10", cat="Threat protection", check="Quarantine policies and released messages", sev="Medium",
         ps="Get-QuarantinePolicy | Format-Table Name,EndUserQuarantinePermissionsValue,ESNEnabled\nGet-QuarantineMessage -ReleaseStatus Released -StartReceivedDate (Get-Date).AddDays(-30) | Format-Table ReceivedTime,SenderAddress,QuarantineTypes",
         secure="Malware/high-confidence phish use AdminOnlyAccessPolicy; no released malware",
         risk="Users release malware or phishing themselves.",
         fix="Set-MalwareFilterPolicy / Set-HostedContentFilterPolicy -HighConfidencePhishQuarantineTag AdminOnlyAccessPolicy",
         console="Microsoft Defender portal", view="Threat policies > Quarantine policies; and Email & collaboration > Review > Quarantine (filter Release status = Released)",
         gfix="In anti-malware and anti-spam policies set the quarantine policy for malware and high-confidence phish to AdminOnlyAccessPolicy > Save."),
    dict(id="T-11", cat="Threat protection", check="Restricted users (blocked for sending spam)", sev="High",
         ps="Get-BlockedSenderAddress",
         secure="No results", risk="An account is compromised and sending spam.",
         fix="After securing the account: Remove-BlockedSenderAddress -SenderAddress <user>",
         console="Microsoft Defender portal", view="Email & collaboration > Review > Restricted entities",
         gfix="Secure the account first (reset password, sign out sessions, remove forwarding/rules), then select the user > Unblock."),
    dict(id="T-12", cat="Threat protection", check="Advanced delivery (phishing simulation / SecOps mailbox)", sev="Low",
         ps="Get-ExoPhishSimOverrideRule | Format-List\nGet-SecOpsOverridePolicy | Format-List",
         secure="Only your real simulation vendor and SecOps mailbox listed",
         risk="Unknown entries let mail skip filtering.",
         fix="Remove-ExoPhishSimOverrideRule / Remove-SecOpsOverridePolicy",
         console="Microsoft Defender portal", view="Threat policies > Advanced delivery (SecOps mailbox and Phishing simulation tabs)",
         gfix="Edit > remove unknown domains, IPs or mailboxes > Save."),
    dict(id="T-13", cat="Threat protection", check="User-reported message settings", sev="Low",
         ps="Get-ReportSubmissionPolicy | Format-List EnableReportToMicrosoft,ReportJunkToCustomizedAddress,ReportPhishToCustomizedAddress,ReportJunkAddresses",
         secure="Report button on; reports go to Microsoft and/or a monitored mailbox",
         risk="Users cannot report phishing easily.",
         fix="Set-ReportSubmissionPolicy -EnableReportToMicrosoft $true",
         console="Microsoft Defender portal", view="Settings > Email & collaboration > User reported settings",
         gfix="Turn on 'Monitor reported messages in Outlook' > use the built-in Report button > choose destination > Save."),
    dict(id="T-14", cat="Threat protection", check="External sender tag in Outlook", sev="Low",
         ps="Get-ExternalInOutlook | Format-List Enabled,AllowList",
         secure="Enabled True", risk="Users cannot see mail is from outside.",
         fix="Set-ExternalInOutlook -Enabled $true",
         console="-", view=NO_GUI, gfix=NO_GUI),
    dict(id="T-15", cat="Threat protection", check="External recipient MailTips", sev="Low",
         ps="Get-OrganizationConfig | Format-List MailTipsAllTipsEnabled,MailTipsExternalRecipientsTipsEnabled",
         secure="True", risk="Users are not warned when emailing outsiders.",
         fix="Set-OrganizationConfig -MailTipsExternalRecipientsTipsEnabled $true",
         console="-", view=NO_GUI, gfix=NO_GUI),

    # ---------------------------------------------------------------- Admin and access
    dict(id="R-01", cat="Admin & access", check="Exchange Organization Management members", sev="High",
         ps="Get-RoleGroupMember 'Organization Management' | Format-Table Name,RecipientType",
         secure="Few named admins (5 or fewer); no shared accounts",
         risk="Too many standing full Exchange admins.",
         fix="Remove-RoleGroupMember 'Organization Management' -Member <user>",
         console="Exchange admin center", view="Roles > Admin roles > Organization Management > Assigned tab",
         gfix="Select members > Remove; grant narrower role groups instead. Also check Entra admin center > Roles & admins > Exchange Administrator / Global Administrator."),
    dict(id="R-02", cat="Admin & access", check="Applications with Exchange access", sev="Medium",
         ps="Get-ManagementRoleAssignment -RoleAssigneeType ServicePrincipal | Format-Table Name,Role,RoleAssignee,CustomResourceScope\nGet-ApplicationAccessPolicy | Format-Table AppId,ScopeName,AccessRight",
         secure="Only known apps, each limited by a management scope",
         risk="An app can read or send as any mailbox.",
         fix="Remove-ManagementRoleAssignment <name>; scope with New-ManagementScope",
         console="Microsoft Entra admin center",
         view="Enterprise apps > All applications > each app > Permissions (look for Mail.*, full_access_as_app, Exchange.ManageAsApp). Exchange RBAC for Applications has no console view.",
         gfix="Remove unknown apps (Properties > Delete) or revoke consent; app scoping (RBAC for Applications) is PowerShell only."),
    dict(id="R-03", cat="Admin & access", check="Mailbox delegation (FullAccess, SendAs)", sev="Medium",
         ps="Get-EXOMailbox -ResultSize Unlimited | Get-EXOMailboxPermission |\n  Where-Object { $_.User -notlike 'NT AUTHORITY*' -and -not $_.IsInherited } | Format-Table Identity,User,AccessRights\nGet-EXORecipientPermission -ResultSize Unlimited | Where-Object Trustee -notlike 'NT AUTHORITY*' | Format-Table Identity,Trustee,AccessRights",
         secure="Only expected delegates (assistants, shared mailboxes)",
         risk="Hidden access to sensitive mailboxes.",
         fix="Remove-MailboxPermission <mailbox> -User <user> -AccessRights FullAccess",
         console="Exchange admin center", view="Recipients > Mailboxes > select mailbox > Delegation (or Microsoft 365 admin center > Active users > user > Mail > Mailbox permissions). Per mailbox only.",
         gfix="Under Read and manage (Full Access) / Send as / Send on behalf select Edit > remove the delegate > Save."),
    dict(id="R-04", cat="Admin & access", check="Mobile devices and ActiveSync default access", sev="Medium",
         ps="Get-ActiveSyncOrganizationSettings | Format-List DefaultAccessLevel\nGet-MobileDevice -ResultSize Unlimited | Format-Table UserDisplayName,DeviceOS,DeviceModel,ClientType,FirstSyncTime",
         secure="DefaultAccessLevel Quarantine or Block with Outlook allowed; no unknown devices",
         risk="Any phone mail app syncs corporate mail outside app protection.",
         fix="Set-ActiveSyncOrganizationSettings -DefaultAccessLevel Quarantine",
         console="Exchange admin center", view="Mobile > Device access; Microsoft 365 admin center > Reports > Usage > Exchange > Email apps usage",
         gfix="Device access > Edit > 'When a device that's not managed by a rule connects' = Quarantine > add a rule allowing Outlook > Save. Prefer Conditional Access blocking ActiveSync clients."),
    dict(id="R-05", cat="Admin & access", check="Outlook on the web: third-party storage and unmanaged-device downloads", sev="Low",
         ps="Get-OwaMailboxPolicy | Format-List Name,AdditionalStorageProvidersAvailable,ConditionalAccessPolicy",
         secure="AdditionalStorageProvidersAvailable False; ConditionalAccessPolicy ReadOnly if BYOD is allowed",
         risk="Attachments saved to personal Dropbox/Google Drive or downloaded on personal PCs.",
         fix="Set-OwaMailboxPolicy OwaMailboxPolicy-Default -AdditionalStorageProvidersAvailable $false -ConditionalAccessPolicy ReadOnly",
         console="-", view=NO_GUI, gfix=NO_GUI + " Alternative: Defender portal > Cloud apps session policy blocking downloads."),
    dict(id="R-06", cat="Admin & access", check="Customer Lockbox (Microsoft engineer access approval)", sev="Low",
         ps="Get-OrganizationConfig | Format-List CustomerLockBoxEnabled",
         secure="True (requires E5 or Customer Lockbox add-on)", risk="Microsoft support access to content without your approval.",
         fix="Set-OrganizationConfig -CustomerLockBoxEnabled $true",
         console="Microsoft 365 admin center", view="Settings > Org settings > Security & privacy > Customer lockbox",
         gfix="Tick 'Require approval for all data access requests' > Save."),
]

PS_COLS = ["ID", "Category", "Check", "Severity", "PowerShell check command", "Secure / expected result",
           "Risk if not met", "PowerShell remediation", "Current value (fill in)", "Result"]
GUI_COLS = ["ID", "Category", "Check", "Severity", "Admin console", "Where to view (click path)",
            "Secure / expected result", "How to resolve in the console", "Result"]

README = [
    ("Exchange Online security checks - PowerShell and admin console", ""),
    ("", ""),
    ("What this is", "Every Exchange Online security setting worth checking, written twice: as PowerShell commands ('PowerShell Checks' sheet) and as click paths in the web admin consoles ('Admin Console (GUI)' sheet). Rows share the same ID across both sheets."),
    ("Read-only checks", "Every command in the 'PowerShell check command' column only reads settings (Get-*). The 'PowerShell remediation' column changes settings - review before running."),
    ("Connect first", "Run C-01 to C-03, then work down the list. Use a Global Reader + Security Reader account for checks; an admin account only for fixes."),
    ("Fill in", "Yellow columns are for you: 'Current value' (paste what the command returned) and 'Result' (Pass / Fail / N/A from the drop-down)."),
    ("Example", "AU-02 > Current value: SmtpClientAuthenticationDisabled : False > Result: Fail"),
    ("No GUI equivalent", "Some settings exist only in PowerShell; the GUI sheet says so in grey rather than inventing a path."),
    ("Export results", "Append  | Export-Csv .\\<ID>.csv -NoTypeInformation  to any check command to save its output, e.g. Get-TransportRule | Select-Object * | Export-Csv .\\F-05.csv -NoTypeInformation. The repository script scripts\\Invoke-ExoTenantHealthCheck.ps1 runs most of these checks automatically and writes CSV + HTML."),
    ("Licensing", "T-06, T-07, T-12 and impersonation settings in T-05 need Defender for Office 365 (Business Premium / E5 / add-on). R-06 needs E5 or the Customer Lockbox add-on."),
    ("Accuracy", "Cmdlets: ExchangeOnlineManagement 3.x. Console paths current as of October 2026; Microsoft moves menus regularly - use the search box at the top of each console if a path has changed."),
    ("Consoles", "Microsoft 365 admin center https://admin.microsoft.com | Exchange admin center https://admin.exchange.microsoft.com | Defender portal https://security.microsoft.com | Purview portal https://purview.microsoft.com | Entra admin center https://entra.microsoft.com"),
]

SEV_FILL = {"High": ("C00000", "FFFFFF"), "Medium": ("FFE699", "000000"), "Low": ("C6E0B4", "000000"), "-": ("D9D9D9", "000000")}


def build():
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.worksheet.datavalidation import DataValidation

    thin = Side(style="thin", color="BFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    wrap = Alignment(wrap_text=True, vertical="top")
    yellow = PatternFill("solid", fgColor="FFFF00")

    wb = Workbook()
    rd = wb.active
    rd.title = "Read Me"
    for a, b in README:
        rd.append([a, b])
    rd["A1"].font = Font(name="Arial", size=14, bold=True)
    for row in rd.iter_rows(min_row=2):
        row[0].font = Font(name="Arial", size=10, bold=True)
        row[1].font = Font(name="Arial", size=10)
        row[0].alignment = wrap
        row[1].alignment = wrap
    rd.column_dimensions["A"].width = 20
    rd.column_dimensions["B"].width = 120

    def sheet(title, cols, widths, values, mono_col=None, fill_cols=(), grey_when_no_gui=()):
        ws = wb.create_sheet(title)
        ws.append(cols)
        for cell in ws[1]:
            cell.font = Font(name="Arial", size=10, bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor="1F3864")
            cell.alignment = Alignment(wrap_text=True, vertical="center")
            cell.border = border
        for c in CHECKS:
            ws.append(values(c))
            r = ws.max_row
            for cell in ws[r]:
                cell.font = Font(name="Arial", size=10)
                cell.alignment = wrap
                cell.border = border
            sev = ws.cell(row=r, column=4)
            bg, fg = SEV_FILL[sev.value]
            sev.fill = PatternFill("solid", fgColor=bg)
            sev.font = Font(name="Arial", size=10, bold=True, color=fg)
            if mono_col:
                for mc in mono_col:
                    ws.cell(row=r, column=mc).font = Font(name="Consolas", size=9)
            for fc in fill_cols:
                ws.cell(row=r, column=fc).fill = yellow
            for gc in grey_when_no_gui:
                cell = ws.cell(row=r, column=gc)
                if isinstance(cell.value, str) and cell.value.startswith("No admin-center setting"):
                    cell.font = Font(name="Arial", size=10, italic=True, color="7F7F7F")
        for i, w in enumerate(widths, start=1):
            ws.column_dimensions[ws.cell(row=1, column=i).column_letter].width = w
        ws.freeze_panes = "D2"
        ws.auto_filter.ref = ws.dimensions
        dv = DataValidation(type="list", formula1='"Pass,Fail,N/A"', allow_blank=True)
        ws.add_data_validation(dv)
        last_col = ws.cell(row=1, column=len(cols)).column_letter
        dv.add(f"{last_col}2:{last_col}{ws.max_row}")
        return ws

    sheet("PowerShell Checks", PS_COLS, [7, 15, 32, 9, 70, 38, 36, 52, 30, 9],
          lambda c: [c["id"], c["cat"], c["check"], c["sev"], c["ps"], c["secure"], c["risk"], c["fix"], "", ""],
          mono_col=(5, 8), fill_cols=(9, 10))
    sheet("Admin Console (GUI)", GUI_COLS, [7, 15, 32, 9, 22, 52, 38, 62, 9],
          lambda c: [c["id"], c["cat"], c["check"], c["sev"], c["console"], c["view"], c["secure"], c["gfix"], ""],
          fill_cols=(9,), grey_when_no_gui=(6, 8))

    wb.save(OUT)
    print(f"Wrote {OUT.name}: {len(CHECKS)} checks")


if __name__ == "__main__":
    build()
