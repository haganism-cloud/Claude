"""Builds the BYOD security remediation workbook for a cloud-only Microsoft 365 tenant.

Outputs (next to this script):
  BYOD-Security-Remediation.numbers   Apple Numbers
  BYOD-Security-Remediation.xlsx      Excel (also opens in Numbers)

Requires: openpyxl, numbers-parser   (pip install openpyxl numbers-parser)
"""

from pathlib import Path

HERE = Path(__file__).parent
NAME = "BYOD-Security-Remediation"

COLUMNS = [
    "Priority",
    "Criticality",
    "Area",
    "Issue",
    "BYOD impact and risk",
    "Remediation steps",
    "Where to configure",
    "Licence needed",
    "How to verify",
    "Effort",
    "Owner",
    "Status",
]

# Ordered by criticality. Licence notes: Business Premium includes Entra ID P1, Intune and
# Defender for Business; Entra ID P2 / Defender for Cloud Apps come with E5 or as add-ons.
ITEMS = [
    {
        "Criticality": "Critical",
        "Area": "Foundation",
        "Issue": "Licensing does not include the controls BYOD depends on",
        "BYOD impact and risk": (
            "Every meaningful BYOD control in Microsoft 365 needs Entra ID P1 (Conditional Access) and "
            "Intune (app protection / device compliance). Tenants on Business Basic/Standard or E1/E3 "
            "without EMS can only use Security Defaults, which enforces MFA but cannot tell a personal "
            "device from a managed one, restrict downloads or wipe corporate data. Without these licences "
            "personal devices get exactly the same access as company-managed ones, and nothing else in "
            "this list can be fully implemented."
        ),
        "Remediation steps": (
            "1. Inventory current licences: Microsoft 365 admin center > Billing > Your products.\n"
            "2. Move users who access company data from personal devices to Microsoft 365 Business Premium "
            "(up to 300 users) or E3 + EMS / E5.\n"
            "3. Decide whether you need Entra ID P2 (risk-based Conditional Access) and Defender for Cloud "
            "Apps (browser session control); both are in E5 or available as add-ons.\n"
            "4. Assign licences to all users before building the policies below; unlicensed users are not "
            "covered by Intune app protection."
        ),
        "Where to configure": "Microsoft 365 admin center > Billing; Users > Active users > Licenses",
        "Licence needed": "Business Premium, or E3 + EMS E3 / E5",
        "How to verify": "Get-MgSubscribedSku | Select SkuPartNumber, ConsumedUnits; confirm every active user has Entra ID P1 + Intune service plans.",
        "Effort": "Low",
    },
    {
        "Criticality": "Critical",
        "Area": "Identity",
        "Issue": "MFA not enforced for every user and legacy authentication still allowed",
        "BYOD impact and risk": (
            "Personal devices are outside IT's control, so the user's password is the only thing standing "
            "between an attacker and the mailbox. Passwords reused on personal sites or captured by malware "
            "on a home PC give full access to Exchange, SharePoint and Teams from anywhere. Legacy protocols "
            "(POP, IMAP, SMTP AUTH with Basic auth, older ActiveSync clients) cannot do MFA and are the main "
            "target of password-spray attacks."
        ),
        "Remediation steps": (
            "1. If you have no Conditional Access licence, turn on Security Defaults (Entra admin center > "
            "Identity > Overview > Properties).\n"
            "2. Otherwise create Conditional Access policies: 'Require MFA for all users' (all cloud apps) and "
            "'Block legacy authentication' (Client apps = Exchange ActiveSync clients + Other clients).\n"
            "3. Start in Report-only mode for 1-2 weeks, review the sign-in logs, then switch to On.\n"
            "4. Exclude two cloud-only break-glass admin accounts, protected by FIDO2 keys and monitored.\n"
            "5. Move users to phishing-resistant methods (passkeys in Microsoft Authenticator, FIDO2 keys, "
            "Windows Hello) and use Authentication strengths to require them for admins.\n"
            "6. Disable POP/IMAP/SMTP AUTH where not needed: Set-CASMailbox -PopEnabled $false "
            "-ImapEnabled $false -SmtpClientAuthenticationDisabled $true (or via CAS mailbox plans)."
        ),
        "Where to configure": "Entra admin center > Protection > Conditional Access; Authentication methods; Exchange Online PowerShell",
        "Licence needed": "Free (Security Defaults) / Entra ID P1 (Conditional Access)",
        "How to verify": "Entra sign-in logs filtered on 'Client app = legacy' show only failures; Authentication methods > User registration details shows 100% MFA-capable.",
        "Effort": "Medium",
    },
    {
        "Criticality": "Critical",
        "Area": "Access control",
        "Issue": "No Conditional Access rule distinguishes personal from managed devices",
        "BYOD impact and risk": (
            "Without device-aware Conditional Access, a personal laptop or phone receives full desktop-client "
            "access: Outlook can cache the whole mailbox, OneDrive can sync every file, and Teams can download "
            "attachments to unencrypted local storage. When the device is lost, sold, shared with family or "
            "infected, that data leaves the organisation with no way to recall it."
        ),
        "Remediation steps": (
            "1. Decide the BYOD model per platform. Recommended: iOS/Android = app protection without "
            "enrolment (MAM); Windows/macOS personal = browser-only or Edge with Windows MAM; full desktop "
            "apps only on Intune-compliant devices.\n"
            "2. Create a CA policy for iOS/Android: grant 'Require app protection policy' (the older "
            "'Require approved client app' control is being retired).\n"
            "3. Create a CA policy for Windows/macOS desktop clients: 'Require device to be marked as "
            "compliant' (Client apps = Mobile apps and desktop clients).\n"
            "4. Create a CA policy for browsers on unmanaged devices: Session > 'Use app enforced "
            "restrictions' (pairs with item 4 below).\n"
            "5. Block unsupported device platforms (e.g. Linux, unknown) unless there is a business need.\n"
            "6. Pilot with a test group in Report-only, then enforce."
        ),
        "Where to configure": "Entra admin center > Protection > Conditional Access",
        "Licence needed": "Entra ID P1 + Intune",
        "How to verify": "Use the Conditional Access 'What If' tool for a user on an unregistered iPhone and an unmanaged Windows PC; check sign-in logs show the expected grant control.",
        "Effort": "High",
    },
    {
        "Criticality": "Critical",
        "Area": "Data protection",
        "Issue": "Corporate data can be saved, synced or copied into personal apps and storage",
        "BYOD impact and risk": (
            "On a personal phone, a user can open an email attachment and save it to personal iCloud or "
            "Google Drive, paste customer data into a personal messaging app, or screenshot it. On a home PC, "
            "files download to an unencrypted disk that IT cannot wipe. This is the most common way data "
            "leaves organisations that allow BYOD, often unintentionally, and it creates breach-notification "
            "exposure under GDPR and similar laws."
        ),
        "Remediation steps": (
            "1. In Intune create App protection policies for iOS and Android targeting all users and core "
            "apps (Outlook, Teams, OneDrive, SharePoint, Word/Excel/PowerPoint, Edge). Start from the "
            "Microsoft 'Level 2 enhanced data protection' framework.\n"
            "2. Data settings: block backup to iCloud/Google, 'Send org data to other apps' = Policy managed "
            "apps, 'Save copies of org data' = Block (allow OneDrive/SharePoint only), restrict cut/copy/paste "
            "to policy-managed apps, encrypt org data, block screen capture (Android).\n"
            "3. Access settings: require app PIN or biometrics, re-check after 30 minutes of inactivity.\n"
            "4. SharePoint/OneDrive on unmanaged devices: Set-SPOTenant -ConditionalAccessPolicy "
            "AllowLimitedAccess (web view only, no download/print/sync).\n"
            "5. Outlook on the web on unmanaged devices: Set-OwaMailboxPolicy -Identity "
            "OwaMailboxPolicy-Default -ConditionalAccessPolicy ReadOnly (attachments viewable, not "
            "downloadable).\n"
            "6. Windows personal PCs: enable Intune 'Windows MAM' for Microsoft Edge so the browser is the "
            "protected container.\n"
            "7. Note: the OneDrive 'sync only on domain-joined PCs' setting needs on-premises AD and does not "
            "apply to a cloud-only tenant; use the compliant-device CA policy (item 3) to control sync."
        ),
        "Where to configure": "Intune admin center > Apps > App protection policies; SharePoint Online PowerShell; Exchange Online PowerShell",
        "Licence needed": "Intune + Entra ID P1",
        "How to verify": "On a test personal phone, try to 'Save to Files' an Outlook attachment and paste mail text into a personal app (both blocked); open SharePoint in a browser on an unmanaged PC (download button absent).",
        "Effort": "High",
    },
    {
        "Criticality": "Critical",
        "Area": "Identity",
        "Issue": "Session and token theft from personal devices (AiTM phishing, info-stealer malware)",
        "BYOD impact and risk": (
            "Home computers frequently lack EDR and run unvetted software. Info-stealer malware lifts browser "
            "cookies and refresh tokens, and adversary-in-the-middle phishing kits proxy the MFA prompt. Either "
            "way the attacker replays the session from their own machine, bypassing MFA entirely, and "
            "typically sets up inbox forwarding rules for business email compromise."
        ),
        "Remediation steps": (
            "1. Require phishing-resistant MFA (passkeys / FIDO2) where possible; it defeats AiTM proxies.\n"
            "2. For unmanaged devices set Session controls: Sign-in frequency (e.g. 8-12 hours) and "
            "'Persistent browser session' = Never persistent.\n"
            "3. Turn on Continuous Access Evaluation and, if you use named locations, strict location "
            "enforcement.\n"
            "4. Where supported, enable Token protection (CA session control) for Exchange/SharePoint/Teams "
            "on Windows; check current platform support before relying on it.\n"
            "5. With Entra ID P2, add risk-based policies: sign-in risk High/Medium = MFA, user risk High = "
            "secure password change.\n"
            "6. Prepare a response playbook: Revoke-MgUserSignInSession -UserId <user>, reset password, "
            "review inbox rules and forwarding (Get-InboxRule), and check audit logs."
        ),
        "Where to configure": "Entra admin center > Conditional Access; Entra ID Protection; Microsoft Graph PowerShell",
        "Licence needed": "Entra ID P1 (P2 for risk policies)",
        "How to verify": "Sign-in logs show sign-in frequency enforced for unmanaged devices; run the playbook against a test account and confirm sessions end within minutes.",
        "Effort": "Medium",
    },
    {
        "Criticality": "High",
        "Area": "Data protection",
        "Issue": "No way to remove corporate data from lost, stolen or leavers' personal devices",
        "BYOD impact and risk": (
            "When an employee leaves or loses a phone, cached mail, Teams chats and downloaded files remain on "
            "a device the organisation does not own. A full device wipe is usually unacceptable (or unlawful) "
            "on personal property, so without app-level wipe the data simply stays there indefinitely."
        ),
        "Remediation steps": (
            "1. Rely on app protection (item 4) so corporate data lives only inside managed apps.\n"
            "2. Set conditional launch 'Offline grace period' to wipe data after e.g. 90 days without "
            "check-in.\n"
            "3. Add to the leaver and lost-device process: Intune > Apps > App selective wipe; disable the "
            "account; Revoke-MgUserSignInSession.\n"
            "4. For native mail apps that are still allowed: Clear-MobileDevice -Identity <id> -AccountOnly "
            "(Exchange account-only wipe, leaves personal data).\n"
            "5. Tell users how to report a lost device within hours, not days."
        ),
        "Where to configure": "Intune admin center > Apps > App selective wipe; Exchange Online PowerShell; HR offboarding procedure",
        "Licence needed": "Intune",
        "How to verify": "Run a selective wipe against a test phone: corporate accounts and files disappear from Outlook/OneDrive/Teams, personal photos and apps remain.",
        "Effort": "Low",
    },
    {
        "Criticality": "High",
        "Area": "Device health",
        "Issue": "Out-of-date, jailbroken/rooted or malware-infected personal devices",
        "BYOD impact and risk": (
            "Personal devices often run old OS versions with known exploits, may be jailbroken or rooted "
            "(which defeats app sandboxing and app protection), or share a PC with family members who install "
            "anything. Such devices can leak data even inside managed apps."
        ),
        "Remediation steps": (
            "1. In app protection policies set Conditional launch: minimum OS version (block or wipe below "
            "it), jailbroken/rooted = Block access, Play Integrity verdict = Basic integrity and certified "
            "device (Android), minimum app versions.\n"
            "2. Optionally connect Microsoft Defender for Endpoint on iOS/Android and set 'Max allowed device "
            "threat level' in conditional launch.\n"
            "3. For personal devices you do enrol (iOS/iPadOS User Enrollment, Android Work Profile), create "
            "compliance policies with minimum OS, passcode and encryption requirements.\n"
            "4. Set Intune compliance 'Mark devices with no compliance policy assigned as' = Not compliant."
        ),
        "Where to configure": "Intune admin center > Apps > App protection policies > Conditional launch; Devices > Compliance",
        "Licence needed": "Intune (Defender for Endpoint optional)",
        "How to verify": "Intune > Apps > Monitor > App protection status shows no users on blocked OS versions; test with an old OS emulator or device.",
        "Effort": "Medium",
    },
    {
        "Criticality": "High",
        "Area": "Email",
        "Issue": "Native mail apps (iOS Mail, Samsung/Gmail) and ActiveSync bypass app protection",
        "BYOD impact and risk": (
            "Built-in mail apps use Exchange ActiveSync and cannot be governed by Intune app protection: "
            "attachments can be saved anywhere and mail is stored outside any managed container. Any "
            "ActiveSync client can connect by default."
        ),
        "Remediation steps": (
            "1. Standardise on Outlook for iOS/Android and communicate the change in advance.\n"
            "2. Conditional Access: block 'Exchange ActiveSync clients' (or require app protection, which "
            "native apps cannot satisfy).\n"
            "3. Defence in depth: Set-ActiveSyncOrganizationSettings -DefaultAccessLevel Quarantine and "
            "approve only Outlook via device access rules, or disable ActiveSync for users who do not need it "
            "(Set-CASMailbox -ActiveSyncEnabled $false).\n"
            "4. Review which devices already sync: Get-MobileDevice -ResultSize Unlimited | Group "
            "DeviceOS, ClientType."
        ),
        "Where to configure": "Entra admin center > Conditional Access; Exchange admin center > Mobile; Exchange Online PowerShell",
        "Licence needed": "Entra ID P1 (Exchange controls are included with Exchange Online)",
        "How to verify": "Adding the work account to iOS Mail fails; Get-MobileDevice shows only Outlook (ClientType REST/Outlook) after cleanup.",
        "Effort": "Low",
    },
    {
        "Criticality": "High",
        "Area": "Data protection",
        "Issue": "Unmanaged browsers and desktop apps on personal Windows and Mac computers",
        "BYOD impact and risk": (
            "A personal PC with any browser can open Outlook on the web, SharePoint and Teams. Without session "
            "controls the user can download, print and sync freely, and malware on that PC can read anything "
            "opened. Office desktop apps and the OneDrive sync client on such PCs create full local copies."
        ),
        "Remediation steps": (
            "1. Block desktop/mobile clients on non-compliant Windows/macOS (item 3, policy for desktop clients).\n"
            "2. Allow browser access with app-enforced restrictions (SharePoint limited access, OWA ReadOnly - "
            "see item 4).\n"
            "3. Preferably require Microsoft Edge with Windows MAM on personal Windows PCs (CA: Windows platform, "
            "browser, grant 'Require app protection policy').\n"
            "4. With Defender for Cloud Apps, use Conditional Access App Control session policies to block "
            "download / copy / print of sensitive content in any browser.\n"
            "5. Educate users that personal PCs are browser-only by design."
        ),
        "Where to configure": "Entra admin center > Conditional Access; Intune > App protection (Windows); Defender portal > Cloud apps",
        "Licence needed": "Entra ID P1 + Intune; Defender for Cloud Apps for session policies",
        "How to verify": "On a personal PC: Outlook desktop sign-in blocked, OWA attachments are view-only, SharePoint shows 'download disabled' banner.",
        "Effort": "Medium",
    },
    {
        "Criticality": "High",
        "Area": "Identity",
        "Issue": "Uncontrolled device registration and enrolment",
        "BYOD impact and risk": (
            "By default any user can register (Entra registered) or join devices without extra verification, "
            "and enrol personal Windows PCs into Intune. An attacker with a stolen password can register their "
            "own device, which may then satisfy weaker device-based policies or persist access. Stale "
            "registrations clutter inventory and hide real devices."
        ),
        "Remediation steps": (
            "1. Entra admin center > Devices > Device settings: limit 'Maximum number of devices per user' "
            "(e.g. 5-10).\n"
            "2. Create a CA policy for the user action 'Register or join devices' requiring MFA (set 'Require "
            "MFA to register or join devices' to No when using the CA policy).\n"
            "3. Intune > Devices > Enrollment restrictions: block personally owned Windows/macOS enrolment if "
            "the BYOD model is MAM-only; allow iOS User Enrollment / Android Work Profile only.\n"
            "4. Schedule clean-up of devices inactive for 90+ days (Entra > Devices > All devices, filter "
            "Activity), disable first and delete after a grace period."
        ),
        "Where to configure": "Entra admin center > Devices > Device settings; Conditional Access; Intune > Enrollment",
        "Licence needed": "Entra ID P1 + Intune",
        "How to verify": "Registering a new device prompts for MFA; Intune enrollment of a personal Windows PC is blocked; stale-device report is reviewed monthly.",
        "Effort": "Low",
    },
    {
        "Criticality": "High",
        "Area": "Identity",
        "Issue": "Users can grant third-party apps access to company data (OAuth consent)",
        "BYOD impact and risk": (
            "On personal devices users install productivity apps, mail clients and AI tools that ask to "
            "'Sign in with Microsoft' and request Mail.Read or Files.Read.All. Once consented, the app reads "
            "data directly through Microsoft Graph from its own servers, bypassing every device control. "
            "Consent phishing uses the same path."
        ),
        "Remediation steps": (
            "1. Entra admin center > Enterprise apps > Consent and permissions: allow user consent only for "
            "apps from verified publishers with low-impact permissions (or disable user consent).\n"
            "2. Enable the admin consent workflow so users can request apps and admins review them.\n"
            "3. Review existing grants: Enterprise apps > filter 'Application type = all', check permissions "
            "and remove unknown apps.\n"
            "4. With Defender for Cloud Apps, enable app governance / OAuth app policies to alert on risky apps."
        ),
        "Where to configure": "Entra admin center > Enterprise applications > Consent and permissions",
        "Licence needed": "Free (Defender for Cloud Apps optional)",
        "How to verify": "A test user attempting to consent to an unverified app with Mail.Read sees 'Approval required'.",
        "Effort": "Low",
    },
    {
        "Criticality": "Medium",
        "Area": "Monitoring",
        "Issue": "Little visibility of which personal devices access what",
        "BYOD impact and risk": (
            "Without device-aware logging you cannot answer 'which unmanaged devices accessed customer data "
            "last week?' during an incident. Entra ID Free keeps sign-in logs for only 7 days, P1/P2 for 30 "
            "days, which is often shorter than the time it takes to discover a compromise."
        ),
        "Remediation steps": (
            "1. Confirm the unified audit log is on: Get-AdminAuditLogConfig | fl UnifiedAuditLogIngestionEnabled.\n"
            "2. Export Entra sign-in and audit logs to a Log Analytics workspace or SIEM for 90+ days of "
            "retention.\n"
            "3. Use the Conditional Access insights and reporting workbook to see unmanaged-device sign-ins.\n"
            "4. Review Intune app protection reports monthly (Apps > Monitor > App protection status).\n"
            "5. Create alerts for new inbox forwarding rules, mass downloads and impossible travel (Defender "
            "portal alert policies)."
        ),
        "Where to configure": "Entra admin center > Monitoring > Diagnostic settings; Purview portal > Audit; Defender portal",
        "Licence needed": "Entra ID P1; Azure subscription for Log Analytics",
        "How to verify": "A sign-in from a test unmanaged device can be found in the SIEM 60 days later.",
        "Effort": "Medium",
    },
    {
        "Criticality": "Medium",
        "Area": "Data protection",
        "Issue": "Sensitive data is not classified, so protection cannot follow it onto personal devices",
        "BYOD impact and risk": (
            "Device controls protect the container, but once data leaves (forwarded email, a file shared "
            "externally, a screenshot on another device) only content-level protection still applies. "
            "Without sensitivity labels and DLP, a payroll spreadsheet and a lunch menu are treated the same."
        ),
        "Remediation steps": (
            "1. Create a small label taxonomy (Public, General, Confidential, Highly Confidential) in Microsoft "
            "Purview.\n"
            "2. Apply encryption to Confidential and above so files can only be opened by authorised users, "
            "and optionally block offline access for Highly Confidential.\n"
            "3. Configure DLP policies for Exchange, SharePoint, OneDrive and Teams to detect and block sharing "
            "of sensitive information types (payment cards, national IDs).\n"
            "4. Turn on default labelling for new documents and mail where appropriate."
        ),
        "Where to configure": "Microsoft Purview portal > Information protection; Data loss prevention",
        "Licence needed": "Business Premium / E3 (manual labels, DLP); E5 for auto-labelling",
        "How to verify": "Open a Highly Confidential document as an unauthorised user (denied); DLP blocks emailing a test card number externally.",
        "Effort": "High",
    },
    {
        "Criticality": "Medium",
        "Area": "Governance",
        "Issue": "No written BYOD policy covering acceptable use, privacy and what IT can see or wipe",
        "BYOD impact and risk": (
            "Without a signed policy, enforcing controls on personal property invites disputes and possible "
            "legal exposure (employee privacy, unlawful wipe of personal data). Users who do not understand "
            "the rules work around them, for example by emailing files to personal accounts. eDiscovery and "
            "legal holds may also need to reach data that sits on personal devices."
        ),
        "Remediation steps": (
            "1. Write a BYOD policy with HR and legal: eligible devices, required apps (Outlook, Teams, "
            "OneDrive), minimum OS, PIN/biometric, reporting loss within 24 hours, selective-wipe consent, "
            "what IT can and cannot see.\n"
            "2. Prefer MAM or user enrolment models so IT never sees personal apps, photos or location.\n"
            "3. Customise Intune Company Portal privacy messaging and terms and conditions.\n"
            "4. Require acknowledgement (Entra terms of use, enforceable via Conditional Access) before access.\n"
            "5. Review the policy annually."
        ),
        "Where to configure": "HR/legal; Entra admin center > Identity governance > Terms of use; Intune > Tenant administration > Customization",
        "Licence needed": "Entra ID P1 (terms of use)",
        "How to verify": "Every BYOD user has accepted the current terms of use version (Terms of use report).",
        "Effort": "Medium",
    },
    {
        "Criticality": "Medium",
        "Area": "Data protection",
        "Issue": "Personal and work accounts mixed in the same apps and browser",
        "BYOD impact and risk": (
            "On a personal device the same Outlook, OneDrive or Edge app often holds both a personal account "
            "and the work account. Users can move content between them, or sign in to other organisations' "
            "tenants and upload company data there."
        ),
        "Remediation steps": (
            "1. Rely on app protection 'multi-identity' behaviour: org data cannot be saved to the personal "
            "account inside Outlook/OneDrive/Office (item 4 settings).\n"
            "2. Use Edge for Business profiles; on Windows MAM the work profile is the protected container.\n"
            "3. Configure Entra Tenant restrictions v2 to stop users signing in to other tenants on devices "
            "where it can be enforced (managed devices or via Global Secure Access).\n"
            "4. Restrict external sharing in SharePoint/OneDrive to existing guests or specific domains."
        ),
        "Where to configure": "Intune > App protection; Entra admin center > External identities > Cross-tenant access; SharePoint admin center > Sharing",
        "Licence needed": "Intune + Entra ID P1",
        "How to verify": "On a test phone, try to save a work attachment to the personal OneDrive account in the same app (blocked).",
        "Effort": "Medium",
    },
    {
        "Criticality": "Medium",
        "Area": "People",
        "Issue": "Users not trained on BYOD risks and how to report incidents",
        "BYOD impact and risk": (
            "Technical controls fail if users install apps from unofficial stores, ignore OS updates, approve "
            "unexpected MFA prompts or do not report a lost phone. Personal devices are also used for personal "
            "email and social media, which raises phishing exposure."
        ),
        "Remediation steps": (
            "1. Run short onboarding training: installing Outlook/Teams, what app protection does, how to "
            "report loss or suspected compromise.\n"
            "2. Use Defender for Office 365 Attack simulation training (Plan 2) or another phishing simulator.\n"
            "3. Enable the Report Message / Report Phishing button in Outlook.\n"
            "4. Publish a one-page 'lost device' procedure with the helpdesk contact."
        ),
        "Where to configure": "Defender portal > Email & collaboration > Attack simulation training; internal comms",
        "Licence needed": "Defender for Office 365 Plan 2 for simulations (optional)",
        "How to verify": "Training completion rate and simulated phish click rate tracked quarterly.",
        "Effort": "Low",
    },
    {
        "Criticality": "Low",
        "Area": "Network",
        "Issue": "Access from untrusted networks (public Wi-Fi, home routers)",
        "BYOD impact and risk": (
            "Microsoft 365 traffic is always TLS-encrypted, so network eavesdropping is a low risk. The "
            "remaining exposure is captive-portal phishing and sign-ins from unexpected countries, which "
            "location-aware policies can reduce."
        ),
        "Remediation steps": (
            "1. Define named locations for countries you operate in and block or require stronger MFA from "
            "others (do not rely on IP alone).\n"
            "2. Keep MFA and token controls (items 2 and 5) as the primary protection.\n"
            "3. Optionally evaluate Microsoft Entra Internet Access / Global Secure Access for compliant-network "
            "checks."
        ),
        "Where to configure": "Entra admin center > Conditional Access > Named locations",
        "Licence needed": "Entra ID P1",
        "How to verify": "A test sign-in through a VPN exit node in a blocked country is denied.",
        "Effort": "Low",
    },
    {
        "Criticality": "Low",
        "Area": "Resilience",
        "Issue": "Accidental deletion or ransomware on a synced personal device",
        "BYOD impact and risk": (
            "If a personal PC with OneDrive sync is hit by ransomware or a user deletes a folder, the change "
            "syncs to the cloud. Microsoft 365 has recovery tools, but retention is limited unless configured."
        ),
        "Remediation steps": (
            "1. Prefer blocking sync on unmanaged PCs (items 3 and 4) so this cannot occur.\n"
            "2. Know the recovery tools: OneDrive 'Restore your OneDrive' (30 days), recycle bins (93 days).\n"
            "3. Apply Purview retention policies to Exchange, SharePoint and OneDrive for business-critical data.\n"
            "4. Consider Microsoft 365 Backup or a third-party backup for longer recovery points."
        ),
        "Where to configure": "Purview portal > Data lifecycle management; Microsoft 365 admin center > Settings > Microsoft 365 Backup",
        "Licence needed": "Included (retention); Microsoft 365 Backup is pay-as-you-go",
        "How to verify": "Test-restore a deleted folder from a pilot user's OneDrive.",
        "Effort": "Low",
    },
]

CRIT_FILL = {  # background, text
    "Critical": ("C00000", "FFFFFF"),
    "High": ("F4B183", "000000"),
    "Medium": ("FFE699", "000000"),
    "Low": ("C6E0B4", "000000"),
}

WIDTHS = [8, 11, 14, 34, 60, 80, 34, 24, 40, 9, 14, 13]

README_ROWS = [
    ("BYOD security remediation plan - Microsoft 365 cloud-only tenant", ""),
    ("", ""),
    ("Purpose", "Issues that bring-your-own-device creates for a cloud-only Microsoft 365 tenant, ordered by criticality, with remediation steps."),
    ("How to use", "Work top to bottom on the 'Remediation Plan' sheet. Items 1-5 (Critical) should be in place before allowing personal devices access to company data."),
    ("Columns to fill in", "Owner and Status are for you to complete. Status values: Not started, In progress, Done, Accepted risk. Everything else is reference content."),
    ("Example", "Priority 2 > Owner: J. Smith > Status: In progress"),
    ("Criticality", "Critical = exploitable now and leads to data loss or account takeover; High = significant exposure; Medium = gaps in governance or defence in depth; Low = residual risk."),
    ("Licensing", "Most controls need Microsoft Entra ID P1 and Intune, both in Microsoft 365 Business Premium (up to 300 users) and E3+EMS / E5. Risk-based policies need Entra ID P2."),
    ("Recommended BYOD model", "Phones/tablets: Intune app protection without enrolment (MAM). Personal Windows/macOS: browser-only or Edge with Windows MAM. Full desktop apps only on Intune-compliant devices."),
    ("Caution", "Introduce Conditional Access policies in Report-only mode first and always exclude two monitored break-glass admin accounts."),
    ("Accuracy", "Microsoft renames portal menus and retires controls regularly (e.g. 'Require approved client app'). Confirm against current Microsoft Learn documentation before changing production."),
    ("Prepared", "2026-10-06"),
]

STATUS_OPTIONS = ["Not started", "In progress", "Done", "Accepted risk"]


def rows():
    for i, item in enumerate(ITEMS, start=1):
        r = dict(item)
        r["Priority"] = i
        r["Owner"] = ""
        r["Status"] = "Not started"
        yield [r[c] for c in COLUMNS]


def build_xlsx(path):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.worksheet.datavalidation import DataValidation

    wb = Workbook()
    ws = wb.active
    ws.title = "Remediation Plan"
    thin = Side(style="thin", color="BFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    base = Font(name="Arial", size=10)

    ws.append(COLUMNS)
    for cell in ws[1]:
        cell.font = Font(name="Arial", size=10, bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="1F3864")
        cell.alignment = Alignment(wrap_text=True, vertical="center")
        cell.border = border

    for values in rows():
        ws.append(values)
        r = ws.max_row
        for cell in ws[r]:
            cell.font = base
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            cell.border = border
        crit = ws.cell(row=r, column=2)
        bg, fg = CRIT_FILL[crit.value]
        crit.fill = PatternFill("solid", fgColor=bg)
        crit.font = Font(name="Arial", size=10, bold=True, color=fg)
        ws.cell(row=r, column=1).alignment = Alignment(horizontal="center", vertical="top")
        ws.cell(row=r, column=11).fill = PatternFill("solid", fgColor="FFFF00")
        ws.cell(row=r, column=12).fill = PatternFill("solid", fgColor="FFFF00")

    for i, w in enumerate(WIDTHS, start=1):
        ws.column_dimensions[ws.cell(row=1, column=i).column_letter].width = w
    ws.freeze_panes = "E2"
    ws.auto_filter.ref = ws.dimensions

    dv = DataValidation(type="list", formula1='"' + ",".join(STATUS_OPTIONS) + '"', allow_blank=True)
    ws.add_data_validation(dv)
    dv.add(f"L2:L{ws.max_row}")

    # Summary by criticality (formulas so it updates as Status changes)
    sm = wb.create_sheet("Summary")
    sm.append(["Criticality", "Items", "Done", "Remaining"])
    last = ws.max_row
    for crit in CRIT_FILL:
        n = sm.max_row + 1
        sm.append([
            crit,
            f"=COUNTIF('Remediation Plan'!$B$2:$B${last},A{n})",
            f"=COUNTIFS('Remediation Plan'!$B$2:$B${last},A{n},'Remediation Plan'!$L$2:$L${last},\"Done\")",
            f"=B{n}-C{n}",
        ])
    n = sm.max_row + 1
    sm.append(["Total", f"=SUM(B2:B{n-1})", f"=SUM(C2:C{n-1})", f"=SUM(D2:D{n-1})"])
    for row in sm.iter_rows():
        for cell in row:
            cell.font = Font(name="Arial", size=10, bold=cell.row in (1, n))
            cell.border = border
    for col, w in zip("ABCD", (14, 10, 10, 12)):
        sm.column_dimensions[col].width = w

    rd = wb.create_sheet("Read Me", 0)
    for a, b in README_ROWS:
        rd.append([a, b])
    rd["A1"].font = Font(name="Arial", size=14, bold=True)
    for row in rd.iter_rows(min_row=2):
        row[0].font = Font(name="Arial", size=10, bold=True)
        row[1].font = base
        row[0].alignment = Alignment(vertical="top")
        row[1].alignment = Alignment(wrap_text=True, vertical="top")
    rd.column_dimensions["A"].width = 24
    rd.column_dimensions["B"].width = 110
    wb.active = 1
    wb.save(path)


def build_numbers(path):
    from numbers_parser import Document, RGB

    data = list(rows())
    doc = Document(
        sheet_name="Remediation Plan",
        table_name="BYOD Remediation",
        num_header_rows=1,
        num_header_cols=0,
        num_rows=len(data) + 1,
        num_cols=len(COLUMNS),
    )
    t = doc.sheets[0].tables[0]
    for c, name in enumerate(COLUMNS):
        t.write(0, c, name)
    for r, values in enumerate(data, start=1):
        for c, v in enumerate(values):
            t.write(r, c, v)

    header = doc.add_style(name="BYOD Header", font_name="Arial", font_size=11.0, bold=True,
                           font_color=RGB(255, 255, 255), bg_color=RGB(31, 56, 100), text_wrap=True)
    body = doc.add_style(name="BYOD Body", font_name="Arial", font_size=10.0, text_wrap=True, alignment=("left", "top"))
    crit_styles = {
        k: doc.add_style(name=f"BYOD {k}", font_name="Arial", font_size=10.0, bold=True, alignment=("left", "top"),
                         bg_color=RGB(*bytes.fromhex(bg)), font_color=RGB(*bytes.fromhex(fg)))
        for k, (bg, fg) in CRIT_FILL.items()
    }
    fill_in = doc.add_style(name="BYOD Fill in", font_name="Arial", font_size=10.0, alignment=("left", "top"),
                            bg_color=RGB(255, 255, 0))
    for c in range(len(COLUMNS)):
        t.set_cell_style(0, c, header)
        t.col_width(c, WIDTHS[c] * 7)
    for r, values in enumerate(data, start=1):
        for c in range(len(COLUMNS)):
            t.set_cell_style(r, c, body)
        t.set_cell_style(r, 1, crit_styles[values[1]])
        t.set_cell_style(r, 10, fill_in)
        t.set_cell_style(r, 11, fill_in)

    doc.add_sheet("Read Me", "Read Me", num_rows=len(README_ROWS), num_cols=2)
    rt = doc.sheets["Read Me"].tables[0]
    for r, (a, b) in enumerate(README_ROWS):
        rt.write(r, 0, a)
        rt.write(r, 1, b)
        rt.set_cell_style(r, 1, body)
    rt.col_width(0, 170)
    rt.col_width(1, 760)
    doc.save(path)


if __name__ == "__main__":
    build_xlsx(HERE / f"{NAME}.xlsx")
    build_numbers(HERE / f"{NAME}.numbers")
    print("Wrote", NAME + ".xlsx and", NAME + ".numbers")
