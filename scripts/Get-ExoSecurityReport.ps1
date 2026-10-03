#Requires -Version 5.1
<#
.SYNOPSIS
    Reviews Exchange Online security posture: authentication, auditing, forwarding controls,
    EOP / Defender for Office 365 policies, quarantine, allow lists and admin / app access.

.DESCRIPTION
    Read-only. Defender for Office 365 checks (Safe Links, Safe Attachments, impersonation) are
    reported as "not licensed" when the cmdlets are unavailable.

    Mailbox-level checks (per-mailbox forwarding, SMTP AUTH exceptions, inbox rules forwarding
    externally, audit bypass) enumerate every mailbox and are opt-in with -IncludeMailboxLevelChecks.

.PARAMETER Days
    Days of quarantine history to summarise (default 7, max 30).

.PARAMETER IncludeMailboxLevelChecks
    Enumerates mailboxes for forwarding, SMTP AUTH and audit bypass settings.

.PARAMETER IncludeInboxRules
    With -IncludeMailboxLevelChecks, also reads inbox rules from every user mailbox to find rules
    that forward or redirect externally. Slow: roughly one call per mailbox.

.PARAMETER OutputPath
    Folder for CSV exports. Omit to only return the result object.

.EXAMPLE
    .\Get-ExoSecurityReport.ps1 -IncludeMailboxLevelChecks -OutputPath .\out
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 30)] [int] $Days = 7,
    [switch] $IncludeMailboxLevelChecks,
    [switch] $IncludeInboxRules,
    [string] $OutputPath
)

. (Join-Path $PSScriptRoot 'ExoHealth.Common.ps1')
Assert-ExoConnection

$result = New-ExoSectionResult -Section 'Security'
$accepted = Invoke-ExoSafe { Get-AcceptedDomain } 'accepted domains' -Default @()

#region Authentication and auditing

$org = Invoke-ExoSafe { Get-OrganizationConfig } 'organization config' -Single
$transport = Invoke-ExoSafe { Get-TransportConfig } 'transport config' -Single

if ($org) {
    if ($org.OAuth2ClientProfileEnabled) {
        Add-ExoFinding $result -Check 'Modern authentication' -Status Pass -Detail 'OAuth2ClientProfileEnabled is true.'
    }
    else {
        Add-ExoFinding $result -Check 'Modern authentication' -Status Fail -Severity High `
            -Detail 'Modern authentication is disabled for Outlook clients.' `
            -Recommendation 'Set-OrganizationConfig -OAuth2ClientProfileEnabled $true'
    }

    if ($org.AuditDisabled) {
        Add-ExoFinding $result -Check 'Mailbox auditing (organisation)' -Status Fail -Severity High `
            -Detail 'Mailbox auditing is turned off for the whole organisation.' `
            -Recommendation 'Set-OrganizationConfig -AuditDisabled $false'
    }
    else {
        Add-ExoFinding $result -Check 'Mailbox auditing (organisation)' -Status Pass -Detail 'Audit-by-default is on.'
    }

    $rejectDirectSend = Get-ExoPropertyValue $org 'RejectDirectSend' $null
    if ($rejectDirectSend -eq $false) {
        Add-ExoFinding $result -Check 'Direct Send' -Status Warning -Severity Medium `
            -Detail 'Unauthenticated Direct Send to the tenant MX using your own domains is accepted (commonly abused for internal-looking phishing).' `
            -Recommendation 'After moving devices/apps to SMTP AUTH or a partner connector: Set-OrganizationConfig -RejectDirectSend $true'
    }
    elseif ($rejectDirectSend -eq $true) {
        Add-ExoFinding $result -Check 'Direct Send' -Status Pass -Detail 'RejectDirectSend is enabled.'
    }
}

$auditCfg = Invoke-ExoSafe { Get-AdminAuditLogConfig } 'admin audit log config' -Single
if ($auditCfg) {
    if ($auditCfg.UnifiedAuditLogIngestionEnabled) {
        Add-ExoFinding $result -Check 'Unified audit log' -Status Pass -Detail 'Unified audit log ingestion is enabled.'
    }
    else {
        Add-ExoFinding $result -Check 'Unified audit log' -Status Fail -Severity High `
            -Detail 'Unified audit log ingestion is disabled - no audit trail for investigations.' `
            -Recommendation 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true'
    }
}

if ($transport) {
    if ($transport.SmtpClientAuthenticationDisabled) {
        Add-ExoFinding $result -Check 'SMTP AUTH (organisation)' -Status Pass -Detail 'SMTP client authentication is disabled tenant-wide.'
    }
    else {
        Add-ExoFinding $result -Check 'SMTP AUTH (organisation)' -Status Warning -Severity Medium `
            -Detail 'SMTP AUTH client submission is enabled for every mailbox by default.' `
            -Recommendation 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true and enable per mailbox only where required (OAuth only - Basic auth for SMTP AUTH is being retired).'
    }
    if (Get-ExoPropertyValue $transport 'AllowLegacyTLSClients' $false) {
        Add-ExoFinding $result -Check 'Legacy TLS clients' -Status Warning -Severity Low `
            -Detail 'TLS 1.0/1.1 clients are allowed on the legacy SMTP endpoint.' `
            -Recommendation 'Set-TransportConfig -AllowLegacyTLSClients $false after confirming no device depends on it.'
    }
}

$authPolicies = Invoke-ExoSafe { Get-AuthenticationPolicy } 'authentication policies'
if ($null -ne $authPolicies -and @($authPolicies).Count -gt 0) {
    $result.Data['AuthenticationPolicies'] = @($authPolicies | ConvertTo-ExoFlatObject -Property Name, AllowBasicAuthSmtp,
        AllowBasicAuthPop, AllowBasicAuthImap, AllowBasicAuthWebServices, AllowBasicAuthPowershell, WhenChanged)
}

$externalTag = Invoke-ExoSafe { Get-ExternalInOutlook } 'external sender tagging' -Single
if ($externalTag) {
    if ($externalTag.Enabled) {
        Add-ExoFinding $result -Check 'External sender tag in Outlook' -Status Pass -Detail 'Enabled.'
    }
    else {
        Add-ExoFinding $result -Check 'External sender tag in Outlook' -Status Warning -Severity Low `
            -Detail 'Outlook does not tag messages from external senders.' -Recommendation 'Set-ExternalInOutlook -Enabled $true'
    }
}

#endregion

#region Forwarding controls

$remoteDefault = Invoke-ExoSafe { Get-RemoteDomain -Identity Default } 'default remote domain' -Single
$outboundSpam = Invoke-ExoSafe { Get-HostedOutboundSpamFilterPolicy } 'outbound spam policies'
if ($null -ne $outboundSpam) {
    $result.Data['OutboundSpamPolicies'] = @($outboundSpam | ConvertTo-ExoFlatObject -Property Name, IsDefault,
        AutoForwardingMode, RecipientLimitExternalPerHour, RecipientLimitInternalPerHour, RecipientLimitPerDay,
        ActionWhenThresholdReached, NotifyOutboundSpam, NotifyOutboundSpamRecipients, BccSuspiciousOutboundMail)

    foreach ($p in $outboundSpam) {
        if ("$($p.AutoForwardingMode)" -eq 'On') {
            Add-ExoFinding $result -Check 'Automatic external forwarding' -Status Fail -Severity High -Target $p.Name `
                -Detail 'Outbound spam policy allows automatic forwarding to external recipients.' `
                -Recommendation 'Set AutoForwardingMode to Off (or Automatic, which is Off) and create scoped exceptions for approved users.'
        }
        if ("$($p.ActionWhenThresholdReached)" -eq 'Alert') {
            Add-ExoFinding $result -Check 'Outbound spam threshold action' -Status Warning -Severity Medium -Target $p.Name `
                -Detail 'Users exceeding sending limits only raise an alert and keep sending.' `
                -Recommendation 'Use BlockUser (or BlockUserForToday) so compromised accounts are restricted automatically.'
        }
    }
    if (-not (@($outboundSpam | Where-Object { "$($_.AutoForwardingMode)" -eq 'On' }))) {
        Add-ExoFinding $result -Check 'Automatic external forwarding' -Status Pass -Detail 'No outbound spam policy allows external auto-forwarding.'
    }
}
if ($remoteDefault -and $remoteDefault.AutoForwardEnabled) {
    Add-ExoFinding $result -Check 'Remote domain auto-forward (Default)' -Status Info -Target 'Default' `
        -Detail 'The Default remote domain allows auto-forward; the outbound spam policy is the effective control.' `
        -Recommendation 'Optionally Set-RemoteDomain Default -AutoForwardEnabled $false for defence in depth.'
}

$blocked = Invoke-ExoSafe { Get-BlockedSenderAddress } 'restricted users'
if ($null -ne $blocked) {
    $result.Data['RestrictedUsers'] = @($blocked | ConvertTo-ExoFlatObject -Property SenderAddress, Reason, CreatedDatetime)
    if (@($blocked).Count -gt 0) {
        Add-ExoFinding $result -Check 'Restricted users (blocked from sending)' -Status Fail -Severity High `
            -Detail "$(@($blocked).Count) users are restricted for sending spam: $((@($blocked) | ForEach-Object { $_.SenderAddress }) -join ', ')." `
            -Recommendation 'Treat as account compromise: reset credentials, revoke sessions, review inbox rules, then Remove-BlockedSenderAddress.'
    }
    else {
        Add-ExoFinding $result -Check 'Restricted users (blocked from sending)' -Status Pass -Detail 'No users are restricted.'
    }
}

#endregion

#region EOP policies

$contentFilter = Invoke-ExoSafe { Get-HostedContentFilterPolicy } 'anti-spam policies'
if ($null -ne $contentFilter) {
    $result.Data['AntiSpamPolicies'] = @($contentFilter | ConvertTo-ExoFlatObject -Property Name, IsDefault, BulkThreshold,
        SpamAction, HighConfidenceSpamAction, PhishSpamAction, HighConfidencePhishAction, BulkSpamAction,
        QuarantineRetentionPeriod, InlineSafetyTipsEnabled, ZapEnabled, SpamZapEnabled, PhishZapEnabled,
        AllowedSenderDomains, AllowedSenders, BlockedSenderDomains)

    foreach ($p in $contentFilter) {
        $allowedDomains = @(Get-ExoPropertyValue $p 'AllowedSenderDomains' @())
        $allowedSenders = @(Get-ExoPropertyValue $p 'AllowedSenders' @())
        if ($allowedDomains.Count -gt 0) {
            Add-ExoFinding $result -Check 'Anti-spam allowed sender domains' -Status Fail -Severity High -Target $p.Name `
                -Detail "$($allowedDomains.Count) domains skip spam filtering: $(ConvertTo-ExoFlatValue $allowedDomains). Allowed domains are easily spoofed." `
                -Recommendation 'Remove them; use the Tenant Allow/Block List with spoof allow entries or fix the sender''s authentication.'
        }
        if ($allowedSenders.Count -gt 0) {
            Add-ExoFinding $result -Check 'Anti-spam allowed senders' -Status Warning -Severity Medium -Target $p.Name `
                -Detail "$($allowedSenders.Count) sender addresses skip spam filtering." `
                -Recommendation 'Review and remove; prefer Tenant Allow/Block List entries with an expiry date.'
        }
        if ("$($p.HighConfidencePhishAction)" -ne 'Quarantine') {
            Add-ExoFinding $result -Check 'High-confidence phish action' -Status Fail -Severity High -Target $p.Name `
                -Detail "HighConfidencePhishAction is $($p.HighConfidencePhishAction)." -Recommendation 'Set to Quarantine.'
        }
        if ("$($p.PhishSpamAction)" -ne 'Quarantine') {
            Add-ExoFinding $result -Check 'Phish action' -Status Warning -Severity Medium -Target $p.Name `
                -Detail "PhishSpamAction is $($p.PhishSpamAction)." -Recommendation 'Set to Quarantine (Standard and Strict presets).'
        }
        if ("$($p.HighConfidenceSpamAction)" -notin 'Quarantine', 'Delete') {
            Add-ExoFinding $result -Check 'High-confidence spam action' -Status Warning -Severity Low -Target $p.Name `
                -Detail "HighConfidenceSpamAction is $($p.HighConfidenceSpamAction)." -Recommendation 'Set to Quarantine.'
        }
        if ([int]$p.BulkThreshold -gt 7) {
            Add-ExoFinding $result -Check 'Bulk complaint level threshold' -Status Warning -Severity Low -Target $p.Name `
                -Detail "BulkThreshold is $($p.BulkThreshold); more bulk mail reaches inboxes." `
                -Recommendation 'Use 6 (Standard preset) or 5 (Strict preset).'
        }
    }
}

$connFilter = Invoke-ExoSafe { Get-HostedConnectionFilterPolicy } 'connection filter policy'
if ($null -ne $connFilter) {
    $result.Data['ConnectionFilterPolicies'] = @($connFilter | ConvertTo-ExoFlatObject -Property Name, IPAllowList, IPBlockList, EnableSafeList)
    foreach ($p in $connFilter) {
        $allowIPs = @(Get-ExoPropertyValue $p 'IPAllowList' @())
        if ($allowIPs.Count -gt 0) {
            Add-ExoFinding $result -Check 'Connection filter IP allow list' -Status Warning -Severity Medium -Target $p.Name `
                -Detail "Mail from $($allowIPs.Count) IP ranges skips spam filtering: $(ConvertTo-ExoFlatValue $allowIPs)." `
                -Recommendation 'Keep only IPs you control; never allow shared/bulk provider ranges. Prefer connectors for partner mail.'
        }
        if ($p.EnableSafeList) {
            Add-ExoFinding $result -Check 'Connection filter safe list' -Status Warning -Severity Low -Target $p.Name `
                -Detail 'EnableSafeList skips spam filtering for Microsoft''s third-party safe list.' -Recommendation 'Set EnableSafeList to $false.'
        }
    }
}

$malware = Invoke-ExoSafe { Get-MalwareFilterPolicy } 'anti-malware policies'
if ($null -ne $malware) {
    $result.Data['AntiMalwarePolicies'] = @($malware | ConvertTo-ExoFlatObject -Property Name, IsDefault, EnableFileFilter,
        FileTypeAction, ZapEnabled, EnableInternalSenderAdminNotifications, InternalSenderAdminAddress, QuarantineTag)
    foreach ($p in $malware) {
        if (-not $p.EnableFileFilter) {
            Add-ExoFinding $result -Check 'Common attachments filter' -Status Warning -Severity Medium -Target $p.Name `
                -Detail 'Common attachment (file type) filter is off.' -Recommendation 'Set-MalwareFilterPolicy -EnableFileFilter $true'
        }
        if (-not $p.ZapEnabled) {
            Add-ExoFinding $result -Check 'Malware ZAP' -Status Warning -Severity Medium -Target $p.Name `
                -Detail 'Zero-hour auto purge for malware is off.' -Recommendation 'Set-MalwareFilterPolicy -ZapEnabled $true'
        }
    }
}

$antiPhish = Invoke-ExoSafe { Get-AntiPhishPolicy } 'anti-phishing policies'
if ($null -ne $antiPhish) {
    $result.Data['AntiPhishPolicies'] = @($antiPhish | ConvertTo-ExoFlatObject -Property Name, IsDefault, Enabled,
        EnableSpoofIntelligence, HonorDmarcPolicy, EnableUnauthenticatedSender, EnableViaTag, EnableFirstContactSafetyTips,
        PhishThresholdLevel, EnableMailboxIntelligence, EnableMailboxIntelligenceProtection, EnableTargetedUserProtection,
        EnableOrganizationDomainsProtection, EnableTargetedDomainsProtection, TargetedUsersToProtect)
    foreach ($p in $antiPhish) {
        if (-not $p.EnableSpoofIntelligence) {
            Add-ExoFinding $result -Check 'Spoof intelligence' -Status Fail -Severity High -Target $p.Name `
                -Detail 'Spoof intelligence is off.' -Recommendation 'Set-AntiPhishPolicy -EnableSpoofIntelligence $true'
        }
        if ((Get-ExoPropertyValue $p 'HonorDmarcPolicy' $true) -eq $false) {
            Add-ExoFinding $result -Check 'Honor DMARC policy' -Status Warning -Severity Medium -Target $p.Name `
                -Detail 'Sender DMARC p=quarantine / p=reject is not honoured.' -Recommendation 'Set-AntiPhishPolicy -HonorDmarcPolicy $true'
        }
        if (-not (Get-ExoPropertyValue $p 'EnableFirstContactSafetyTips' $false)) {
            Add-ExoFinding $result -Check 'First contact safety tip' -Status Warning -Severity Low -Target $p.Name `
                -Detail 'Users are not warned on first contact with a new sender.' -Recommendation 'Set-AntiPhishPolicy -EnableFirstContactSafetyTips $true'
        }
        $threshold = Get-ExoPropertyValue $p 'PhishThresholdLevel' $null
        if ($null -ne $threshold -and [int]$threshold -lt 2 -and (Test-ExoCommand 'Get-SafeLinksPolicy')) {
            Add-ExoFinding $result -Check 'Phishing threshold' -Status Warning -Severity Low -Target $p.Name `
                -Detail "PhishThresholdLevel is $threshold." -Recommendation 'Use 3 (Standard) or 4 (Strict).'
        }
    }
}

#endregion

#region Defender for Office 365

if (Test-ExoCommand 'Get-SafeLinksPolicy') {
    $builtIn = Invoke-ExoSafe { Get-ATPBuiltInProtectionRule } 'built-in protection rule'
    $safeLinks = Invoke-ExoSafe { Get-SafeLinksPolicy } 'Safe Links policies'
    if ($null -ne $safeLinks) {
        $result.Data['SafeLinksPolicies'] = @($safeLinks | ConvertTo-ExoFlatObject -Property Name, IsBuiltInProtection,
            EnableSafeLinksForEmail, EnableSafeLinksForTeams, EnableSafeLinksForOffice, ScanUrls, DeliverMessageAfterScan,
            EnableForInternalSenders, TrackClicks, AllowClickThrough, DisableUrlRewrite)
        foreach ($p in $safeLinks) {
            if (-not $p.EnableSafeLinksForEmail) {
                Add-ExoFinding $result -Check 'Safe Links for email' -Status Warning -Severity Medium -Target $p.Name -Detail 'Disabled for email.'
            }
            if ($p.AllowClickThrough) {
                Add-ExoFinding $result -Check 'Safe Links click-through' -Status Warning -Severity Low -Target $p.Name `
                    -Detail 'Users may click through to known-malicious URLs.' -Recommendation 'Set AllowClickThrough to $false.'
            }
            if (-not $p.DeliverMessageAfterScan) {
                Add-ExoFinding $result -Check 'Safe Links wait for scan' -Status Warning -Severity Low -Target $p.Name `
                    -Detail 'Messages are delivered before URL detonation completes.' -Recommendation 'Set DeliverMessageAfterScan to $true.'
            }
        }
    }

    $safeAtt = Invoke-ExoSafe { Get-SafeAttachmentPolicy } 'Safe Attachments policies'
    if ($null -ne $safeAtt) {
        $result.Data['SafeAttachmentPolicies'] = @($safeAtt | ConvertTo-ExoFlatObject -Property Name, IsBuiltInProtection, Enable, Action, QuarantineTag, Redirect, RedirectAddress)
        foreach ($p in $safeAtt) {
            if (-not $p.Enable -or "$($p.Action)" -eq 'Allow') {
                Add-ExoFinding $result -Check 'Safe Attachments action' -Status Warning -Severity Medium -Target $p.Name `
                    -Detail "Policy enabled: $($p.Enable); action: $($p.Action)." -Recommendation 'Use Block (or DynamicDelivery) and enable the policy.'
            }
        }
    }

    $atp = Invoke-ExoSafe { Get-AtpPolicyForO365 } 'Defender for Office 365 global settings' -Single
    if ($atp) {
        $spo = Get-ExoPropertyValue $atp 'EnableATPForSPOTeamsODB' $false
        $status = if ($spo) { 'Pass' } else { 'Warning' }
        Add-ExoFinding $result -Check 'Safe Attachments for SharePoint, OneDrive and Teams' -Status $status -Severity Medium `
            -Detail "EnableATPForSPOTeamsODB: $spo. Safe Documents: $(Get-ExoPropertyValue $atp 'EnableSafeDocs' 'n/a')." `
            -Recommendation 'Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true'
    }

    $presetRules = @()
    $presetRules += @(Invoke-ExoSafe { Get-EOPProtectionPolicyRule } 'preset EOP rules' -Default @())
    $presetRules += @(Invoke-ExoSafe { Get-ATPProtectionPolicyRule } 'preset Defender rules' -Default @())
    $presetRules = @($presetRules | Where-Object { $_ })
    $result.Data['PresetSecurityPolicyRules'] = @($presetRules | ConvertTo-ExoFlatObject -Property Identity, State, Priority, SentTo, SentToMemberOf, RecipientDomainIs, ExceptIfSentTo)
    $enabledPresets = @($presetRules | Where-Object { "$($_.State)" -eq 'Enabled' })
    Add-ExoFinding $result -Check 'Preset security policies' -Status Info `
        -Detail "$($enabledPresets.Count) preset policy rules enabled: $(($enabledPresets | ForEach-Object { $_.Identity }) -join ', '). Built-in protection: $(if ($builtIn) { 'present' } else { 'not found' })." `
        -Recommendation 'Standard / Strict presets keep settings current with Microsoft recommendations; use Configuration analyzer to compare custom policies.'
}
else {
    Add-ExoFinding $result -Check 'Defender for Office 365' -Status Info `
        -Detail 'Safe Links / Safe Attachments cmdlets are not available (not licensed, or missing Security Reader role).' `
        -Recommendation 'Defender for Office 365 Plan 1 or 2 adds Safe Links, Safe Attachments and impersonation protection.'
}

#endregion

#region Tenant Allow/Block List and quarantine

$tabl = New-Object System.Collections.Generic.List[object]
foreach ($listType in 'Sender', 'Url', 'FileHash', 'IP') {
    $items = Invoke-ExoSafe { Get-TenantAllowBlockListItems -ListType $listType -Allow } "Tenant Allow List ($listType)" -Default @()
    foreach ($i in @($items)) {
        if ($null -eq $i) { continue }
        $tabl.Add([pscustomobject]@{
                ListType       = $listType
                Value          = $i.Value
                Action         = $i.Action
                ExpirationDate = $i.ExpirationDate
                LastUsedDate   = Get-ExoPropertyValue $i 'LastUsedDate'
                Notes          = $i.Notes
            })
    }
}
$result.Data['TenantAllowEntries'] = $tabl.ToArray()
$neverExpire = @($tabl | Where-Object { -not $_.ExpirationDate })
if ($neverExpire.Count -gt 0) {
    Add-ExoFinding $result -Check 'Tenant allow entries without expiry' -Status Warning -Severity Low `
        -Detail "$($neverExpire.Count) allow entries never expire: $(($neverExpire | Select-Object -First 10 | ForEach-Object { $_.Value }) -join ', ')." `
        -Recommendation 'Give allow entries an expiry date and review entries whose LastUsedDate is old.'
}

if (Test-ExoCommand 'Get-QuarantineMessage') {
    $qStart = (Get-Date).AddDays(-$Days)
    $quarantine = Invoke-ExoSafe {
        $all = New-Object System.Collections.Generic.List[object]
        $page = 1
        do {
            $batch = @(Get-QuarantineMessage -StartReceivedDate $qStart -EndReceivedDate (Get-Date) -PageSize 1000 -Page $page)
            foreach ($b in $batch) { $all.Add($b) }
            $page++
        } while ($batch.Count -eq 1000 -and $page -le 50)
        $all.ToArray()
    } 'quarantine messages'

    if ($null -ne $quarantine) {
        $byType = @($quarantine | Group-Object QuarantineTypes | Sort-Object Count -Descending |
            ForEach-Object { [pscustomobject]@{ QuarantineType = $_.Name; Messages = $_.Count; Released = @($_.Group | Where-Object ReleaseStatus -eq 'RELEASED').Count } })
        $result.Data['QuarantineByType'] = $byType
        $released = @($quarantine | Where-Object ReleaseStatus -eq 'RELEASED')
        Add-ExoFinding $result -Check 'Quarantine summary' -Status Info `
            -Detail ("{0} messages quarantined in {1} days ({2}). {3} released." -f @($quarantine).Count, $Days,
                (($byType | ForEach-Object { "$($_.QuarantineType) $($_.Messages)" }) -join ', '), $released.Count)

        $releasedMalware = @($released | Where-Object { "$($_.QuarantineTypes)" -match 'Malware|HighConfPhish' })
        if ($releasedMalware.Count -gt 0) {
            Add-ExoFinding $result -Check 'Released malware / high-confidence phish' -Status Warning -Severity High `
                -Detail "$($releasedMalware.Count) malware or high-confidence phishing messages were released from quarantine." `
                -Recommendation 'Review who released them; restrict release with quarantine policies (AdminOnlyAccessPolicy).'
        }
    }
}

#endregion

#region Admin and application access

$appRoles = Invoke-ExoSafe { Get-ManagementRoleAssignment -RoleAssigneeType ServicePrincipal } 'RBAC for Applications assignments'
if ($null -ne $appRoles -and @($appRoles).Count -gt 0) {
    $result.Data['AppRoleAssignments'] = @($appRoles | ConvertTo-ExoFlatObject -Property Name, Role, RoleAssignee, CustomResourceScope, RecipientWriteScope, Enabled)
    Add-ExoFinding $result -Check 'RBAC for Applications' -Status Info `
        -Detail "$(@($appRoles).Count) Exchange role assignments to service principals." `
        -Recommendation 'Confirm each app needs its role and that a management scope limits it to the mailboxes it should reach.'
}

$appPolicies = Invoke-ExoSafe { Get-ApplicationAccessPolicy } 'application access policies'
if ($null -ne $appPolicies -and @($appPolicies).Count -gt 0) {
    $result.Data['ApplicationAccessPolicies'] = @($appPolicies | ConvertTo-ExoFlatObject -Property AppId, ScopeName, AccessRight, Description)
    Add-ExoFinding $result -Check 'Application access policies (legacy)' -Status Info `
        -Detail "$(@($appPolicies).Count) legacy application access policies." `
        -Recommendation 'Plan migration to RBAC for Applications (management scopes + service principal role assignments).'
}

#endregion

#region Mailbox-level checks (opt-in)

if ($IncludeMailboxLevelChecks) {
    $mbx = Invoke-ExoSafe { Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward } 'mailbox forwarding'
    if ($null -ne $mbx) {
        $forwarding = @($mbx | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | ForEach-Object {
                $smtp = "$($_.ForwardingSmtpAddress)"
                [pscustomobject]@{
                    Mailbox               = $_.UserPrincipalName
                    ForwardingSmtpAddress = $smtp
                    ForwardingAddress     = "$($_.ForwardingAddress)"
                    KeepCopy              = $_.DeliverToMailboxAndForward
                    External              = [bool]($smtp -and (Test-ExoExternalAddress -Address $smtp -AcceptedDomains $accepted))
                }
            })
        $result.Data['MailboxForwarding'] = $forwarding
        $external = @($forwarding | Where-Object External)
        if ($external.Count -gt 0) {
            Add-ExoFinding $result -Check 'Mailboxes forwarding externally' -Status Fail -Severity High `
                -Detail "$($external.Count) mailboxes forward to external addresses: $(($external | Select-Object -First 10 | ForEach-Object { "$($_.Mailbox) -> $($_.ForwardingSmtpAddress)" }) -join '; ')." `
                -Recommendation 'Confirm business justification; remove with Set-Mailbox -ForwardingSmtpAddress $null.'
        }
        else {
            Add-ExoFinding $result -Check 'Mailboxes forwarding externally' -Status Pass -Detail "$($forwarding.Count) mailboxes forward internally; none externally."
        }
    }

    $cas = Invoke-ExoSafe { Get-EXOCASMailbox -ResultSize Unlimited -Properties SmtpClientAuthenticationDisabled, PopEnabled, ImapEnabled } 'CAS mailbox settings'
    if ($null -ne $cas) {
        $smtpOn = @($cas | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false })
        $result.Data['SmtpAuthEnabledMailboxes'] = @($smtpOn | ConvertTo-ExoFlatObject -Property PrimarySmtpAddress, SmtpClientAuthenticationDisabled)
        Add-ExoFinding $result -Check 'SMTP AUTH per-mailbox exceptions' -Status Info `
            -Detail "$($smtpOn.Count) mailboxes explicitly allow SMTP AUTH. POP enabled: $(@($cas | Where-Object PopEnabled).Count); IMAP enabled: $(@($cas | Where-Object ImapEnabled).Count)." `
            -Recommendation 'Disable POP/IMAP via CAS mailbox plans for users who do not need them.'
    }

    $bypass = Invoke-ExoSafe { Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object AuditBypassEnabled } 'audit bypass'
    if ($null -ne $bypass -and @($bypass).Count -gt 0) {
        $result.Data['AuditBypass'] = @($bypass | ConvertTo-ExoFlatObject -Property Name, AuditBypassEnabled)
        Add-ExoFinding $result -Check 'Mailbox audit bypass' -Status Warning -Severity Medium `
            -Detail "$(@($bypass).Count) accounts bypass mailbox audit logging: $((@($bypass) | ForEach-Object { $_.Name }) -join ', ')." `
            -Recommendation 'Remove bypass unless it is a documented high-volume service account.'
    }

    if ($IncludeInboxRules -and $null -ne $mbx) {
        $ruleRows = New-Object System.Collections.Generic.List[object]
        $users = @($mbx | Where-Object { "$($_.RecipientTypeDetails)" -in 'UserMailbox', 'SharedMailbox' })
        $i = 0
        foreach ($m in $users) {
            $i++
            Write-Progress -Activity 'Reading inbox rules' -Status $m.UserPrincipalName -PercentComplete (100 * $i / [math]::Max(1, $users.Count))
            $inboxRules = Invoke-ExoSafe { Get-InboxRule -Mailbox $m.UserPrincipalName -ErrorAction Stop } "inbox rules for $($m.UserPrincipalName)" -Default @()
            foreach ($r in @($inboxRules)) {
                if ($null -eq $r -or -not $r.Enabled) { continue }
                $targets = @(@($r.ForwardTo) + @($r.ForwardAsAttachmentTo) + @($r.RedirectTo) | Where-Object { $_ } | ForEach-Object {
                        # Inbox rule targets look like: "Name" [SMTP:user@domain]
                        if ("$_" -match 'SMTP:([^\]]+)') { $Matches[1] } else { "$_" }
                    })
                $external = @($targets | Where-Object { Test-ExoExternalAddress -Address $_ -AcceptedDomains $accepted })
                $hides = $r.DeleteMessage -or $r.MarkAsRead -or ("$($r.MoveToFolder)" -match 'RSS|Archive|Conversation History|Deleted Items')
                if ($external.Count -gt 0 -or ($hides -and $r.From)) {
                    $ruleRows.Add([pscustomobject]@{
                            Mailbox        = $m.UserPrincipalName
                            Rule           = $r.Name
                            ExternalTarget = $external -join '; '
                            MoveToFolder   = "$($r.MoveToFolder)"
                            DeleteMessage  = $r.DeleteMessage
                            MarkAsRead     = $r.MarkAsRead
                        })
                }
            }
        }
        Write-Progress -Activity 'Reading inbox rules' -Completed
        $result.Data['SuspiciousInboxRules'] = $ruleRows.ToArray()
        $ext = @($ruleRows | Where-Object ExternalTarget)
        if ($ext.Count -gt 0) {
            Add-ExoFinding $result -Check 'Inbox rules forwarding externally' -Status Fail -Severity High `
                -Detail "$($ext.Count) inbox rules forward or redirect externally." `
                -Recommendation 'Investigate as possible business email compromise; see SuspiciousInboxRules.'
        }
        else {
            Add-ExoFinding $result -Check 'Inbox rules forwarding externally' -Status Pass -Detail 'No enabled inbox rules forward externally.'
        }
    }
}
else {
    Add-ExoFinding $result -Check 'Mailbox-level checks' -Status Info -Detail 'Skipped.' `
        -Recommendation 'Re-run with -IncludeMailboxLevelChecks (and optionally -IncludeInboxRules) for per-mailbox forwarding, SMTP AUTH and audit bypass.'
}

#endregion

if ($OutputPath) { Export-ExoSectionResult -Result $result -OutputPath $OutputPath }
$result
