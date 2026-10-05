<#
.SYNOPSIS
    Fake Exchange Online cmdlets returning a deliberately misconfigured lab tenant.

.DESCRIPTION
    Dot-source this file to exercise the report scripts without a tenant (used by
    Invoke-SmokeTest.ps1, and handy in training for reading the code paths). Each stub returns
    data designed to trigger specific findings, noted in comments.
#>

$global:ExoStubNow = Get-Date

function global:Get-OrganizationConfig {
    [pscustomobject]@{
        DisplayName = 'Contoso Lab'; Name = 'contoso.onmicrosoft.com'; Identity = 'contoso.onmicrosoft.com'
        IsDehydrated = $false; OAuth2ClientProfileEnabled = $true; AuditDisabled = $false
        DefaultAuthenticationPolicy = $null; MailTipsAllTipsEnabled = $true
        MailTipsExternalRecipientsTipsEnabled = $false          # -> Warning
        CustomerLockBoxEnabled = $false; RejectDirectSend = $false  # -> Warning
        EwsEnabled = $null; FocusedInboxOn = $true; ActivityBasedAuthenticationTimeoutEnabled = $true
        WhenCreated = $global:ExoStubNow.AddYears(-4)
    }
}

function global:Get-AcceptedDomain {
    @(
        [pscustomobject]@{ DomainName = 'contoso.com'; DomainType = 'Authoritative'; Default = $true; MatchSubDomains = $false; AuthenticationType = 'Managed'; SendingFromDomainDisabled = $false; InitialDomain = $false }
        [pscustomobject]@{ DomainName = 'contoso.onmicrosoft.com'; DomainType = 'Authoritative'; Default = $false; MatchSubDomains = $false; AuthenticationType = 'Managed'; SendingFromDomainDisabled = $false; InitialDomain = $true }
        [pscustomobject]@{ DomainName = 'fabrikam.com'; DomainType = 'InternalRelay'; Default = $false; MatchSubDomains = $false; AuthenticationType = 'Managed'; SendingFromDomainDisabled = $false; InitialDomain = $false }
    )
}

function global:Get-RemoteDomain {
    [pscustomobject]@{ Name = 'Default'; DomainName = '*'; AutoForwardEnabled = $true; AutoReplyEnabled = $true; DeliveryReportEnabled = $true; NDREnabled = $true; TNEFEnabled = $null; AllowedOOFType = 'External'; CharacterSet = $null }
}

function global:Get-EXORecipient {
    $types = 'UserMailbox', 'UserMailbox', 'UserMailbox', 'SharedMailbox', 'MailUniversalDistributionGroup', 'GroupMailbox', 'MailContact'
    foreach ($i in 1..70) { [pscustomobject]@{ Name = "r$i"; RecipientTypeDetails = $types[$i % $types.Count] } }
}

function global:Get-EXOMailbox {
    if ($args -contains '-InactiveMailboxOnly') { return @([pscustomobject]@{ UserPrincipalName = 'leaver@contoso.com' }) }
    @(
        [pscustomobject]@{ UserPrincipalName = 'adele@contoso.com'; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $true; ArchiveStatus = 'Active'; RetentionPolicy = 'Default MRM Policy'; ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverToMailboxAndForward = $false }
        [pscustomobject]@{ UserPrincipalName = 'ben@contoso.com'; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $false; ArchiveStatus = 'None'; RetentionPolicy = 'Default MRM Policy'; ForwardingSmtpAddress = 'smtp:ben.private@gmail.com'; ForwardingAddress = $null; DeliverToMailboxAndForward = $true }   # -> external forwarding
        [pscustomobject]@{ UserPrincipalName = 'carol@contoso.com'; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $false; ArchiveStatus = 'None'; RetentionPolicy = 'Default MRM Policy'; ForwardingSmtpAddress = 'smtp:dave@contoso.com'; ForwardingAddress = $null; DeliverToMailboxAndForward = $true }
        [pscustomobject]@{ UserPrincipalName = 'info@contoso.com'; RecipientTypeDetails = 'SharedMailbox'; LitigationHoldEnabled = $false; ArchiveStatus = 'None'; RetentionPolicy = $null; ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverToMailboxAndForward = $false }
        [pscustomobject]@{ UserPrincipalName = 'room1@contoso.com'; RecipientTypeDetails = 'RoomMailbox'; LitigationHoldEnabled = $false; ArchiveStatus = 'None'; RetentionPolicy = $null; ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverToMailboxAndForward = $false }
    )
}

function global:Get-RoleGroupMember {
    foreach ($n in 'admin', 'alex', 'sam', 'jo', 'kim', 'lee', 'pat') {   # 7 members -> Warning
        [pscustomobject]@{ Name = $n; DisplayName = $n; RecipientType = 'UserMailbox'; PrimarySmtpAddress = "$n@contoso.com" }
    }
}

function global:Get-InboundConnector {
    @(
        # Partner connector, no IP/cert restriction, all domains, no TLS -> Fail High + Warning
        [pscustomobject]@{ Name = 'From Fabrikam partner'; Enabled = $true; ConnectorType = 'Partner'; ConnectorSource = 'Default'
            SenderDomains = @('smtp:*;1'); SenderIPAddresses = @('203.0.113.10'); RestrictDomainsToIPAddresses = $false; RestrictDomainsToCertificate = $false
            RequireTls = $false; TlsSenderCertificateName = $null; CloudServicesMailEnabled = $false; TreatMessagesAsInternal = $false
            EFSkipLastIP = $false; EFSkipIPs = @(); EFUsers = @(); EFTestMode = $false; ScanAndDropRecipients = @(); AssociatedAcceptedDomains = @(); WhenChanged = $global:ExoStubNow.AddDays(-400) }
        [pscustomobject]@{ Name = 'Inbound from contoso-onprem'; Enabled = $true; ConnectorType = 'OnPremises'; ConnectorSource = 'HybridWizard'
            SenderDomains = @('smtp:*;1'); SenderIPAddresses = @(); RestrictDomainsToIPAddresses = $false; RestrictDomainsToCertificate = $false
            RequireTls = $true; TlsSenderCertificateName = 'mail.contoso.com'; CloudServicesMailEnabled = $true; TreatMessagesAsInternal = $false
            EFSkipLastIP = $true; EFSkipIPs = @(); EFUsers = @(); EFTestMode = $false; ScanAndDropRecipients = @(); AssociatedAcceptedDomains = @(); WhenChanged = $global:ExoStubNow.AddDays(-30) }
    )
}

function global:Get-OutboundConnector {
    @(
        [pscustomobject]@{ Name = 'Outbound to contoso-onprem'; Enabled = $true; ConnectorType = 'OnPremises'; ConnectorSource = 'HybridWizard'
            RecipientDomains = @('contoso.com'); SmartHosts = @('mail.contoso.com'); UseMXRecord = $false; TlsSettings = 'DomainValidation'; TlsDomain = 'mail.contoso.com'
            IsTransportRuleScoped = $false; RouteAllMessagesViaOnPremises = $false; AllAcceptedDomains = $false; CloudServicesMailEnabled = $true
            IsValidated = $true; LastValidationTimestamp = $global:ExoStubNow.AddDays(-200); SenderRewritingEnabled = $false; TestMode = $false; WhenChanged = $global:ExoStubNow.AddDays(-30) }
        # Egress via third party with opportunistic TLS, never validated -> Warnings
        [pscustomobject]@{ Name = 'Egress via filtering service'; Enabled = $true; ConnectorType = 'Partner'; ConnectorSource = 'Default'
            RecipientDomains = @('*'); SmartHosts = @('outbound.filter.example.net'); UseMXRecord = $false; TlsSettings = $null; TlsDomain = $null
            IsTransportRuleScoped = $false; RouteAllMessagesViaOnPremises = $false; AllAcceptedDomains = $false; CloudServicesMailEnabled = $false
            IsValidated = $false; LastValidationTimestamp = $null; SenderRewritingEnabled = $false; TestMode = $false; WhenChanged = $global:ExoStubNow.AddDays(-90) }
    )
}

function global:Get-OnPremisesOrganization {
    [pscustomobject]@{ Name = 'contoso-onprem'; OrganizationName = 'Contoso'; OrganizationGuid = [guid]::NewGuid(); HybridDomains = @('contoso.com')
        InboundConnector = 'Inbound from contoso-onprem'; OutboundConnector = 'Outbound to old-onprem'   # -> missing connector reference
        OrganizationRelationship = 'O365 to On-premises'; WhenChanged = $global:ExoStubNow.AddDays(-30) }
}

function global:Get-OrganizationRelationship {
    [pscustomobject]@{ Name = 'O365 to On-premises'; Enabled = $true; DomainNames = @('contoso.com'); FreeBusyAccessEnabled = $true
        FreeBusyAccessLevel = 'LimitedDetails'; FreeBusyAccessScope = $null; MailboxMoveEnabled = $true; MailboxMoveCapability = 'RemoteInbound'
        DeliveryReportEnabled = $true; MailTipsAccessEnabled = $true; MailTipsAccessLevel = 'All'; ArchiveAccessEnabled = $true
        TargetApplicationUri = 'FYDIBOHF25SPDLT.contoso.com'; TargetAutodiscoverEpr = 'https://autodiscover.contoso.com/autodiscover/autodiscover.svc/WSSecurity'
        TargetSharingEpr = $null; OrganizationContact = $null }
}

function global:Get-IntraOrganizationConnector {
    [pscustomobject]@{ Name = 'HybridIOC'; Enabled = $true; TargetAddressDomains = @('contoso.com'); DiscoveryEndpoint = 'https://autodiscover.contoso.com/autodiscover/autodiscover.svc'; TargetSharingEpr = $null }
}

function global:Get-MigrationEndpoint {
    [pscustomobject]@{ Identity = 'Hybrid Migration Endpoint - EWS'; EndpointType = 'ExchangeRemoteMove'; RemoteServer = 'mail.contoso.com'; ExchangeServer = $null
        MaxConcurrentMigrations = 20; MaxConcurrentIncrementalSyncs = 10; IsRemote = $true; Username = 'CONTOSO\svc-mig' }
}

function global:Get-MessageTraceV2 {
    [CmdletBinding()]
    param([datetime] $StartDate, [datetime] $EndDate, [int] $ResultSize = 1000, [string] $StartingRecipientAddress)
    # 400 rows: 360 delivered, 30 failed (7.5% -> Fail), 6 quarantined, 4 spam.
    $rng = New-Object System.Random 42
    $span = ($EndDate - $StartDate).TotalMinutes
    foreach ($i in 1..400) {
        $status = if ($i -le 30) { 'Failed' } elseif ($i -le 36) { 'Quarantined' } elseif ($i -le 40) { 'FilteredAsSpam' } else { 'Delivered' }
        $inbound = $i % 3 -eq 0
        [pscustomobject]@{
            Received         = $StartDate.AddMinutes($rng.NextDouble() * $span)
            SenderAddress    = if ($inbound) { "news$($i % 7)@partner$($i % 4).example" } else { "user$($i % 9)@contoso.com" }
            RecipientAddress = if ($inbound) { "user$($i % 9)@contoso.com" } elseif ($status -eq 'Failed') { "someone@bad$($i % 3).example" } else { "client$($i % 11)@customer.example" }
            Subject          = "Message $i"
            Status           = $status
            Size             = 20000 + $i
            FromIP           = '198.51.100.20'
            ToIP             = $null
            MessageTraceId   = [guid]::NewGuid()
        }
    }
}

function global:Get-MailflowStatusReport {
    foreach ($dir in 'Inbound', 'Outbound') {
        foreach ($evt in 'GoodMail', 'SpamDetections', 'Malware') {
            [pscustomobject]@{ Date = $global:ExoStubNow.Date; Direction = $dir; EventType = $evt; MessageCount = 10 }
        }
    }
}

function global:Get-TransportRule {
    @(
        # Spam bypass keyed on spoofable sender domain -> Fail High
        [pscustomobject]@{ Priority = 0; Name = 'Whitelist payroll vendor'; State = 'Enabled'; Mode = 'Enforce'; SetSCL = '-1'
            SenderDomainIs = @('payroll.example'); FromAddressContainsWords = @(); SenderIpRanges = @(); HeaderContainsMessageHeader = $null
            RedirectMessageTo = @(); BlindCopyTo = @(); AddToRecipients = @(); CopyTo = @(); RouteMessageOutboundConnector = $null
            SetHeaderName = $null; SetHeaderValue = $null; ActivationDate = $null; ExpiryDate = $null; Comments = ''; WhenChanged = $global:ExoStubNow.AddDays(-700) }
        # BCC to an external address -> Fail High
        [pscustomobject]@{ Priority = 1; Name = 'Copy CFO mail'; State = 'Enabled'; Mode = 'Enforce'; SetSCL = $null
            SenderDomainIs = @(); FromAddressContainsWords = @(); SenderIpRanges = @(); HeaderContainsMessageHeader = $null
            RedirectMessageTo = @(); BlindCopyTo = @('archive@outside-collector.example'); AddToRecipients = @(); CopyTo = @(); RouteMessageOutboundConnector = $null
            SetHeaderName = $null; SetHeaderValue = $null; ActivationDate = $null; ExpiryDate = $null; Comments = ''; WhenChanged = $global:ExoStubNow.AddDays(-3) }
        # Routes to a connector that does not exist, in test mode, expired
        [pscustomobject]@{ Priority = 2; Name = 'Route legal via encryption gateway'; State = 'Enabled'; Mode = 'Audit'; SetSCL = $null
            SenderDomainIs = @(); FromAddressContainsWords = @(); SenderIpRanges = @(); HeaderContainsMessageHeader = $null
            RedirectMessageTo = @(); BlindCopyTo = @(); AddToRecipients = @(); CopyTo = @(); RouteMessageOutboundConnector = 'Encryption gateway'
            SetHeaderName = $null; SetHeaderValue = $null; ActivationDate = $null; ExpiryDate = $global:ExoStubNow.AddDays(-10); Comments = ''; WhenChanged = $global:ExoStubNow.AddDays(-60) }
        [pscustomobject]@{ Priority = 3; Name = 'Disclaimer'; State = 'Disabled'; Mode = 'Enforce'; SetSCL = $null
            SenderDomainIs = @(); FromAddressContainsWords = @(); SenderIpRanges = @(); HeaderContainsMessageHeader = $null
            RedirectMessageTo = @(); BlindCopyTo = @(); AddToRecipients = @(); CopyTo = @(); RouteMessageOutboundConnector = $null
            SetHeaderName = $null; SetHeaderValue = $null; ActivationDate = $null; ExpiryDate = $null; Comments = ''; WhenChanged = $global:ExoStubNow.AddDays(-900) }
    )
}

function global:Get-TransportConfig {
    [pscustomobject]@{ MaxSendSize = '35 MB'; MaxReceiveSize = '36 MB'; MaxRecipientEnvelopeLimit = 500; ExternalPostmasterAddress = $null
        JournalingReportNdrTo = '<>'                         # -> journaling NDR Fail
        SmtpClientAuthenticationDisabled = $false            # -> Warning
        AllowLegacyTLSClients = $false; ReplyAllStormProtectionEnabled = $true; ReplyAllStormDetectionMinimumRecipients = 2500
        AddressBookPolicyRoutingEnabled = $false; ConvertDisclaimerWrapperToEml = $false; InternalDsnSendHtml = $true; ExternalDsnSendHtml = $true }
}

function global:Get-JournalRule {
    [pscustomobject]@{ Name = 'Journal all'; Enabled = $true; Scope = 'Global'; Recipient = $null; JournalEmailAddress = 'journal@archive.example' }
}

function global:Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = $true } }

function global:Get-AuthenticationPolicy {
    [pscustomobject]@{ Name = 'Block Basic Auth'; AllowBasicAuthSmtp = $false; AllowBasicAuthPop = $false; AllowBasicAuthImap = $false; AllowBasicAuthWebServices = $false; AllowBasicAuthPowershell = $false; WhenChanged = $global:ExoStubNow.AddDays(-300) }
}

function global:Get-ExternalInOutlook { [pscustomobject]@{ Identity = 'contoso'; Enabled = $false } }

function global:Get-HostedOutboundSpamFilterPolicy {
    [pscustomobject]@{ Name = 'Default'; IsDefault = $true; AutoForwardingMode = 'Automatic'; RecipientLimitExternalPerHour = 0; RecipientLimitInternalPerHour = 0
        RecipientLimitPerDay = 0; ActionWhenThresholdReached = 'BlockUserForToday'; NotifyOutboundSpam = $false; NotifyOutboundSpamRecipients = @(); BccSuspiciousOutboundMail = $false }
}

function global:Get-BlockedSenderAddress { [pscustomobject]@{ SenderAddress = 'eve@contoso.com'; Reason = 'Outbound spam'; CreatedDatetime = $global:ExoStubNow.AddHours(-5) } }

function global:Get-HostedContentFilterPolicy {
    [pscustomobject]@{ Name = 'Default'; IsDefault = $true; BulkThreshold = 7; SpamAction = 'MoveToJmf'; HighConfidenceSpamAction = 'MoveToJmf'
        PhishSpamAction = 'MoveToJmf'; HighConfidencePhishAction = 'Quarantine'; BulkSpamAction = 'MoveToJmf'; QuarantineRetentionPeriod = 30
        InlineSafetyTipsEnabled = $true; ZapEnabled = $true; SpamZapEnabled = $true; PhishZapEnabled = $true
        AllowedSenderDomains = @('partner.example'); AllowedSenders = @(); BlockedSenderDomains = @() }   # -> allowed domain Fail
}

function global:Get-HostedConnectionFilterPolicy { [pscustomobject]@{ Name = 'Default'; IPAllowList = @('192.0.2.0/24'); IPBlockList = @(); EnableSafeList = $false } }

function global:Get-MalwareFilterPolicy {
    [pscustomobject]@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true; FileTypeAction = 'Reject'; ZapEnabled = $true
        EnableInternalSenderAdminNotifications = $false; InternalSenderAdminAddress = $null; QuarantineTag = 'AdminOnlyAccessPolicy' }
}

function global:Get-AntiPhishPolicy {
    [pscustomobject]@{ Name = 'Office365 AntiPhish Default'; IsDefault = $true; Enabled = $true; EnableSpoofIntelligence = $true; HonorDmarcPolicy = $true
        EnableUnauthenticatedSender = $true; EnableViaTag = $true; EnableFirstContactSafetyTips = $false; PhishThresholdLevel = 1
        EnableMailboxIntelligence = $true; EnableMailboxIntelligenceProtection = $false; EnableTargetedUserProtection = $false
        EnableOrganizationDomainsProtection = $false; EnableTargetedDomainsProtection = $false; TargetedUsersToProtect = @() }
}

function global:Get-SafeLinksPolicy {
    [pscustomobject]@{ Name = 'Built-In Protection Policy'; IsBuiltInProtection = $true; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true
        EnableSafeLinksForOffice = $true; ScanUrls = $true; DeliverMessageAfterScan = $true; EnableForInternalSenders = $false; TrackClicks = $true
        AllowClickThrough = $false; DisableUrlRewrite = $true }
}

function global:Get-SafeAttachmentPolicy { [pscustomobject]@{ Name = 'Built-In Protection Policy'; IsBuiltInProtection = $true; Enable = $true; Action = 'Block'; QuarantineTag = 'AdminOnlyAccessPolicy'; Redirect = $false; RedirectAddress = $null } }
function global:Get-AtpPolicyForO365 { [pscustomobject]@{ EnableATPForSPOTeamsODB = $false; EnableSafeDocs = $false } }
function global:Get-ATPBuiltInProtectionRule { [pscustomobject]@{ Identity = 'ATP Built-In Protection Rule'; State = 'Enabled' } }
function global:Get-EOPProtectionPolicyRule { [pscustomobject]@{ Identity = 'Standard Preset Security Policy'; State = 'Disabled'; Priority = 1; SentTo = @(); SentToMemberOf = @(); RecipientDomainIs = @(); ExceptIfSentTo = @() } }
function global:Get-ATPProtectionPolicyRule { [pscustomobject]@{ Identity = 'Standard Preset Security Policy'; State = 'Disabled'; Priority = 1; SentTo = @(); SentToMemberOf = @(); RecipientDomainIs = @(); ExceptIfSentTo = @() } }

function global:Get-TenantAllowBlockListItems {
    $listType = $args[([array]::IndexOf($args, '-ListType')) + 1]
    if ($listType -eq 'Sender') {
        [pscustomobject]@{ Value = 'newsletter@vendor.example'; Action = 'Allow'; ExpirationDate = $null; LastUsedDate = $global:ExoStubNow.AddDays(-200); Notes = 'ticket 1234' }
    }
}

function global:Get-QuarantineMessage {
    if ($args -contains 2) { return }   # single page
    foreach ($i in 1..12) {
        [pscustomobject]@{ QuarantineTypes = if ($i -le 2) { 'Malware' } elseif ($i -le 6) { 'Phish' } else { 'Spam' }
            ReleaseStatus = if ($i -eq 1) { 'RELEASED' } else { 'NOTRELEASED' }; ReceivedTime = $global:ExoStubNow.AddDays(-1) }
    }
}

function global:Get-ManagementRoleAssignment {
    [pscustomobject]@{ Name = 'Mail.Send-Notifier'; Role = 'Application Mail.Send'; RoleAssignee = 'sp-notifier'; CustomResourceScope = $null; RecipientWriteScope = 'Organization'; Enabled = $true }
}
function global:Get-ApplicationAccessPolicy { }

function global:Get-EXOCASMailbox {
    [pscustomobject]@{ PrimarySmtpAddress = 'scanner@contoso.com'; SmtpClientAuthenticationDisabled = $false; PopEnabled = $true; ImapEnabled = $true }
    [pscustomobject]@{ PrimarySmtpAddress = 'adele@contoso.com'; SmtpClientAuthenticationDisabled = $null; PopEnabled = $false; ImapEnabled = $false }
}

function global:Get-MailboxAuditBypassAssociation { [pscustomobject]@{ Name = 'svc-backup'; AuditBypassEnabled = $true } }

function global:Get-InboxRule {
    if ($args -contains 'ben@contoso.com') {
        [pscustomobject]@{ Name = '.'; Enabled = $true; ForwardTo = @('"x" [SMTP:collector@evil.example]'); ForwardAsAttachmentTo = $null; RedirectTo = $null
            DeleteMessage = $false; MarkAsRead = $true; MoveToFolder = 'RSS Feeds'; From = $null }
    }
}

function global:Get-DkimSigningConfig {
    @(
        [pscustomobject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'; Selector1CNAME = 'selector1-contoso-com._domainkey.contoso.n-v1.dkim.mail.microsoft'
            Selector2CNAME = 'selector2-contoso-com._domainkey.contoso.n-v1.dkim.mail.microsoft'; Selector1KeySize = 1024; Selector2KeySize = 2048; RotateOnDate = $global:ExoStubNow.AddDays(-10); LastChecked = $global:ExoStubNow }
        [pscustomobject]@{ Domain = 'contoso.onmicrosoft.com'; Enabled = $true; Status = 'Valid'; Selector1CNAME = $null; Selector2CNAME = $null; Selector1KeySize = 2048; Selector2KeySize = 2048; RotateOnDate = $null; LastChecked = $global:ExoStubNow }
    )
}

# Fake DNS (replaces Resolve-DnsName so DNS checks run offline and deterministically).
$global:ExoStubDns = @{
    'MX|contoso.com'                       = @(@{ NameExchange = 'contoso-com.mail.protection.outlook.com'; Preference = 0 })
    'TXT|contoso.com'                      = @(@{ Strings = @('v=spf1 include:spf.protection.outlook.com include:_spf.vendor.example ~all') }, @{ Strings = @('MS=ms12345678') })
    'TXT|_spf.vendor.example'              = @(@{ Strings = @('v=spf1 a mx include:_spf2.vendor.example -all') })
    'TXT|_spf2.vendor.example'             = @(@{ Strings = @('v=spf1 ip4:192.0.2.0/24 -all') })
    'TXT|_dmarc.contoso.com'               = @(@{ Strings = @('v=DMARC1; p=none; rua=mailto:dmarc@contoso.com') })
    'CNAME|selector1._domainkey.contoso.com' = @(@{ NameHost = 'selector1-contoso-com._domainkey.contoso.n-v1.dkim.mail.microsoft' })
    'MX|fabrikam.com'                      = @(@{ NameExchange = 'mx1.thirdparty-filter.example'; Preference = 10 })
    'TXT|fabrikam.com'                     = @(@{ Strings = @('v=spf1 +all') }, @{ Strings = @('v=spf1 include:spf.protection.outlook.com -all') })
}

function global:Resolve-DnsName {
    [CmdletBinding()]
    param([string] $Name, [string] $Type, [switch] $DnsOnly)
    if ($Name -like '*broken.example') { throw "$Name : This operation returned because the timeout period expired" }   # resolver failure
    $entries = $global:ExoStubDns["$Type|$Name"]
    if (-not $entries) { throw "$Name : DNS name does not exist" }
    foreach ($e in $entries) {
        $o = [ordered]@{ Name = $Name; Type = $Type }
        foreach ($k in $e.Keys) { $o[$k] = $e[$k] }
        [pscustomobject]$o
    }
}

function global:Get-ConnectionInformation {
    [pscustomobject]@{ State = 'Connected'; TenantID = '11111111-2222-3333-4444-555555555555'; UserPrincipalName = 'reader@contoso.com' }
}
