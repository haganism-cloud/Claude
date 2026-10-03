#Requires -Version 5.1
<#
.SYNOPSIS
    Collects a baseline inventory of an Exchange Online tenant.

.DESCRIPTION
    Read-only. Reports organisation configuration, accepted and remote domains, recipient counts by
    type, mailbox hold / archive posture, inactive mailboxes and (optionally) Exchange Online service
    health from Microsoft Graph.

    Returns a section result object (Section, Findings, Data). With -OutputPath, also writes CSVs.

.PARAMETER OutputPath
    Folder for CSV exports. Omit to only return the result object.

.PARAMETER SkipRecipientCounts
    Skips the Get-EXORecipient / Get-EXOMailbox enumeration (slow in tenants with 100k+ objects).

.EXAMPLE
    .\Get-ExoTenantOverview.ps1 -OutputPath .\out | Select-Object -ExpandProperty Findings | Format-Table
#>
[CmdletBinding()]
param(
    [string] $OutputPath,
    [switch] $SkipRecipientCounts
)

. (Join-Path $PSScriptRoot 'ExoHealth.Common.ps1')
Assert-ExoConnection

$result = New-ExoSectionResult -Section 'Tenant Overview'

#region Organisation configuration

$org = Invoke-ExoSafe { Get-OrganizationConfig } 'organization config' -Single
if ($org) {
    $result.Data['OrganizationConfig'] = @($org | ConvertTo-ExoFlatObject -Property DisplayName, Name, Identity,
        IsDehydrated, OAuth2ClientProfileEnabled, AuditDisabled, DefaultAuthenticationPolicy,
        MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, CustomerLockBoxEnabled,
        RejectDirectSend, EwsEnabled, FocusedInboxOn, ActivityBasedAuthenticationTimeoutEnabled,
        WhenCreated)

    Add-ExoFinding $result -Check 'Tenant identity' -Status Info -Target $org.DisplayName `
        -Detail "Organisation: $($org.Name). Created: $(ConvertTo-ExoFlatValue (Get-ExoPropertyValue $org 'WhenCreated'))."

    if (Get-ExoPropertyValue $org 'IsDehydrated' $false) {
        Add-ExoFinding $result -Check 'Organisation customisation' -Status Info -Target $org.Name `
            -Detail 'The tenant is dehydrated: some objects (custom role groups, retention policies) cannot be created yet.' `
            -Recommendation 'Run Enable-OrganizationCustomization once before creating custom RBAC role groups or policies.'
    }

    $mailTips = Get-ExoPropertyValue $org 'MailTipsExternalRecipientsTipsEnabled' $null
    if ($mailTips -eq $false) {
        Add-ExoFinding $result -Check 'External recipient MailTips' -Status Warning -Severity Low -Target $org.Name `
            -Detail 'Users are not warned when they address external recipients.' `
            -Recommendation 'Set-OrganizationConfig -MailTipsExternalRecipientsTipsEnabled $true'
    }
    elseif ($mailTips -eq $true) {
        Add-ExoFinding $result -Check 'External recipient MailTips' -Status Pass -Target $org.Name -Detail 'Enabled.'
    }
}

#endregion

#region Domains

$accepted = Invoke-ExoSafe { Get-AcceptedDomain } 'accepted domains'
if ($null -ne $accepted) {
    $result.Data['AcceptedDomains'] = @($accepted | ConvertTo-ExoFlatObject -Property DomainName, DomainType, Default,
        MatchSubDomains, AuthenticationType, SendingFromDomainDisabled, InitialDomain)

    $relay = @($accepted | Where-Object DomainType -eq 'InternalRelay')
    $authoritative = @($accepted | Where-Object DomainType -eq 'Authoritative')
    Add-ExoFinding $result -Check 'Accepted domains' -Status Info `
        -Detail "$(@($accepted).Count) accepted domains: $($authoritative.Count) Authoritative, $($relay.Count) InternalRelay."

    foreach ($d in $relay) {
        Add-ExoFinding $result -Check 'InternalRelay domain' -Status Info -Target $d.DomainName `
            -Detail 'Mail for unknown recipients in this domain is relayed via an outbound connector instead of being rejected by Directory-Based Edge Blocking.' `
            -Recommendation 'Switch to Authoritative once all recipients exist in Exchange Online, so DBEB rejects mail to non-existent addresses.'
    }
}

$remote = Invoke-ExoSafe { Get-RemoteDomain } 'remote domains'
if ($null -ne $remote) {
    $result.Data['RemoteDomains'] = @($remote | ConvertTo-ExoFlatObject -Property Name, DomainName, AutoForwardEnabled,
        AutoReplyEnabled, DeliveryReportEnabled, NDREnabled, TNEFEnabled, AllowedOOFType, CharacterSet)
}

#endregion

#region Recipients and mailboxes

if (-not $SkipRecipientCounts) {
    $recipients = Invoke-ExoSafe { Get-EXORecipient -ResultSize Unlimited -Properties RecipientTypeDetails } 'recipients'
    if ($null -ne $recipients) {
        $byType = @($recipients | Group-Object RecipientTypeDetails | Sort-Object Count -Descending |
            ForEach-Object { [pscustomobject]@{ RecipientTypeDetails = $_.Name; Count = $_.Count } })
        $result.Data['RecipientCounts'] = $byType
        Add-ExoFinding $result -Check 'Recipient inventory' -Status Info `
            -Detail ("{0} recipients. {1}" -f @($recipients).Count, (($byType | Select-Object -First 6 |
                ForEach-Object { "$($_.RecipientTypeDetails): $($_.Count)" }) -join ', '))
    }

    $mailboxProps = 'LitigationHoldEnabled', 'ArchiveStatus', 'RetentionPolicy', 'RecipientTypeDetails'
    $mailboxes = Invoke-ExoSafe { Get-EXOMailbox -ResultSize Unlimited -Properties $mailboxProps } 'mailboxes'
    if ($null -ne $mailboxes) {
        $user = @($mailboxes | Where-Object RecipientTypeDetails -eq 'UserMailbox')
        $onHold = @($user | Where-Object LitigationHoldEnabled).Count
        $archived = @($user | Where-Object { "$($_.ArchiveStatus)" -eq 'Active' }).Count
        $summary = [pscustomobject]@{
            UserMailboxes          = $user.Count
            SharedMailboxes        = @($mailboxes | Where-Object RecipientTypeDetails -eq 'SharedMailbox').Count
            RoomMailboxes          = @($mailboxes | Where-Object RecipientTypeDetails -eq 'RoomMailbox').Count
            EquipmentMailboxes     = @($mailboxes | Where-Object RecipientTypeDetails -eq 'EquipmentMailbox').Count
            UserMailboxesOnLitHold = $onHold
            UserMailboxesArchived  = $archived
        }
        $result.Data['MailboxSummary'] = @($summary)

        $retention = @($user | Group-Object { "$($_.RetentionPolicy)" } |
            ForEach-Object { [pscustomobject]@{ RetentionPolicy = $_.Name; UserMailboxes = $_.Count } })
        $result.Data['MailboxRetentionPolicies'] = $retention

        Add-ExoFinding $result -Check 'Mailbox inventory' -Status Info `
            -Detail ("{0} user, {1} shared, {2} room, {3} equipment mailboxes. {4} on litigation hold, {5} with an archive." -f
                $summary.UserMailboxes, $summary.SharedMailboxes, $summary.RoomMailboxes, $summary.EquipmentMailboxes, $onHold, $archived)
    }

    $inactive = Invoke-ExoSafe { Get-EXOMailbox -InactiveMailboxOnly -ResultSize Unlimited } 'inactive mailboxes'
    if ($null -ne $inactive) {
        Add-ExoFinding $result -Check 'Inactive mailboxes' -Status Info -Detail "$(@($inactive).Count) inactive mailboxes retained by holds."
    }
}

#endregion

#region RBAC overview

$orgMgmt = Invoke-ExoSafe { Get-RoleGroupMember -Identity 'Organization Management' -ResultSize Unlimited } 'Organization Management members'
if ($null -ne $orgMgmt) {
    $result.Data['OrganizationManagementMembers'] = @($orgMgmt | ConvertTo-ExoFlatObject -Property Name, DisplayName, RecipientType, PrimarySmtpAddress)
    $n = @($orgMgmt).Count
    if ($n -gt 5) {
        Add-ExoFinding $result -Check 'Organization Management membership' -Status Warning -Severity Medium `
            -Detail "$n direct members hold full Exchange administration rights." `
            -Recommendation 'Reduce standing admins; use PIM for Entra roles and scoped Exchange role groups for day-to-day work.'
    }
    else {
        Add-ExoFinding $result -Check 'Organization Management membership' -Status Pass -Detail "$n direct members."
    }
}

#endregion

#region Service health (optional, Microsoft Graph)

if ((Test-ExoCommand 'Get-MgServiceAnnouncementHealthOverview') -and (Test-ExoCommand 'Get-MgContext') -and (Get-MgContext)) {
    $health = Invoke-ExoSafe { Get-MgServiceAnnouncementHealthOverview -ServiceHealthOverviewId 'Exchange Online' -ExpandProperty Issues } 'Exchange Online service health' -Single
    if ($health) {
        $open = @($health.Issues | Where-Object { -not $_.IsResolved })
        $result.Data['ServiceHealthOpenIssues'] = @($open | ConvertTo-ExoFlatObject -Property Id, Title, Classification, Status, StartDateTime, Feature, ImpactDescription)
        $status = if ("$($health.Status)" -eq 'serviceOperational') { 'Pass' } else { 'Warning' }
        Add-ExoFinding $result -Check 'Exchange Online service health' -Status $status -Severity Medium `
            -Detail "Service status: $($health.Status). $($open.Count) open issues/advisories." `
            -Recommendation 'Review open incidents in the Microsoft 365 admin center Service health page.'
    }
}
else {
    Add-ExoFinding $result -Check 'Exchange Online service health' -Status Info `
        -Detail 'Skipped: not connected to Microsoft Graph.' `
        -Recommendation 'Run Connect-ExoTenant.ps1 -IncludeGraph to include service health.'
}

#endregion

if ($OutputPath) { Export-ExoSectionResult -Result $result -OutputPath $OutputPath }
$result
