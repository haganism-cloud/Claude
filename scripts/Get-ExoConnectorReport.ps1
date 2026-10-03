#Requires -Version 5.1
<#
.SYNOPSIS
    Audits every Exchange Online connector: inbound / outbound mail connectors, hybrid
    (on-premises organisation, organisation relationships, IntraOrganizationConnector) and
    migration endpoints.

.DESCRIPTION
    Read-only. Flags common connector risks:
      - Partner inbound connectors that are not restricted by IP or certificate (spoofing bypass).
      - On-premises inbound connectors with neither a TLS certificate nor IP addresses.
      - Inbound connectors without Enhanced Filtering when MX points to a third party.
      - Outbound connectors that do not validate the remote TLS certificate.
      - Outbound connectors never validated, or validated more than 90 days ago.
      - Hybrid objects that reference connectors that no longer exist.

    Does NOT run Validate-OutboundConnector (that sends test messages).

.PARAMETER OutputPath
    Folder for CSV exports. Omit to only return the result object.

.EXAMPLE
    .\Get-ExoConnectorReport.ps1 -OutputPath .\out
#>
[CmdletBinding()]
param(
    [string] $OutputPath,
    [int] $ValidationMaxAgeDays = 90
)

. (Join-Path $PSScriptRoot 'ExoHealth.Common.ps1')
Assert-ExoConnection

$result = New-ExoSectionResult -Section 'Connectors'

#region Inbound connectors

$inbound = Invoke-ExoSafe { Get-InboundConnector } 'inbound connectors'
if ($null -ne $inbound) {
    $result.Data['InboundConnectors'] = @($inbound | ConvertTo-ExoFlatObject -Property Name, Enabled, ConnectorType,
        ConnectorSource, SenderDomains, SenderIPAddresses, RestrictDomainsToIPAddresses, RestrictDomainsToCertificate,
        RequireTls, TlsSenderCertificateName, CloudServicesMailEnabled, TreatMessagesAsInternal, EFSkipLastIP,
        EFSkipIPs, EFUsers, EFTestMode, ScanAndDropRecipients, AssociatedAcceptedDomains, WhenChanged)

    if (@($inbound).Count -eq 0) {
        Add-ExoFinding $result -Check 'Inbound connectors' -Status Info `
            -Detail 'No inbound connectors. Mail arrives directly from the internet via EOP (MX -> Exchange Online).'
    }

    foreach ($c in $inbound) {
        $name = $c.Name
        if (-not $c.Enabled) {
            Add-ExoFinding $result -Check 'Inbound connector disabled' -Status Info -Target $name `
                -Detail 'Connector is disabled.' -Recommendation 'Remove connectors that are no longer needed.'
            continue
        }

        $senderIPs = @(Get-ExoPropertyValue $c 'SenderIPAddresses' @())
        $certName = "$(Get-ExoPropertyValue $c 'TlsSenderCertificateName' '')"
        $restrictIP = [bool](Get-ExoPropertyValue $c 'RestrictDomainsToIPAddresses' $false)
        $restrictCert = [bool](Get-ExoPropertyValue $c 'RestrictDomainsToCertificate' $false)
        $requireTls = [bool](Get-ExoPropertyValue $c 'RequireTls' $false)
        $senderDomains = @(Get-ExoPropertyValue $c 'SenderDomains' @()) | ForEach-Object { "$_" }

        if ("$($c.ConnectorType)" -eq 'OnPremises') {
            if (-not $certName -and $senderIPs.Count -eq 0) {
                Add-ExoFinding $result -Check 'On-premises connector identification' -Status Fail -Severity High -Target $name `
                    -Detail 'OnPremises connector has no TlsSenderCertificateName and no SenderIPAddresses, so Exchange Online cannot reliably identify on-premises mail.' `
                    -Recommendation 'Configure certificate-based identification (TlsSenderCertificateName) - re-running the Hybrid Configuration Wizard does this.'
            }
            elseif ($certName) {
                Add-ExoFinding $result -Check 'On-premises connector identification' -Status Pass -Target $name `
                    -Detail "Identified by certificate '$certName'."
            }
            else {
                Add-ExoFinding $result -Check 'On-premises connector identification' -Status Warning -Severity Low -Target $name `
                    -Detail "Identified by IP address only ($($senderIPs -join ', '))." `
                    -Recommendation 'Prefer certificate-based identification; IP-based connectors break when egress IPs change.'
            }
        }
        else {
            # Partner connector
            if (-not $restrictIP -and -not $restrictCert) {
                $sev = if ($senderDomains -contains '*' -or $senderDomains -contains 'smtp:*;1') { 'High' } else { 'Medium' }
                Add-ExoFinding $result -Check 'Partner connector restriction' -Status Fail -Severity $sev -Target $name `
                    -Detail "Partner connector for sender domains '$($senderDomains -join ', ')' does not reject mail from other IPs or certificates. Anyone can spoof these domains to match the connector." `
                    -Recommendation 'Set RestrictDomainsToIPAddresses or RestrictDomainsToCertificate (with TlsSenderCertificateName).'
            }
            else {
                Add-ExoFinding $result -Check 'Partner connector restriction' -Status Pass -Target $name `
                    -Detail ('Restricted by {0}.' -f ($(if ($restrictCert) { 'certificate' } else { 'IP address' })))
            }

            if (-not $requireTls) {
                Add-ExoFinding $result -Check 'Partner connector TLS' -Status Warning -Severity Medium -Target $name `
                    -Detail 'RequireTls is off: mail from this partner may arrive unencrypted.' `
                    -Recommendation 'Set-InboundConnector -RequireTls $true once the partner supports TLS.'
            }

            if (Get-ExoPropertyValue $c 'TreatMessagesAsInternal' $false) {
                Add-ExoFinding $result -Check 'TreatMessagesAsInternal on partner connector' -Status Warning -Severity Medium -Target $name `
                    -Detail 'Partner mail is treated as internal (bypasses some external protections).' `
                    -Recommendation 'Only OnPremises connectors in hybrid deployments should treat messages as internal.'
            }
        }

        $efIPs = @(Get-ExoPropertyValue $c 'EFSkipIPs' @())
        $efLast = [bool](Get-ExoPropertyValue $c 'EFSkipLastIP' $false)
        if (-not $efLast -and $efIPs.Count -eq 0) {
            Add-ExoFinding $result -Check 'Enhanced Filtering for Connectors' -Status Info -Target $name `
                -Detail 'Enhanced Filtering (skip listing) is not configured.' `
                -Recommendation 'If MX points to a third-party filter or on-premises gateway in front of EOP, enable Enhanced Filtering so SPF/DKIM/DMARC and IP reputation use the original sender IP (see the DNS report MX check).'
        }
        else {
            $testMode = Get-ExoPropertyValue $c 'EFTestMode' $false
            Add-ExoFinding $result -Check 'Enhanced Filtering for Connectors' -Status Pass -Target $name `
                -Detail ("Enabled ({0}){1}." -f $(if ($efLast) { 'skip last IP' } else { "skip $($efIPs -join ', ')" }), $(if ($testMode) { ', test mode' } else { '' }))
        }

        $drop = @(Get-ExoPropertyValue $c 'ScanAndDropRecipients' @())
        if ($drop.Count -gt 0) {
            Add-ExoFinding $result -Check 'Scan-and-drop recipients' -Status Info -Target $name `
                -Detail "$($drop.Count) recipients have mail scanned and silently dropped: $($drop -join ', ')."
        }
    }
}

#endregion

#region Outbound connectors

$outbound = Invoke-ExoSafe { Get-OutboundConnector -IncludeTestModeConnectors $true } 'outbound connectors'
if ($null -eq $outbound) { $outbound = Invoke-ExoSafe { Get-OutboundConnector } 'outbound connectors (retry)' }
if ($null -ne $outbound) {
    $result.Data['OutboundConnectors'] = @($outbound | ConvertTo-ExoFlatObject -Property Name, Enabled, ConnectorType,
        ConnectorSource, RecipientDomains, SmartHosts, UseMXRecord, TlsSettings, TlsDomain, IsTransportRuleScoped,
        RouteAllMessagesViaOnPremises, AllAcceptedDomains, CloudServicesMailEnabled, IsValidated,
        LastValidationTimestamp, SenderRewritingEnabled, TestMode, WhenChanged)

    if (@($outbound).Count -eq 0) {
        Add-ExoFinding $result -Check 'Outbound connectors' -Status Info `
            -Detail 'No outbound connectors. Exchange Online delivers external mail directly using MX lookups.'
    }

    foreach ($c in $outbound) {
        $name = $c.Name
        if (-not $c.Enabled) {
            Add-ExoFinding $result -Check 'Outbound connector disabled' -Status Info -Target $name -Detail 'Connector is disabled.'
            continue
        }

        $tls = "$(Get-ExoPropertyValue $c 'TlsSettings' '')"
        $smartHosts = @(Get-ExoPropertyValue $c 'SmartHosts' @())
        $recipientDomains = @(Get-ExoPropertyValue $c 'RecipientDomains' @()) | ForEach-Object { "$_" }

        switch ($tls) {
            'DomainValidation' {
                Add-ExoFinding $result -Check 'Outbound connector TLS' -Status Pass -Target $name `
                    -Detail "Validates the certificate subject ($((Get-ExoPropertyValue $c 'TlsDomain' '')))."
            }
            'CertificateValidation' {
                Add-ExoFinding $result -Check 'Outbound connector TLS' -Status Pass -Target $name -Detail 'Validates the certificate chain.'
            }
            'EncryptionOnly' {
                Add-ExoFinding $result -Check 'Outbound connector TLS' -Status Warning -Severity Low -Target $name `
                    -Detail 'TLS required but the remote certificate is not validated.' `
                    -Recommendation 'Use CertificateValidation or DomainValidation with TlsDomain.'
            }
            default {
                $sev = if ($smartHosts.Count -gt 0) { 'Medium' } else { 'Low' }
                Add-ExoFinding $result -Check 'Outbound connector TLS' -Status Warning -Severity $sev -Target $name `
                    -Detail 'Opportunistic TLS only: mail can be sent in clear text if the remote server does not offer TLS.' `
                    -Recommendation 'Set-OutboundConnector -TlsSettings DomainValidation -TlsDomain <smarthost certificate name>.'
            }
        }

        if ("$($c.ConnectorType)" -eq 'Partner' -and $recipientDomains -contains '*' -and -not (Get-ExoPropertyValue $c 'IsTransportRuleScoped' $false)) {
            Add-ExoFinding $result -Check 'Outbound connector scope' -Status Warning -Severity Medium -Target $name `
                -Detail 'All external mail is routed through this partner connector.' `
                -Recommendation 'Confirm this is an intended egress gateway; otherwise scope it to specific recipient domains or transport rules.'
        }

        if (Get-ExoPropertyValue $c 'RouteAllMessagesViaOnPremises' $false) {
            Add-ExoFinding $result -Check 'Centralized mail transport' -Status Info -Target $name `
                -Detail 'All outbound internet mail is routed via on-premises (centralized mail transport). On-premises availability now affects Exchange Online mail flow.'
        }

        $validated = Get-ExoPropertyValue $c 'IsValidated' $null
        $lastValidation = Get-ExoPropertyValue $c 'LastValidationTimestamp' $null
        if ($validated -eq $false -or $null -eq $lastValidation) {
            Add-ExoFinding $result -Check 'Outbound connector validation' -Status Warning -Severity Low -Target $name `
                -Detail 'Connector has never been validated successfully.' `
                -Recommendation 'Run Validate-OutboundConnector -Identity <name> -Recipients <test address> (sends a test message).'
        }
        elseif (([datetime]$lastValidation) -lt (Get-Date).AddDays(-$ValidationMaxAgeDays)) {
            Add-ExoFinding $result -Check 'Outbound connector validation' -Status Info -Target $name `
                -Detail "Last validated $(([datetime]$lastValidation).ToString('yyyy-MM-dd')), more than $ValidationMaxAgeDays days ago."
        }
    }
}

#endregion

#region Hybrid and federation

$onPremOrg = Invoke-ExoSafe { Get-OnPremisesOrganization } 'on-premises organization'
if ($null -ne $onPremOrg -and @($onPremOrg).Count -gt 0) {
    $result.Data['OnPremisesOrganization'] = @($onPremOrg | ConvertTo-ExoFlatObject -Property Name, OrganizationName,
        OrganizationGuid, HybridDomains, InboundConnector, OutboundConnector, OrganizationRelationship, WhenChanged)

    $connectorNames = @(@($inbound) + @($outbound) | Where-Object { $_ } | ForEach-Object { "$($_.Name)" })
    foreach ($o in $onPremOrg) {
        foreach ($ref in 'InboundConnector', 'OutboundConnector') {
            $refName = "$(Get-ExoPropertyValue $o $ref '')"
            if ($refName -and $connectorNames -notcontains $refName) {
                Add-ExoFinding $result -Check 'Hybrid connector reference' -Status Fail -Severity Medium -Target $o.Name `
                    -Detail "On-premises organisation references $ref '$refName', which does not exist." `
                    -Recommendation 'Re-run the Hybrid Configuration Wizard, or remove stale hybrid objects if hybrid was decommissioned.'
            }
        }
        Add-ExoFinding $result -Check 'Hybrid deployment' -Status Info -Target $o.Name `
            -Detail "Hybrid configured for: $(ConvertTo-ExoFlatValue (Get-ExoPropertyValue $o 'HybridDomains'))."
    }
}

$orgRel = Invoke-ExoSafe { Get-OrganizationRelationship } 'organization relationships'
if ($null -ne $orgRel -and @($orgRel).Count -gt 0) {
    $result.Data['OrganizationRelationships'] = @($orgRel | ConvertTo-ExoFlatObject -Property Name, Enabled, DomainNames,
        FreeBusyAccessEnabled, FreeBusyAccessLevel, FreeBusyAccessScope, MailboxMoveEnabled, MailboxMoveCapability,
        DeliveryReportEnabled, MailTipsAccessEnabled, MailTipsAccessLevel, ArchiveAccessEnabled, TargetApplicationUri,
        TargetAutodiscoverEpr, TargetSharingEpr, OrganizationContact)

    foreach ($r in $orgRel) {
        if ((Get-ExoPropertyValue $r 'FreeBusyAccessLevel' '') -eq 'LimitedDetails' -and -not (Get-ExoPropertyValue $r 'FreeBusyAccessScope' $null)) {
            Add-ExoFinding $result -Check 'Organization relationship free/busy' -Status Info -Target $r.Name `
                -Detail "Shares free/busy with subject and location to $(ConvertTo-ExoFlatValue $r.DomainNames) for all users." `
                -Recommendation 'Confirm this is expected for non-hybrid (partner) relationships, or scope with FreeBusyAccessScope.'
        }
    }
}

$ioc = Invoke-ExoSafe { Get-IntraOrganizationConnector } 'intra-organization connectors'
if ($null -ne $ioc -and @($ioc).Count -gt 0) {
    $result.Data['IntraOrganizationConnectors'] = @($ioc | ConvertTo-ExoFlatObject -Property Name, Enabled,
        TargetAddressDomains, DiscoveryEndpoint, TargetSharingEpr)
    foreach ($i in $ioc) {
        $status = if ($i.Enabled) { 'Pass' } else { 'Warning' }
        Add-ExoFinding $result -Check 'IntraOrganizationConnector (OAuth hybrid)' -Status $status -Severity Low -Target $i.Name `
            -Detail "Enabled: $($i.Enabled). Discovery endpoint: $(Get-ExoPropertyValue $i 'DiscoveryEndpoint' '')." `
            -Recommendation 'Test with Test-OAuthConnectivity -Service EWS -TargetUri <on-prem EWS URL> -Mailbox <cloud mailbox>.'
    }
}

$migration = Invoke-ExoSafe { Get-MigrationEndpoint } 'migration endpoints'
if ($null -ne $migration -and @($migration).Count -gt 0) {
    $result.Data['MigrationEndpoints'] = @($migration | ConvertTo-ExoFlatObject -Property Identity, EndpointType,
        RemoteServer, ExchangeServer, MaxConcurrentMigrations, MaxConcurrentIncrementalSyncs, IsRemote, Username)
    Add-ExoFinding $result -Check 'Migration endpoints' -Status Info `
        -Detail "$(@($migration).Count) migration endpoints. Stale endpoints hold stored credentials." `
        -Recommendation 'Remove endpoints for completed migrations (Remove-MigrationEndpoint).'
}

#endregion

$summaryCounts = '{0} inbound, {1} outbound connectors' -f @($inbound | Where-Object { $_ }).Count, @($outbound | Where-Object { $_ }).Count
Add-ExoFinding $result -Check 'Connector inventory' -Status Info -Detail $summaryCounts

if ($OutputPath) { Export-ExoSectionResult -Result $result -OutputPath $OutputPath }
$result
