#Requires -Version 5.1
<#
.SYNOPSIS
    Analyses Exchange Online mail flow: message trace statistics, mail flow (transport) rules,
    journaling and transport configuration.

.DESCRIPTION
    Read-only.

    Message trace uses Get-MessageTraceV2 (falls back to the legacy Get-MessageTrace in older
    module versions). V2 returns up to 5,000 rows per call and covers up to 10 days per query, so
    the script walks the requested period in windows and pages with StartingRecipientAddress.

    Transport rule checks flag rules that:
      - set SCL -1 (bypass spam filtering), especially when keyed on spoofable sender domains;
      - redirect, BCC or add external recipients (silent data exfiltration);
      - are disabled, in test mode or past their expiry date;
      - route to an outbound connector that does not exist.

.PARAMETER Days
    Days of message trace history to analyse (1-90). Default 2. Larger values take longer and
    count against the message trace throttle (100 queries / 5 minutes).

.PARAMETER MaxMessages
    Stop collecting trace rows after this many (default 50,000).

.PARAMETER FailedRateWarningPercent
    Failed-delivery percentage that produces a warning (default 2). Twice this value is a failure.

.PARAMETER OutputPath
    Folder for CSV exports. Omit to only return the result object.

.EXAMPLE
    .\Get-ExoMailFlowReport.ps1 -Days 7 -OutputPath .\out
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)] [int] $Days = 2,
    [ValidateRange(100, 1000000)] [int] $MaxMessages = 50000,
    [double] $FailedRateWarningPercent = 2,
    [string] $OutputPath
)

. (Join-Path $PSScriptRoot 'ExoHealth.Common.ps1')
Assert-ExoConnection

$result = New-ExoSectionResult -Section 'Mail Flow'

$accepted = Invoke-ExoSafe { Get-AcceptedDomain } 'accepted domains' -Default @()
$outboundConnectors = Invoke-ExoSafe { Get-OutboundConnector } 'outbound connectors' -Default @()
$outboundNames = @($outboundConnectors | ForEach-Object { "$($_.Name)" })

#region Message trace

function Get-ExoMessageTraceRows {
    param([datetime] $Start, [datetime] $End, [int] $Max)

    $rows = New-Object System.Collections.Generic.List[object]
    $useV2 = Test-ExoCommand 'Get-MessageTraceV2'
    if (-not $useV2) {
        Write-Warning 'Get-MessageTraceV2 not found - falling back to the deprecated Get-MessageTrace (10 days max). Update ExchangeOnlineManagement.'
    }

    $windowStart = $Start
    while ($windowStart -lt $End -and $rows.Count -lt $Max) {
        $windowEnd = $windowStart.AddDays(10)
        if ($windowEnd -gt $End) { $windowEnd = $End }

        if ($useV2) {
            $pageEnd = $windowEnd
            $startingRecipient = $null
            do {
                $params = @{ StartDate = $windowStart; EndDate = $pageEnd; ResultSize = 5000 }
                if ($startingRecipient) { $params.StartingRecipientAddress = $startingRecipient }
                $batch = @(Get-MessageTraceV2 @params -ErrorAction Stop)
                foreach ($b in $batch) { $rows.Add($b) }
                Write-Verbose "Message trace: $($rows.Count) rows so far"
                $more = $batch.Count -eq 5000 -and $rows.Count -lt $Max
                if ($more) {
                    # Documented V2 paging: next query uses the last row's Received and RecipientAddress.
                    $last = $batch[-1]
                    $pageEnd = [datetime]$last.Received
                    $startingRecipient = $last.RecipientAddress
                }
            } while ($more)
        }
        else {
            $page = 1
            do {
                $batch = @(Get-MessageTrace -StartDate $windowStart -EndDate $windowEnd -PageSize 5000 -Page $page -ErrorAction Stop)
                foreach ($b in $batch) { $rows.Add($b) }
                $page++
            } while ($batch.Count -eq 5000 -and $page -le 1000 -and $rows.Count -lt $Max)
        }
        $windowStart = $windowEnd
    }
    $rows.ToArray()
}

$end = (Get-Date).ToUniversalTime()
$start = $end.AddDays(-$Days)
$trace = Invoke-ExoSafe { Get-ExoMessageTraceRows -Start $start -End $end -Max $MaxMessages } "message trace ($Days days)"

if ($null -ne $trace) {
    $total = @($trace).Count
    if ($total -ge $MaxMessages) {
        Add-ExoFinding $result -Check 'Message trace coverage' -Status Info `
            -Detail "Stopped at $MaxMessages rows; statistics cover part of the $Days-day period." `
            -Recommendation 'Increase -MaxMessages, reduce -Days, or use Start-HistoricalSearch for large tenants.'
    }

    $direction = {
        param($row)
        $senderInternal = -not (Test-ExoExternalAddress -Address $row.SenderAddress -AcceptedDomains $accepted)
        $recipientInternal = -not (Test-ExoExternalAddress -Address $row.RecipientAddress -AcceptedDomains $accepted)
        if ($senderInternal -and $recipientInternal) { 'Internal' }
        elseif ($senderInternal) { 'Outbound' }
        elseif ($recipientInternal) { 'Inbound' }
        else { 'Relay' }
    }

    $enriched = @($trace | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, Size, FromIP, ToIP, MessageTraceId,
        @{ Name = 'Direction'; Expression = { & $direction $_ } })

    $byStatus = @($enriched | Group-Object Status | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{ Status = $_.Name; Count = $_.Count; Percent = if ($total) { [math]::Round(100 * $_.Count / $total, 2) } else { 0 } }
        })
    $byDirection = @($enriched | Group-Object Direction, Status | Sort-Object Count -Descending | ForEach-Object {
            $parts = $_.Name -split ', '
            [pscustomobject]@{ Direction = $parts[0]; Status = $parts[1]; Count = $_.Count }
        })
    $topSenders = @($enriched | Group-Object SenderAddress | Sort-Object Count -Descending | Select-Object -First 25 |
        ForEach-Object { [pscustomobject]@{ SenderAddress = $_.Name; Messages = $_.Count } })
    $failed = @($enriched | Where-Object Status -eq 'Failed')
    $topFailedDomains = @($failed | Group-Object { Get-ExoSmtpDomain $_.RecipientAddress } | Sort-Object Count -Descending |
        Select-Object -First 25 | ForEach-Object { [pscustomobject]@{ RecipientDomain = $_.Name; Failed = $_.Count } })
    $perDay = @($enriched | Group-Object { ([datetime]$_.Received).ToString('yyyy-MM-dd') } | Sort-Object Name | ForEach-Object {
            $g = $_.Group
            [pscustomobject]@{
                Date        = $_.Name
                Total       = $g.Count
                Delivered   = @($g | Where-Object Status -eq 'Delivered').Count
                Failed      = @($g | Where-Object Status -eq 'Failed').Count
                Quarantined = @($g | Where-Object Status -eq 'Quarantined').Count
                Spam        = @($g | Where-Object Status -eq 'FilteredAsSpam').Count
            }
        })

    $result.Data['TraceByStatus'] = $byStatus
    $result.Data['TraceByDirection'] = $byDirection
    $result.Data['TracePerDay'] = $perDay
    $result.Data['TopSenders'] = $topSenders
    $result.Data['TopFailedRecipientDomains'] = $topFailedDomains
    $result.Data['FailedMessages'] = @($failed | Select-Object -First 1000)

    Add-ExoFinding $result -Check 'Message volume' -Status Info `
        -Detail ("{0} message events in the last {1} days: {2}." -f $total, $Days, (($byStatus | ForEach-Object { "$($_.Status) $($_.Count)" }) -join ', '))

    if ($total -gt 0) {
        $failedPct = [math]::Round(100 * $failed.Count / $total, 2)
        if ($failedPct -ge (2 * $FailedRateWarningPercent)) { $st = 'Fail'; $sev = 'High' }
        elseif ($failedPct -ge $FailedRateWarningPercent) { $st = 'Warning'; $sev = 'Medium' }
        else { $st = 'Pass'; $sev = 'Info' }
        Add-ExoFinding $result -Check 'Delivery failure rate' -Status $st -Severity $sev `
            -Detail "$failedPct% of messages failed ($($failed.Count) of $total). Top failing domains: $(($topFailedDomains | Select-Object -First 5 | ForEach-Object { "$($_.RecipientDomain) ($($_.Failed))" }) -join ', ')." `
            -Recommendation 'Inspect FailedMessages with Get-MessageTraceDetailV2 -MessageTraceId <id> -RecipientAddress <addr> to read the NDR code.'

        $pending = @($enriched | Where-Object Status -in 'Pending', 'Deferred').Count
        if ($pending -gt [math]::Max(25, $total * 0.01)) {
            Add-ExoFinding $result -Check 'Pending / deferred messages' -Status Warning -Severity Medium `
                -Detail "$pending messages are pending or deferred." `
                -Recommendation 'Check outbound connector smart hosts and the remote servers'' availability; look for 4.x.x codes in trace details.'
        }

        $volumeSpike = @($topSenders | Where-Object { $_.Messages -gt [math]::Max(2000, $total * 0.2) -and
                -not (Test-ExoExternalAddress -Address $_.SenderAddress -AcceptedDomains $accepted) })
        foreach ($s in $volumeSpike) {
            Add-ExoFinding $result -Check 'High-volume internal sender' -Status Warning -Severity Low -Target $s.SenderAddress `
                -Detail "$($s.Messages) messages in $Days days." `
                -Recommendation 'Confirm this is an expected application / notification sender and not a compromised account (check outbound spam alerts).'
        }
    }
}

# Mail flow status report (aggregate counts from EOP, cheaper than trace for long periods).
if (Test-ExoCommand 'Get-MailflowStatusReport') {
    $mfStatus = Invoke-ExoSafe { Get-MailflowStatusReport -StartDate $start -EndDate $end } 'mail flow status report'
    if ($null -ne $mfStatus -and @($mfStatus).Count -gt 0) {
        $result.Data['MailflowStatusReport'] = @($mfStatus | Group-Object Direction, EventType | ForEach-Object {
                $parts = $_.Name -split ', '
                [pscustomobject]@{ Direction = $parts[0]; EventType = $parts[1]; MessageCount = ($_.Group | Measure-Object MessageCount -Sum).Sum }
            })
    }
}

#endregion

#region Transport rules

$rules = Invoke-ExoSafe { Get-TransportRule -ResultSize Unlimited } 'mail flow rules'
if ($null -ne $rules) {
    $result.Data['TransportRules'] = @($rules | ConvertTo-ExoFlatObject -Property Priority, Name, State, Mode, SetSCL,
        SenderDomainIs, FromAddressContainsWords, SenderIpRanges, RedirectMessageTo, BlindCopyTo, AddToRecipients,
        CopyTo, RouteMessageOutboundConnector, SetHeaderName, SetHeaderValue, ActivationDate, ExpiryDate, Comments, WhenChanged)

    Add-ExoFinding $result -Check 'Mail flow rule inventory' -Status Info `
        -Detail ("{0} rules: {1} enabled, {2} disabled, {3} in test mode." -f @($rules).Count,
            @($rules | Where-Object State -eq 'Enabled').Count,
            @($rules | Where-Object State -eq 'Disabled').Count,
            @($rules | Where-Object { "$($_.Mode)" -ne 'Enforce' }).Count)

    foreach ($r in $rules) {
        $enabled = "$($r.State)" -eq 'Enabled'
        $scl = Get-ExoPropertyValue $r 'SetSCL' $null

        if ($enabled -and $null -ne $scl -and "$scl" -eq '-1') {
            $senderDomains = @(Get-ExoPropertyValue $r 'SenderDomainIs' @())
            $fromWords = @(Get-ExoPropertyValue $r 'FromAddressContainsWords' @())
            $ipRanges = @(Get-ExoPropertyValue $r 'SenderIpRanges' @())
            $headerCond = Get-ExoPropertyValue $r 'HeaderContainsMessageHeader' $null
            if (($senderDomains.Count -gt 0 -or $fromWords.Count -gt 0) -and $ipRanges.Count -eq 0 -and -not $headerCond) {
                Add-ExoFinding $result -Check 'Spam bypass on spoofable condition' -Status Fail -Severity High -Target $r.Name `
                    -Detail "Rule sets SCL -1 based on sender domain/address only ($(($senderDomains + $fromWords) -join ', ')). Attackers can spoof these senders to skip spam filtering." `
                    -Recommendation 'Add a SenderIpRanges or authentication-results header condition, or use the Tenant Allow/Block List / advanced delivery policy instead.'
            }
            else {
                Add-ExoFinding $result -Check 'Spam bypass rule' -Status Warning -Severity Medium -Target $r.Name `
                    -Detail 'Rule sets SCL -1 (bypasses spam filtering).' `
                    -Recommendation 'Review whether the bypass is still required. Use advanced delivery for phishing simulations / SecOps mailboxes.'
            }
        }

        foreach ($prop in 'RedirectMessageTo', 'BlindCopyTo', 'AddToRecipients', 'CopyTo') {
            $targets = @(Get-ExoPropertyValue $r $prop @()) | ForEach-Object { "$_" } | Where-Object { $_ -match '@' }
            $external = @($targets | Where-Object { Test-ExoExternalAddress -Address $_ -AcceptedDomains $accepted })
            if ($enabled -and $external.Count -gt 0) {
                Add-ExoFinding $result -Check 'Rule copies mail externally' -Status Fail -Severity High -Target $r.Name `
                    -Detail "$prop sends messages to external address(es): $($external -join ', ')." `
                    -Recommendation 'Confirm with the business owner; this is a common persistence / exfiltration technique after admin compromise.'
            }
        }

        $connector = "$(Get-ExoPropertyValue $r 'RouteMessageOutboundConnector' '')"
        if ($enabled -and $connector -and $outboundNames -notcontains $connector) {
            Add-ExoFinding $result -Check 'Rule references missing connector' -Status Fail -Severity Medium -Target $r.Name `
                -Detail "Routes to outbound connector '$connector', which does not exist." `
                -Recommendation 'Fix the rule or recreate the connector; affected mail will not route as intended.'
        }

        $expiry = Get-ExoPropertyValue $r 'ExpiryDate' $null
        if ($enabled -and $expiry -and ([datetime]$expiry) -lt (Get-Date)) {
            Add-ExoFinding $result -Check 'Expired rule' -Status Info -Target $r.Name `
                -Detail "Expired on $(([datetime]$expiry).ToString('yyyy-MM-dd')) but still enabled." -Recommendation 'Disable or remove the rule.'
        }

        if ($enabled -and "$($r.Mode)" -ne 'Enforce') {
            Add-ExoFinding $result -Check 'Rule in test mode' -Status Info -Target $r.Name `
                -Detail "Mode is $($r.Mode); actions are not enforced." -Recommendation 'Enforce or remove once testing is complete.'
        }
    }
}

#endregion

#region Journaling and transport configuration

$transport = Invoke-ExoSafe { Get-TransportConfig } 'transport config' -Single
if ($transport) {
    $result.Data['TransportConfig'] = @($transport | ConvertTo-ExoFlatObject -Property MaxSendSize, MaxReceiveSize,
        MaxRecipientEnvelopeLimit, ExternalPostmasterAddress, JournalingReportNdrTo, SmtpClientAuthenticationDisabled,
        AllowLegacyTLSClients, ReplyAllStormProtectionEnabled, ReplyAllStormDetectionMinimumRecipients,
        AddressBookPolicyRoutingEnabled, ConvertDisclaimerWrapperToEml, InternalDsnSendHtml, ExternalDsnSendHtml)

    $storm = Get-ExoPropertyValue $transport 'ReplyAllStormProtectionEnabled' $null
    if ($storm -eq $false) {
        Add-ExoFinding $result -Check 'Reply-all storm protection' -Status Warning -Severity Low `
            -Detail 'Reply-all storm protection is disabled.' -Recommendation 'Set-TransportConfig -ReplyAllStormProtectionEnabled $true'
    }
    elseif ($storm -eq $true) {
        Add-ExoFinding $result -Check 'Reply-all storm protection' -Status Pass -Detail 'Enabled.'
    }
}

$journal = Invoke-ExoSafe { Get-JournalRule } 'journal rules'
if ($null -ne $journal -and @($journal).Count -gt 0) {
    $result.Data['JournalRules'] = @($journal | ConvertTo-ExoFlatObject -Property Name, Enabled, Scope, Recipient, JournalEmailAddress)
    $ndrTo = "$(Get-ExoPropertyValue $transport 'JournalingReportNdrTo' '')"
    if (-not $ndrTo -or $ndrTo -match '^<>$') {
        Add-ExoFinding $result -Check 'Journaling NDR mailbox' -Status Fail -Severity Medium `
            -Detail "$(@($journal).Count) journal rules exist but JournalingReportNdrTo is not set; undeliverable journal reports are lost." `
            -Recommendation 'Set-TransportConfig -JournalingReportNdrTo <dedicated mailbox that is not journaled>.'
    }
    else {
        Add-ExoFinding $result -Check 'Journaling NDR mailbox' -Status Pass -Detail "Journal NDRs go to $ndrTo."
    }
}

#endregion

if ($OutputPath) { Export-ExoSectionResult -Result $result -OutputPath $OutputPath }
$result
