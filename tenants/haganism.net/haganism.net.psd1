# Tenant profile for haganism.net: the expected ("known-good") state used by
# Get-ExoBaselineReport.ps1 to detect drift. Edit this file whenever an approved change is made.
#
# Recorded 2026-10-05 from public sources:
#   - Tenant ID and managed (cloud-only) sign-in: login.microsoftonline.com discovery endpoints
#   - DNS values: public DNS lookups
# Exchange object lists marked ASSUMED were inferred (MX goes straight to EOP and SPF authorises
# only Exchange Online, so no third-party gateway is expected). Confirm them on the first
# connected run and adjust.
@{
    TenantName = 'haganism.net'
    TenantId   = 'd77abf63-feb1-4e10-aba5-bc7d55e54c1d'

    Dns = @{
        'haganism.net' = @{
            Mx          = @('haganism-net.mail.protection.outlook.com')
            Spf         = 'v=spf1 include:spf.protection.outlook.com -all'
            DmarcPolicy = 'quarantine'   # current policy; raise to 'reject' after DKIM is enabled
            DkimCnames  = $false         # set to $true once selector1/selector2 CNAMEs are published
        }
    }

    Exchange = @{
        AcceptedDomains    = @('haganism.net')   # custom domains only; *.onmicrosoft.com is ignored
        InboundConnectors  = @()                 # ASSUMED: none
        OutboundConnectors = @()                 # ASSUMED: none
        TransportRules     = $null               # $null = not checked; list rule names after the first run
    }

    # Defaults for Invoke-HaganismNetHealthCheck.ps1
    Report = @{
        MessageTraceDays = 7
    }
}
