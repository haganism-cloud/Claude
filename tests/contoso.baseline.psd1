# Baseline for the stub tenant in ExoStubs.ps1. Deliberately differs from it so the smoke test
# can assert drift findings.
@{
    TenantName = 'contoso.com'
    TenantId   = '11111111-2222-3333-4444-555555555555'
    Dns        = @{
        'contoso.com' = @{
            Mx          = @('contoso-com.mail.protection.outlook.com')
            Spf         = 'v=spf1 include:spf.protection.outlook.com -all'   # stub publishes an extra include -> SPF changed
            DmarcPolicy = 'quarantine'                                     # stub publishes p=none -> weaker
        }
    }
    Exchange   = @{
        AcceptedDomains    = @('contoso.com', 'fabrikam.com')
        InboundConnectors  = @('Inbound from contoso-onprem')                # 'From Fabrikam partner' is unexpected
        OutboundConnectors = @('Outbound to contoso-onprem', 'Egress via filtering service')
        TransportRules     = @('Whitelist payroll vendor', 'Copy CFO mail', 'Route legal via encryption gateway', 'Disclaimer', 'Retired rule')
    }
}
