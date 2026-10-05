# haganism.net — Exchange Online tenant health check

| | |
|---|---|
| Tenant ID | `d77abf63-feb1-4e10-aba5-bc7d55e54c1d` (region NA) |
| Sign-in | Managed (cloud-only, not federated) |
| Mail routing | MX → `haganism-net.mail.protection.outlook.com` (direct to Exchange Online Protection; no third-party gateway) |
| Profile | [`haganism.net.psd1`](haganism.net.psd1): the expected state that the drift check compares against |

## Run it

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -MinimumVersion 3.4.0

cd tenants\haganism.net

# Full report: connectors, mail flow, security, DNS, drift (sign in with a haganism.net account)
.\Invoke-HaganismNetHealthCheck.ps1 -UserPrincipalName you@haganism.net

# Public DNS posture only, no sign-in
.\Invoke-HaganismNetHealthCheck.ps1 -DnsOnly
```

Output goes to `reports\haganism.net\<yyyyMMdd-HHmm>\ExoHealthReport.html` (plus CSV/JSON). That folder is git-ignored because it holds tenant data.

- **Sign-in:** use an account with **Global Reader + Security Reader**. The scripts only read, so no admin role is needed.
- **Tenant guard:** the runner stops if the session is signed in to any tenant other than `d77abf63-…`.
- **What runs:** every section, including per-mailbox forwarding, SMTP AUTH and audit-bypass checks, and an inbox-rule scan of every mailbox (add `-SkipInboxRules` for a faster run). Message trace covers 7 days.

Scheduled / unattended run (Entra app with `Exchange.ManageAsApp` and Global Reader, certificate in the store; exit code 2 means high-severity findings):

```powershell
.\Invoke-HaganismNetHealthCheck.ps1 -AppId <appId> -CertificateThumbprint <thumbprint> `
    -Organization <tenant>.onmicrosoft.com -FailOnHighSeverity
```

## Public posture as of 2026-10-05

From a live `-DnsOnly` run against public DNS:

| Check | Result | Detail |
|---|---|---|
| MX | Pass | `0 haganism-net.mail.protection.outlook.com` |
| SPF | Pass | `v=spf1 include:spf.protection.outlook.com -all`: one record, Exchange Online only, hard fail |
| DMARC | Pass | `p=quarantine; adkim=r; aspf=r; rua=mailto:dmarc_rua@onsecureserver.net` |
| DKIM | **Warning** | `selector1._domainkey` / `selector2._domainkey` CNAMEs are not published. Exchange Online is therefore signing as `*.onmicrosoft.com`, so DKIM never aligns with haganism.net and DMARC relies on SPF alone (which breaks on forwarding). |
| MTA-STS / TLS-RPT | Info | Not published |
| Autodiscover | — | CNAME → `autodiscover.outlook.com` |

### Recommended next steps

1. **Enable DKIM** (highest value).
   ```powershell
   New-DkimSigningConfig -DomainName haganism.net -Enabled $false
   Get-DkimSigningConfig haganism.net | Format-List Selector1CNAME, Selector2CNAME
   # publish both CNAMEs at the DNS host, wait for propagation, then:
   Set-DkimSigningConfig -Identity haganism.net -Enabled $true
   ```
   Then set `DkimCnames = $true` in `haganism.net.psd1` so removal of the CNAMEs is caught as drift.
2. **Check DMARC reports.** Aggregate reports go to `onsecureserver.net`, an outside reporting address (likely set up by the domain registrar). Make sure someone can actually read them. After DKIM has been aligned for a few weeks, move to `p=reject` and update `DmarcPolicy` in the profile.
3. **Optional:** publish MTA-STS and TLS-RPT so other mail servers must use TLS when delivering to you.
4. **First signed-in run:**
   - Check that the profile assumptions hold: no inbound or outbound connectors.
   - Copy the mail flow rule names you approve into `TransportRules` so new rules show up as drift.

The connected checks (connectors, mail flow, security policies, forwarding, audit) have not been
run against this tenant yet; they need a sign-in.
