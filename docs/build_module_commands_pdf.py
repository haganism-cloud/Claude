"""Builds M365-PowerShell-Module-Commands.pdf: the commands to install, load and connect the
PowerShell modules used to manage a Microsoft 365 environment.

Requires: reportlab   (pip install reportlab)
"""

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (KeepTogether, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

OUT = Path(__file__).parent / "M365-PowerShell-Module-Commands.pdf"
TITLE = "Microsoft 365 PowerShell Modules - Install, Load and Connect"

NAVY = colors.HexColor("#1F3864")
CODE_BG = colors.HexColor("#F2F4F7")
CODE_BORDER = colors.HexColor("#C9CFD8")
MUTED = colors.HexColor("#5D6675")

base = getSampleStyleSheet()
S = {
    "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold", fontSize=20,
                            leading=24, textColor=NAVY, alignment=TA_LEFT, spaceAfter=4),
    "sub": ParagraphStyle("s", parent=base["Normal"], fontName="Helvetica", fontSize=10,
                          textColor=MUTED, spaceAfter=14),
    "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=14,
                         leading=18, textColor=NAVY, spaceBefore=14, spaceAfter=6),
    "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11,
                         leading=14, textColor=colors.black, spaceBefore=8, spaceAfter=4),
    "body": ParagraphStyle("b", parent=base["Normal"], fontName="Helvetica", fontSize=9.5,
                           leading=13, spaceAfter=5),
    "note": ParagraphStyle("n", parent=base["Normal"], fontName="Helvetica-Oblique", fontSize=8.5,
                           leading=11, textColor=MUTED, spaceAfter=6),
    "cell": ParagraphStyle("c", parent=base["Normal"], fontName="Helvetica", fontSize=8.5, leading=11),
    "cellb": ParagraphStyle("cb", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5,
                            leading=11, textColor=colors.white),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=8, leading=10.2),
}

MAX_CODE = 96  # characters per code line that fit the text width at Courier 8pt


def p(text, style="body"):
    return Paragraph(text, S[style])


def code(text):
    text = text.strip("\n")
    for line in text.splitlines():
        assert len(line) <= MAX_CODE, f"code line too long ({len(line)}): {line}"
    t = Table([[Preformatted(text, S["code"])]], colWidths=[7.0 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, CODE_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return [t, Spacer(1, 7)]


def table(rows, widths):
    data = [[Paragraph(escape(c), S["cellb"]) for c in rows[0]]]
    data += [[Paragraph(escape(c), S["cell"]) for c in r] for r in rows[1:]]
    t = Table(data, colWidths=[w * inch for w in widths], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F8FA")]),
        ("GRID", (0, 0), (-1, -1), 0.4, CODE_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return [t, Spacer(1, 8)]


def section(title, *flowables):
    """Keep a heading with the first block that follows it."""
    items = list(flowables)
    first = items[0] if isinstance(items[0], list) else [items[0]]
    rest = items[1:]
    out = [KeepTogether([p(title, "h2")] + first)]
    for r in rest:
        out += r if isinstance(r, list) else [r]
    return out


story = []
story += [
    p(TITLE, "title"),
    p("Quick reference for administrators. Commands are for PowerShell 7 (recommended) or "
      "Windows PowerShell 5.1. Run as your normal user: <b>-Scope CurrentUser</b> needs no admin "
      "rights. Prepared November 2026.", "sub"),
]

# ------------------------------------------------------------------ 1. Prerequisites
story.append(p("1. Prerequisites (once per computer)", "h1"))
story += section("Install PowerShell 7 and check the version", code("""
winget install --id Microsoft.PowerShell --source winget     # Windows
brew install --cask powershell                               # macOS (Homebrew)
$PSVersionTable.PSVersion                                    # 7.4 or later recommended
"""))
story += section("Windows PowerShell 5.1 only: TLS 1.2 and the NuGet provider", code("""
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
"""))
story += section("Allow locally run and signed scripts; make sure the PowerShell Gallery is registered", code("""
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
Get-PSRepository                                  # should list PSGallery
Register-PSRepository -Default                    # only if PSGallery is missing
Unblock-File .\\Initialize-M365AdminModules.ps1    # only for scripts downloaded from the web
"""))

# ------------------------------------------------------------------ 2. Modules
story.append(p("2. Which modules you need", "h1"))
story += table([
    ["Module", "Use it for", "Connect with"],
    ["Microsoft.Graph.Authentication", "Sign-in to Graph; Invoke-MgGraphRequest for any Graph query", "Connect-MgGraph"],
    ["Microsoft.Graph.Users / Users.Actions", "Users, managers, licence assignment, revoke sessions", "(Graph)"],
    ["Microsoft.Graph.Groups", "Groups and membership", "(Graph)"],
    ["Microsoft.Graph.Identity.DirectoryManagement", "Roles, domains, subscribed SKUs, devices", "(Graph)"],
    ["Microsoft.Graph.Identity.SignIns", "Conditional Access, authentication methods", "(Graph)"],
    ["Microsoft.Graph.Reports", "Sign-in and audit logs, usage reports", "(Graph)"],
    ["ExchangeOnlineManagement", "Exchange Online; Security & Compliance (Purview) PowerShell", "Connect-ExchangeOnline / Connect-IPPSSession"],
    ["MicrosoftTeams", "Teams policies, voice, meetings", "Connect-MicrosoftTeams"],
    ["PnP.PowerShell (PS 7)", "SharePoint Online and OneDrive", "Connect-PnPOnline"],
    ["Microsoft.Online.SharePoint.PowerShell", "SharePoint Online admin (classic module)", "Connect-SPOService"],
    ["Microsoft.Entra", "Entra ID cmdlets with AzureAD-style names (built on Graph)", "Connect-Entra"],
    ["ImportExcel", "Export results to .xlsx without Excel installed", "-"],
], [2.35, 3.05, 1.6])
story.append(p("Microsoft.Graph is a meta-module of about 40 sub-modules. Install it whole if you like, "
               "but import only the sub-modules you need: importing everything is slow, and in "
               "Windows PowerShell 5.1 it can hit the 4,096-function limit.", "note"))

# ------------------------------------------------------------------ 3. Install
story.append(p("3. Install (once) and update", "h1"))
story += section("Core set: Graph for users/groups/licences/reports, Exchange Online, Excel export", code("""
$core = 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users',
        'Microsoft.Graph.Users.Actions', 'Microsoft.Graph.Groups',
        'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Reports', 'ExchangeOnlineManagement', 'ImportExcel'
Install-Module -Name $core -Scope CurrentUser -Repository PSGallery -AllowClobber -Force
"""))
story += section("Optional: Teams, SharePoint, Entra, extra Graph areas", code("""
Install-Module MicrosoftTeams, Microsoft.Entra -Scope CurrentUser -Force
Install-Module PnP.PowerShell -Scope CurrentUser -Force                  # PowerShell 7
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser # 5.1 alternative
Install-Module Microsoft.Graph.Applications, Microsoft.Graph.DeviceManagement,
    Microsoft.Graph.Security, Microsoft.Graph.Identity.Governance -Scope CurrentUser -Force
Install-Module Microsoft.Graph -Scope CurrentUser -Force          # or: the whole Graph SDK
Install-Module Microsoft.Graph.Beta -Scope CurrentUser -Force     # preview APIs (optional)
"""))
story += section("Update everything, and keep all Graph sub-modules on the same version", code("""
Update-Module -Name Microsoft.Graph*, ExchangeOnlineManagement, MicrosoftTeams, PnP.PowerShell
Get-InstalledModule Microsoft.Graph* | Sort-Object Version | Format-Table Name, Version
"""))

# ------------------------------------------------------------------ 4. Load
story.append(p("4. Load the modules (each new PowerShell session)", "h1"))
story.append(p("Load Microsoft.Graph.Authentication first: it brings in the sign-in libraries the other "
               "Graph sub-modules share. PowerShell also auto-loads a module the first time you use "
               "one of its commands, but explicit imports make version problems show up immediately."))
story += code("""
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users, Microsoft.Graph.Users.Actions, Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Reports
Import-Module ExchangeOnlineManagement
Import-Module ImportExcel
# Optional
Import-Module MicrosoftTeams
Import-Module PnP.PowerShell                       # or: Microsoft.Online.SharePoint.PowerShell
Import-Module Microsoft.Entra
""")

# ------------------------------------------------------------------ 5. Connect
story.append(p("5. Connect to each service", "h1"))
story += section("Microsoft Graph (users, groups, licences, directory, reports)", code("""
Connect-MgGraph -NoWelcome -Scopes 'User.ReadWrite.All', 'Group.ReadWrite.All',
    'Directory.Read.All', 'Organization.Read.All', 'AuditLog.Read.All', 'Reports.Read.All',
    'Policy.Read.All'
Get-MgContext | Format-List Account, TenantId, Scopes        # who and what you are connected as
Find-MgGraphCommand -Command Get-MgUser | Select-Object -First 1 -ExpandProperty Permissions
"""))
story.append(p("Ask only for the scopes you need; read-only work needs only the *.Read.All scopes. "
               "Find-MgGraphCommand shows which permissions a cmdlet requires.", "note"))
story += section("Exchange Online and Security & Compliance (Purview)", code("""
Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.com -ShowBanner:$false
Connect-IPPSSession    -UserPrincipalName admin@yourdomain.com     # Purview / compliance
Get-ConnectionInformation | Format-Table Name, UserPrincipalName, TokenStatus
"""))
story += section("Teams, SharePoint and Entra", code("""
Connect-MicrosoftTeams
Connect-SPOService -Url https://yourtenant-admin.sharepoint.com          # classic SPO module
Connect-PnPOnline  -Url https://yourtenant-admin.sharepoint.com -Interactive -ClientId <appId>
Connect-Entra -Scopes 'User.Read.All', 'Group.Read.All'
"""))
story.append(p("PnP.PowerShell needs your own Entra app registration (its shared app was retired). "
               "Create one once with: Register-PnPEntraIDAppForInteractiveLogin "
               "-ApplicationName 'PnP PowerShell' -Tenant yourtenant.onmicrosoft.com -Interactive", "note"))
story += section("Unattended / scheduled scripts (certificate, no prompts)", code("""
Connect-MgGraph -ClientId <appId> -TenantId <tenantId> -CertificateThumbprint <thumbprint>
Connect-ExchangeOnline -AppId <appId> -CertificateThumbprint <thumbprint> `
    -Organization yourtenant.onmicrosoft.com
Connect-MgGraph -Identity            # Azure Automation / Azure VM managed identity
"""))

# ------------------------------------------------------------------ 6. Verify and first queries
story.append(p("6. Verify and first queries", "h1"))
story += code("""
Get-Module Microsoft.Graph*, ExchangeOnlineManagement, MicrosoftTeams |
    Format-Table Name, Version
Get-MgUser -All -Property DisplayName, UserPrincipalName, AccountEnabled |
    Select-Object DisplayName, UserPrincipalName, AccountEnabled
Get-MgSubscribedSku | Select-Object SkuPartNumber, ConsumedUnits,
    @{ n = 'Purchased'; e = { $_.PrepaidUnits.Enabled } }
Invoke-MgGraphRequest -Method GET -Uri 'v1.0/users?$top=5&$select=displayName,mail'
Get-EXOMailbox -ResultSize 10 | Export-Excel .\\mailboxes.xlsx -AutoSize -TableName Mailboxes
""")

# ------------------------------------------------------------------ 7. Disconnect / clean up
story.append(p("7. Disconnect and remove retired modules", "h1"))
story += code("""
Disconnect-MgGraph
Disconnect-ExchangeOnline -Confirm:$false
Disconnect-MicrosoftTeams
Disconnect-PnPOnline
Uninstall-Module MSOnline, AzureAD, AzureADPreview -AllVersions -ErrorAction SilentlyContinue
""")
story += table([
    ["Retired / legacy module", "Replace with"],
    ["MSOnline (Connect-MsolService)", "Microsoft.Graph (Get-MgUser, Set-MgUserLicense...) or Microsoft.Entra"],
    ["AzureAD / AzureADPreview (Connect-AzureAD)", "Microsoft.Graph or Microsoft.Entra (similar cmdlet names)"],
    ["SharePointPnPPowerShellOnline", "PnP.PowerShell"],
    ["Skype for Business Online connector", "MicrosoftTeams"],
    ["Exchange Remote PowerShell (New-PSSession to outlook.office365.com)", "ExchangeOnlineManagement v3 (REST based)"],
], [2.9, 4.1])

# ------------------------------------------------------------------ 8. Troubleshooting
story.append(KeepTogether([p("8. Troubleshooting", "h1")] + table([
    ["Symptom", "Fix"],
    ["'Could not load file or assembly' when importing Graph", "Graph sub-modules are at different versions. Update-Module Microsoft.Graph* so they match, then open a new PowerShell window."],
    ["MSAL / sign-in error when using Graph and Exchange together", "Both modules ship MSAL. Start a new window and connect to one service at a time, or connect Graph first."],
    ["'Function capacity 4096 has been exceeded'", "Windows PowerShell 5.1 limit. Use PowerShell 7, or import only the Graph sub-modules you need."],
    ["Install-Module: 'Unable to find repository PSGallery'", "Register-PSRepository -Default. On 5.1 also set TLS 1.2 (section 1)."],
    ["Install-Module fails behind a proxy", "Allow www.powershellgallery.com (and its CDN) through the proxy, or ask IT for an internal repository."],
    ["Insufficient privileges / 403 from Graph", "Reconnect with the needed -Scopes; an admin may need to grant consent for the tenant."],
    ["Script will not run: 'not digitally signed'", "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser, then Unblock-File <script>."],
], [2.6, 4.4])))

# ------------------------------------------------------------------ 9. One command
story.append(p("9. All of the above in one command", "h1"))
story.append(p("The repository script <b>scripts/Initialize-M365AdminModules.ps1</b> installs, updates, imports and "
               "optionally connects in one step, and warns about retired or mismatched modules:"))
story += code("""
.\\Initialize-M365AdminModules.ps1                         # Core set: install if missing + load
.\\Initialize-M365AdminModules.ps1 -Profile Full -Update   # everything, updated
.\\Initialize-M365AdminModules.ps1 -Connect -UserPrincipalName admin@yourdomain.com
.\\Initialize-M365AdminModules.ps1 -WhatIf                 # preview, change nothing
""")


def on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(0.75 * inch, 0.5 * inch, "Microsoft 365 PowerShell modules - quick reference")
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
    canvas.restoreState()


doc = SimpleDocTemplate(str(OUT), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                        topMargin=0.7 * inch, bottomMargin=0.75 * inch, title=TITLE,
                        author="M365 admin toolkit", subject="PowerShell modules for Microsoft 365")
doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
print(f"Wrote {OUT.name}")
