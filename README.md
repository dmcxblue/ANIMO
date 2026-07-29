
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure%20%7C%20M365-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" />
  <img src="https://img.shields.io/badge/C++-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" />
  <img src="https://img.shields.io/badge/Qt-6.x-41CD52?style=for-the-badge&logo=qt&logoColor=white" />
  <img src="https://img.shields.io/badge/License-Private-red?style=for-the-badge" />
</p>

<h1 align="center">ANIMO</h1>
<h3 align="center">Azure Network Intel & Mission Ops</h3>

<p align="center">
  <i>A unified client-server platform for Azure & Microsoft 365 security assessment</i>
</p>

<p align="center">
  <b>Designed for authorized penetration testing, red team operations, and security research.</b>
</p>

---

## What is ANIMO?

ANIMO is a comprehensive Azure AD / Entra ID assessment platform that combines **PowerShell-based session management** with **native Graph API integration**. It gives red teamers a single interface to manage multiple Azure sessions, manipulate tokens, enumerate cloud resources, and execute post-exploitation techniques during authorized engagements.

### Highlights

> - Manage **multiple Azure PowerShell sessions** simultaneously from a single dashboard
> - **Capture, exchange, and analyze** OAuth tokens (access, refresh, PRT)
> - Access **Outlook, Calendar, Teams, OneDrive** and SharePoint through the Graph API
> - Enumerate **subscriptions, Key Vaults, VMs, storage, SQL, Functions, Logic Apps** and more
> - Execute **password sprays, consent phishing, persistence techniques**, and post-exploitation
> - Generate **professional engagement reports** with session timelines and findings
> - AES-256-GCM **encrypted session persistence** with auto-restore on restart

---

## Screenshots

### Dashboard
<!-- Add screenshot: screenshots/dashboard.png -->
<p align="center">
  <img src="screenshots/dashboard.png" alt="ANIMO Dashboard" width="800" />
</p>

### Device Code Authentication
<!-- Add screenshot: screenshots/device-code.png -->
<p align="center">
  <img src="screenshots/device-code.png" alt="Device Code Login" width="800" />
</p>

### Azure Enumeration
<!-- Add screenshot: screenshots/azure-enum.png -->
<p align="center">
  <img src="screenshots/azure-enum.png" alt="Azure Enumeration" width="800" />
</p>

### Outlook Email Access
<!-- Add screenshot: screenshots/outlook-email.png -->
<p align="center">
  <img src="screenshots/outlook-email.png" alt="Outlook Email Access" width="800" />
</p>

### Token Analysis
<!-- Add screenshot: screenshots/token-analysis.png -->
<p align="center">
  <img src="screenshots/token-analysis.png" alt="Token Analysis" width="800" />
</p>

---

## Quick Start

### Prerequisites

| Requirement | Version |
|:------------|:--------|
| OS | Linux (Kali recommended), macOS, or Windows with WSL2 |
| Qt6 | 6.2+ (Widgets, Network, WebEngineWidgets, Sql) |
| CMake | 3.16+ |
| PowerShell | 7.x (`pwsh`) |
| Azure CLI | 2.x (`az`) — optional but recommended for parity |
| Python | 3.8+ with `msal`, `requests` |

### Install & Build

```bash
# Clone the repository
git clone https://github.com/dmcxblue/ANIMO.git
cd ANIMO

# Install system dependencies (Linux/Kali)
./install-dependencies.sh

# Install PowerShell modules
pwsh -File Install-AllModules.ps1

# Build
./build.sh
```

### Launch

```bash
# Start the server
./build/server/AnimoServer -i 0.0.0.0 -p 7777 -P <YourPassword>

# Start the client (separate terminal)
./build/client/AnimoClient
```

Connect to the server using the client login window with your server IP, port, and password.

---

## Feature Overview

### Authentication Methods

| Method | Description |
|:-------|:------------|
| Credentials | Username/password login via MSAL |
| Device Code | Phishing-friendly device code flow |
| Access Token | Direct token input |
| Browser OAuth | Interactive browser authentication |
| Illicit Consent | OAuth consent grant phishing |

### Discovery & Enumeration

| Feature | API |
|:--------|:----|
| Azure Subscriptions & Resources | ARM |
| Conditional Access Policies | Graph |
| Cross-Tenant Access Policies | Graph |
| OAuth Consent Grants | Graph |
| MFA Status Checker | Graph |
| Password Writeback Detection | Graph |
| Service Principal Enumeration | Graph |
| Key Vault Secrets & Certificates | Vault |
| Virtual Machines | ARM |
| Storage Accounts & Blobs | ARM |
| SQL Databases | ARM |
| Function Apps | ARM |
| Logic Apps | ARM |
| Automation Runbooks | ARM |

<!-- Add screenshot: screenshots/enumeration.png -->
<p align="center">
  <img src="screenshots/enumeration.png" alt="Discovery & Enumeration" width="800" />
</p>

### Microsoft 365 Access

| Feature | Capabilities |
|:--------|:-------------|
| Outlook Email | Read, reply, send, bulk operations, templates |
| Outlook Calendar | View and export calendar events |
| Teams Chat | Read conversations and messages |
| OneDrive / SharePoint | Browse, search, and download files |
| Graph Queries | Execute custom MS Graph API queries |

<!-- Add screenshot: screenshots/m365-access.png -->
<p align="center">
  <img src="screenshots/m365-access.png" alt="Microsoft 365 Access" width="800" />
</p>

### Attack Functions

| Attack | Description |
|:-------|:------------|
| Password Spray | Bulk credential testing with smart lockout avoidance |
| SPN Secret Spray | Service Principal secret enumeration |
| Add App Secret | Inject secrets into Azure AD applications |

### Persistence & Post-Exploitation

| Technique | Description |
|:----------|:------------|
| Windows Hello Attack | WHfB credential persistence via rogue workstation |
| Email Forwarding Rules | Stealth inbox forwarding rules |
| Consent Manipulation | Silent OAuth permission grants |
| App Backdoors | Register apps with hidden credentials |
| Group Manipulation | Add users to privileged groups |
| Role Assignment | Assign Azure RBAC roles |
| Guest Invite | Silent B2B guest invitations |

<!-- Add screenshot: screenshots/post-exploit.png -->
<p align="center">
  <img src="screenshots/post-exploit.png" alt="Post-Exploitation" width="800" />
</p>

### Token Operations

| Feature | Description |
|:--------|:------------|
| Token Logging | View and export all captured tokens |
| Token Analysis | JWT claim inspection and validation |
| Refresh Token Exchange | Exchange refresh tokens across resources |
| PRT Exchange | Primary Refresh Token operations |
| SSO Cookie Conversion | SSO cookie to access token |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AnimoClient                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ Dashboard   │  │  Plugin     │  │ Direct API Calls        │ │
│  │ (Sessions)  │  │  Windows    │  │ (Graph, ARM, Vault)     │ │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘ │
│         │                │                       │              │
│         └────────────────┴───────────────────────┘              │
│                          │                                      │
│                   ClientTransport                               │
│                          │ TCP / JSON                           │
└──────────────────────────┼──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                         AnimoServer                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    Request Dispatcher                      │ │
│  └──────────┬─────────────────────────────────┬───────────────┘ │
│             │                                 │                 │
│  ┌──────────▼──────────┐         ┌───────────▼───────────┐     │
│  │  PowerShellManager  │         │   SessionDBManager    │     │
│  │  (Session Processes)│         │   (SQLite Database)   │     │
│  └─────────────────────┘         └───────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

Communication uses **line-delimited JSON over TCP** (default port 7777). The client sends actions, the server dispatches to PowerShell sessions or the SQLite database and responds with results.

---

## Usage Examples

### Initial Access via Device Code

1. Open **Access > Device Code Login**
2. Enter a client ID (or use the default)
3. Click **Start Device Code Flow**
4. Send the device code URL to the target
5. When the victim authenticates, tokens are captured automatically
6. Enable **Create session from captured token** to auto-create a session

### Enumerate Azure Resources

1. Create a session with an Azure Management token
2. Open **Attacks > Enumeration > Subscriptions & Resources**
3. Select user and click **Auto-Fetch Token**
4. Click **Fetch Subscriptions** to discover all subscriptions
5. Select a subscription to enumerate resources (VMs, Key Vaults, Storage, etc.)

### Password Spray

1. Open **Attacks > Authentication > Password Spray**
2. Enter target usernames (one per line)
3. Enter passwords to try
4. Configure delay (500ms+ recommended to avoid lockout)
5. Click **Start Spray** - valid credentials are highlighted in green

### Persistence via Email Rules

1. Compromise a mailbox (Graph token with `Mail.ReadWrite`)
2. Open **Persistence > Email Inbox Rules**
3. Configure a forwarding rule with stealth options (hidden name, stop processing)
4. Click **Create Rule**

---

## Keyboard Shortcuts

| Shortcut | Action |
|:---------|:-------|
| `Ctrl+N` | New Device Code session |
| `F5` | Refresh sessions list |
| `Ctrl+Q` | Quit application |
| `Ctrl+Shift+T` | Open Token Log |
| `Ctrl+G` | Open Graph Query |
| `Ctrl+E` | Open Azure Enumeration |

---

## Server Configuration

```
AnimoServer [options]
  -i, --ip <address>      Listen IP (default: 127.0.0.1)
  -p, --port <port>       Listen port (default: 7777)
  -P, --password <pass>   Client authentication password (required)
  -d, --data <path>       Data directory (default: ./data)
```

### Required PowerShell Modules

Installed automatically by `Install-AllModules.ps1`:

| Module | Purpose |
|:-------|:--------|
| `Az` | Azure Resource Manager |
| `AzureAD` | Azure Active Directory |
| `AADInternals` | Azure AD internals & token operations |
| `Microsoft.Graph` | Microsoft Graph SDK |
| `SqlServer` | Azure SQL operations |
| `AzTable` | Azure Table Storage |

---

## Security & OPSEC

- **Transport**: Use SSH tunnels or VPN for client-server communication over untrusted networks
- **Server Password**: Transmitted in cleartext over TCP - use strong passwords
- **Token Storage**: Captured tokens are stored in SQLite - protect the `data/` directory
- **Cleanup**: Always delete the `data/` directory after an engagement
- **Token Lifetimes**: Access tokens expire in ~1 hour; refresh tokens last up to 90 days unless revoked

---

## Legal Disclaimer

> **ANIMO is intended for authorized security testing, red team operations, and security research only.**

Users are responsible for:

1. Obtaining **proper written authorization** before testing
2. Complying with all **applicable laws and regulations**
3. Following **responsible disclosure** practices
4. **Protecting** captured credentials and tokens during and after engagements

**Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of this tool.**

---

## Acknowledgments

- [AADInternals](https://github.com/Gerenios/AADInternals) - Azure AD internals research
- [ROADtools](https://github.com/dirkjanm/ROADtools) - Azure AD exploration toolkit
- [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-python) - Microsoft Authentication Library

---

<p align="center">
  <b>ANIMO</b> - <i>Azure Network Intel & Mission Ops</i>
</p>
