# ANIMO

**Azure Network Intel & Mission Ops**

A comprehensive client-server platform for Azure and Microsoft 365 security assessment, designed for authorized penetration testing, red team operations, and security research.

![Qt6](https://img.shields.io/badge/Qt-6.x-green.svg)
![C++17](https://img.shields.io/badge/C++-17-blue.svg)
![License](https://img.shields.io/badge/License-Private-red.svg)

---

## Overview

ANIMO provides a unified interface for Azure AD/Entra ID reconnaissance, token manipulation, and post-exploitation activities during authorized security engagements. It combines PowerShell-based Azure session management with native Graph API integration for comprehensive cloud assessment capabilities.

### Key Capabilities

- **Multi-Session Management** - Maintain multiple Azure PowerShell sessions simultaneously
- **Token Operations** - Capture, exchange, and manipulate OAuth tokens (access, refresh, PRT)
- **Microsoft 365 Access** - Read emails, calendar, Teams chats, OneDrive/SharePoint files
- **Azure Enumeration** - Discover subscriptions, resources, Key Vaults, VMs, and more
- **Attack Functions** - Password spray, MFA detection, consent phishing, persistence techniques
- **Reporting** - Generate professional engagement reports with timelines and findings

---

## Quick Start

### Prerequisites

- **OS**: Linux (Kali recommended), macOS, or Windows with WSL2
- **Qt6**: 6.2+ with Widgets, Network, WebEngineWidgets, Sql modules
- **CMake**: 3.16+
- **PowerShell**: 7.x (pwsh)
- **Python**: 3.8+ with msal, requests

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/animo.git
cd animo

# Install system dependencies (Linux/Kali)
./install-dependencies.sh

# Install PowerShell modules
pwsh -File Install-AllModules.ps1

# Build
./build.sh
```

### Running

```bash
# Start the server (choose a strong password)
./build/server/AnimoServer -i 0.0.0.0 -p 7777 -P YourSecurePassword

# Start the client (in another terminal)
./build/client/AnimoClient
```

Connect to the server using the client's login window with your server IP, port, and password.

---

## Features

### Authentication Methods

| Method | Window | Description |
|--------|--------|-------------|
| Credentials | `CredentialLoginWindow` | Username/password with MSAL |
| Device Code | `DeviceCodeLoginWindow` | Phishing-friendly device code flow |
| Access Token | `TokenLoginWindow` | Direct token input |
| Browser OAuth | `InteractiveBrowserAuth` | Interactive browser authentication |
| Illicit Consent | `IllicitConsentGrant` | OAuth consent grant phishing |

### Discovery & Enumeration

| Feature | Window | API |
|---------|--------|-----|
| Azure Subscriptions | `AzureEnumWindow` | ARM API |
| Conditional Access | `ConditionalAccessWindow` | Graph API |
| Cross-Tenant Access | `CrossTenantAccessWindow` | Graph API |
| OAuth Consent Grants | `OAuthConsentEnumeratorWindow` | Graph API |
| MFA Status | `MfaStatusCheckerWindow` | Graph API |
| Password Writeback | `PasswordWritebackCheckerWindow` | Graph API |
| Service Principals | `SPNEnumWindow` | Graph API |
| Key Vault Secrets | `KeyVaultExplorerWindow` | Vault API |
| Virtual Machines | `AzureVMManagerWindow` | ARM API |
| Storage Accounts | `AzureStorageWindow` | ARM API |
| SQL Databases | `SqlDatabaseWindow` | ARM API |
| Function Apps | `FunctionAppExplorerWindow` | ARM API |
| Logic Apps | `LogicAppsViewerWindow` | ARM API |
| Automation Runbooks | `RunbookExplorerWindow` | ARM API |

### Microsoft 365 Access

| Feature | Window | Capabilities |
|---------|--------|--------------|
| Outlook Email | `OutlookEmailWindow` | Read, reply, send, bulk operations, templates |
| Outlook Calendar | `OutlookCalendarWindow` | View calendar events |
| Teams Chat | `TeamsChatWindow` | Read conversations and messages |
| OneDrive/SharePoint | `SharePointBrowserWindow` | Browse and download files |
| Graph Queries | `GraphQueryWindow` | Custom Graph API queries |

### Attack Functions

| Attack | Window | Description |
|--------|--------|-------------|
| Password Spray | `MSOLSprayWindow` | Bulk credential testing with smart lockout avoidance |
| SPN Secret Spray | `SPNSpraySerialWindow` | Service Principal secret enumeration |
| Add App Secret | `AddAzADAppSecret` | Add secrets to Azure AD applications |
| Windows Hello Attack | `WHfBAttackWindow` | WHfB credential persistence via device code |

### Post-Exploitation & Persistence

| Feature | Window/Tab | Description |
|---------|------------|-------------|
| Group Manipulation | `PostExploitWindow` | Add users to groups |
| App Backdoors | `PostExploitWindow` | Create app registrations with secrets |
| Role Assignment | `PostExploitWindow` | Assign Azure RBAC roles |
| Guest Invite | `PostExploitWindow` | Silent B2B guest invitations |
| Email Rules | `EmailRulesWindow` | Create forwarding rules for persistence |
| Consent Manipulation | `ConsentManipulationWindow` | Manage OAuth consent grants |

### Token Operations

| Feature | Window | Description |
|---------|--------|-------------|
| Token Logging | `TokenLogWindow` | View and export captured tokens |
| Token Analysis | `TokenAnalysisWindow` | JWT claim inspection |
| Refresh Token Exchange | `RequestRefreshTokens` | Exchange refresh tokens for access tokens |
| PRT Exchange | `PRTTokenUI` | Primary Refresh Token operations |
| SSO Cookie | `SsoCookieTokenWindow` | SSO cookie to token conversion |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AnimoClient                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ Dashboard   │  │ Plugin      │  │ Direct API Calls        │  │
│  │ (Sessions)  │  │ Windows     │  │ (Graph, ARM, Vault)     │  │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘  │
│         │                │                      │               │
│         └────────────────┴──────────────────────┘               │
│                          │                                       │
│                   ClientTransport                                │
│                          │ TCP/JSON                              │
└──────────────────────────┼───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                         AnimoServer                               │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Request Dispatcher                        │ │
│  └──────────┬──────────────────────────────────┬───────────────┘ │
│             │                                  │                 │
│  ┌──────────▼──────────┐          ┌───────────▼───────────┐     │
│  │  PowerShellManager  │          │   SessionDBManager    │     │
│  │  (Session Processes)│          │   (SQLite Database)   │     │
│  └─────────────────────┘          └───────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

### Communication Protocol

Client-server communication uses line-delimited JSON over TCP:

```json
{"action": "login", "password": "secret"}
{"action": "new_session", "auth_type": "token", "access_token": "eyJ..."}
{"action": "run_command", "session_id": "abc123", "command": "Get-AzContext"}
{"action": "log_token", "access_token": "eyJ...", "source": "device_code"}
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for complete protocol documentation.

---

## Usage Examples

### Initial Access via Device Code

1. Open **Access → Device Code Login**
2. Enter a client ID (or use default Microsoft Office)
3. Click **Start Device Code Flow**
4. Send the device code URL to target via phishing
5. When victim authenticates, tokens are captured
6. Enable **Create session from captured token** to auto-create a session

### Enumerate Azure Resources

1. Create a session with Azure Management token
2. Open **Attacks → Enumeration → Subscriptions & Resources**
3. Select user and click **Auto-Fetch Token**
4. Click **Fetch Subscriptions** to list all subscriptions
5. Select a subscription to enumerate resources
6. Resources are grouped by type (VMs, Key Vaults, Storage, etc.)

### Password Spray Attack

1. Open **Attacks → Authentication → Password Spray**
2. Enter target usernames (one per line)
3. Enter passwords to try
4. Configure delay (500ms+ recommended to avoid lockout)
5. Click **Start Spray**
6. Valid credentials are highlighted in green

### Persistence via Email Rules

1. Compromise a mailbox (get Graph token with Mail.ReadWrite)
2. Open **Persistence → Email Inbox Rules**
3. Configure rule:
   - Action: Forward or Redirect
   - Condition: Subject contains "invoice", "payment"
   - Target: attacker@evil.com
4. Enable stealth options (hidden name, stop processing)
5. Click **Create Rule**

### Generate Engagement Report

1. Run enumeration and collect tokens during engagement
2. Open **Reports → Generate Report**
3. Fill in engagement metadata
4. Select sections to include
5. Click **Generate HTML Report**
6. Professional report with timeline and findings is created

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | New Device Code session |
| `F5` | Refresh sessions list |
| `Ctrl+Q` | Quit application |
| `Ctrl+Shift+T` | Open Token Log |
| `Ctrl+G` | Open Graph Query |
| `Ctrl+E` | Open Azure Enumeration |

---

## Configuration

### Server Options

```
AnimoServer [options]
  -i, --ip <address>      Listen IP (default: 127.0.0.1)
  -p, --port <port>       Listen port (default: 7777)
  -P, --password <pass>   Client authentication password (required)
  -d, --data <path>       Data directory (default: ./data)
```

### Required PowerShell Modules

The following modules are installed by `Install-AllModules.ps1`:

- `Az` - Azure Resource Manager
- `AzureAD` - Azure Active Directory
- `AADInternals` - Azure AD internals and token operations
- `Microsoft.Graph` - Microsoft Graph SDK
- `SqlServer` - Azure SQL operations
- `AzTable` - Azure Table Storage

---

## Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | This file - overview and quick start |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Detailed installation guide |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Complete user manual |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Technical architecture and protocol |
| [docs/ATTACK_TECHNIQUES.md](docs/ATTACK_TECHNIQUES.md) | Attack technique details |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## Security Considerations

### Operational Security

- **TLS**: Use SSH tunnels or VPN for client-server communication over untrusted networks
- **Passwords**: Server password is transmitted in cleartext - use strong passwords
- **Tokens**: Captured tokens are stored in SQLite - protect the data directory
- **Logs**: Activity is logged - sanitize before leaving engagement environment

### Token Handling

- Access tokens expire (typically 1 hour) - use refresh tokens for persistence
- Refresh tokens last 90 days unless revoked
- PRT tokens provide SSO across Microsoft services
- Always delete `data/` directory after engagement

---

## Legal Disclaimer

ANIMO is intended for authorized security testing, red team operations, and security research only. Users are responsible for:

1. Obtaining proper authorization before testing
2. Complying with all applicable laws and regulations
3. Following responsible disclosure practices
4. Protecting captured credentials and tokens

**Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of this tool.**

---

## Contributing

This is a private security tool. Contributions are limited to authorized team members.

### Development Setup

```bash
# Build with debug symbols
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Run tests
cd build && ctest --output-on-failure
```

### Code Style

- C++17 standard
- Qt naming conventions (camelCase for methods, PascalCase for classes)
- One class per file pair (.h/.cpp)
- Use `NetworkHelper` for all HTTP requests
- Use `ErrorLogger` for logging
- Use `WindowHelper` for window positioning

---

## License

Private - All Rights Reserved

---

## Acknowledgments

- [AADInternals](https://github.com/Gerenios/AADInternals) - Azure AD internals research
- [ROADtools](https://github.com/dirkjanm/ROADtools) - Azure AD token operations
- [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-python) - Microsoft Authentication Library

---

**ANIMO** - *Azure Network Intel & Mission Ops*
