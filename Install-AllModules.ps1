<#
.SYNOPSIS
    Installs the PowerShell modules and CLI tools ANIMO drives.

.DESCRIPTION
    Runs on Windows PowerShell 5.1, and on PowerShell 7 on Windows, Linux and
    macOS. Modules that only exist on Windows (AzureAD, and the winget-installed
    CLI tools) are skipped with a message on other platforms rather than failing.

    This script is additive. It never uninstalls modules you already have.

.EXAMPLE
    pwsh -File Install-AllModules.ps1

.EXAMPLE
    # Skip the ~2 GB umbrella Az module and install only the submodules ANIMO uses
    pwsh -File Install-AllModules.ps1 -SkipUmbrellaAz
#>
[CmdletBinding()]
param(
    # Install only the Az.* submodules ANIMO calls, not the full Az meta-module.
    [switch]$SkipUmbrellaAz
)

# Continue, not Stop: one unavailable module should not abort the whole install.
$ErrorActionPreference = 'Continue'

# $IsWindows is a PowerShell 6+ automatic variable. On Windows PowerShell 5.1 it
# is undefined, and that edition only ever runs on Windows.
$onWindows = $IsWindows -or ($PSVersionTable.PSEdition -eq 'Desktop')

Write-Host ""
Write-Host "--- ANIMO module setup ---" -ForegroundColor Cyan
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)) on $(if ($onWindows) { 'Windows' } else { 'Unix' })"
Write-Host ""

# ---------------------------------------------------------------------------
# Gallery bootstrap
# ---------------------------------------------------------------------------

function Initialize-Gallery {
    # Windows PowerShell 5.1 ships without the NuGet provider and defaults to
    # TLS 1.0, both of which break Install-Module against the gallery.
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        } catch {
            Write-Warning "Could not force TLS 1.2: $($_.Exception.Message)"
        }
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-Host "Installing NuGet package provider..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
    }

    $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if ($gallery -and $gallery.InstallationPolicy -ne 'Trusted') {
        Write-Host "Trusting PSGallery for this user..."
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Module installation
# ---------------------------------------------------------------------------

function Ensure-Module {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Note
    )

    if (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue) {
        Write-Host ("  {0,-26} already installed" -f $Name) -ForegroundColor DarkGray
        return
    }

    Write-Host ("  {0,-26} installing..." -f $Name)
    try {
        # -AllowClobber: Az command names collide with leftover AzureRM installs.
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host ("  {0,-26} OK" -f $Name) -ForegroundColor Green
    } catch {
        Write-Warning ("{0}: {1}" -f $Name, $_.Exception.Message)
        if ($Note) { Write-Host "      $Note" -ForegroundColor Yellow }
    }
}

Initialize-Gallery

# Az submodules ANIMO actually calls. Installing these individually is far
# smaller than the umbrella Az module and covers every Az cmdlet in the codebase.
$azSubmodules = @(
    'Az.Accounts'    # Connect-AzAccount, Get-AzAccessToken, Get-AzContext
    'Az.Resources'   # Get-AzResource, Get-AzRoleAssignment, Get-AzADServicePrincipal
    'Az.Compute'     # Get-AzVM, Get-AzVMImage, Get-AzVMSize
    'Az.Network'     # Get-AzVirtualNetwork, Get-AzNetworkSecurityGroup
    'Az.Storage'     # Get-AzStorageAccount, Get-AzStorageBlob, SAS tokens
    'Az.KeyVault'    # Get-AzKeyVaultSecret, Get-AzKeyVaultKey
    'Az.Monitor'
)

# Modules that install and load on every platform.
$crossPlatform = @(
    @{ Name = 'Microsoft.Graph' }
    @{ Name = 'SqlServer' }        # Invoke-SqlCmd, used by SqlDatabaseWindow
    @{ Name = 'AADInternals'; Note = 'Some AADInternals cmdlets are Windows-only.' }
    @{ Name = 'AADInternals-Endpoints'; Note = 'Some cmdlets are Windows-only.' }
    @{ Name = 'AzTable' }
)

Write-Host "Az submodules:" -ForegroundColor Cyan
foreach ($m in $azSubmodules) { Ensure-Module -Name $m }

if (-not $SkipUmbrellaAz) {
    Write-Host ""
    Write-Host "Umbrella Az module (large - use -SkipUmbrellaAz to omit):" -ForegroundColor Cyan
    Ensure-Module -Name 'Az'
}

Write-Host ""
Write-Host "Cross-platform modules:" -ForegroundColor Cyan
foreach ($m in $crossPlatform) { Ensure-Module -Name $m.Name -Note $m.Note }

# ---------------------------------------------------------------------------
# Windows-only: AzureAD module and the winget-installed CLI tools
# ---------------------------------------------------------------------------

function Ensure-Winget {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "  winget                     already installed" -ForegroundColor DarkGray
        return $true
    }

    Write-Host "  winget                     installing App Installer bundle..."
    try {
        $installerUrl = 'https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
        $installerPath = Join-Path $env:TEMP 'winget.msixbundle'
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -ErrorAction Stop
        # May require elevation.
        Add-AppxPackage -Path $installerPath -ErrorAction Stop
        Remove-Item $installerPath -ErrorAction SilentlyContinue
        return [bool](Get-Command winget -ErrorAction SilentlyContinue)
    } catch {
        Write-Warning "winget install failed: $($_.Exception.Message)"
        return $false
    }
}

function Ensure-WingetPackage {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$Label
    )

    if (Get-Command $Command -ErrorAction SilentlyContinue) {
        Write-Host ("  {0,-26} already installed" -f $Label) -ForegroundColor DarkGray
        return
    }

    Write-Host ("  {0,-26} installing via winget..." -f $Label)
    winget install -e --id $Id --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "$Label install returned exit code $LASTEXITCODE."
    }
}

Write-Host ""
if ($onWindows) {
    Write-Host "Windows-only modules:" -ForegroundColor Cyan
    # AzureAD targets .NET Framework and cannot be imported by PowerShell 7.
    # It installs fine, but only Windows PowerShell 5.1 can load it.
    Ensure-Module -Name 'AzureAD' `
        -Note 'AzureAD loads only under Windows PowerShell 5.1, not pwsh 7.'
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        Write-Host "      Note: import AzureAD from Windows PowerShell 5.1, or use" -ForegroundColor Yellow
        Write-Host "      Import-Module AzureAD -UseWindowsPowerShell from pwsh 7." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Windows CLI tools:" -ForegroundColor Cyan
    if (Ensure-Winget) {
        Ensure-WingetPackage -Id 'Microsoft.AzureCLI'                -Command 'az'   -Label 'Azure CLI'
        Ensure-WingetPackage -Id 'Microsoft.Azure.FunctionsCoreTools' -Command 'func' -Label 'Functions Core Tools'
        Ensure-WingetPackage -Id 'Git.Git'                           -Command 'git'  -Label 'Git'
    } else {
        Write-Host "  winget unavailable - install az, func and git manually." -ForegroundColor Yellow
    }
} else {
    Write-Host "Skipping Windows-only components on this platform:" -ForegroundColor Cyan
    Write-Host "  AzureAD    - .NET Framework only; cannot load on pwsh 7."
    Write-Host "               ANIMO panels that need it degrade rather than break."
    Write-Host "  winget     - Windows package manager."
    Write-Host "  az / func / git - install via ./install-dependencies.sh or your"
    Write-Host "               distro package manager."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "--- Verifying ---" -ForegroundColor Cyan
$check = $azSubmodules + $crossPlatform.Name
if (-not $SkipUmbrellaAz) { $check += 'Az' }
if ($onWindows) { $check += 'AzureAD' }

foreach ($m in $check) {
    $found = Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue
    if ($found) {
        $ver = ($found.Version | Select-Object -Unique | Sort-Object -Descending | Select-Object -First 1)
        Write-Host ("  {0,-26} {1}" -f $m, $ver) -ForegroundColor Green
    } else {
        Write-Host ("  {0,-26} MISSING" -f $m) -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Done. No modules were removed and nothing was cloned into this directory." -ForegroundColor Green
Write-Host "Third-party tooling ANIMO pairs well with is listed under 'Related Tooling'"
Write-Host "in README.md - clone those outside this repository."
Write-Host ""
