$ErrorActionPreference = 'Stop'
Write-Host "`n--- Azure Tool Setup ---`n"

function Remove-AllAzureModules {
    Write-Host "`n--- Starting removal of all Azure-related modules ---`n"
    
    Write-Host "Removing AzureRM modules..."
    Get-Module -ListAvailable AzureRM* | ForEach-Object {
        Write-Host "Removing: $($_.Name)"
        Uninstall-Module -Name $_.Name -AllVersions -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "`nRemoving Az modules..."
    Get-Module -ListAvailable Az* | ForEach-Object {
        Write-Host "Removing: $($_.Name)"
        Uninstall-Module -Name $_.Name -AllVersions -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "`nRemoving any modules starting with 'Azure'..."
    Get-Module -ListAvailable Azure* | ForEach-Object {
        Write-Host "Removing: $($_.Name)"
        Uninstall-Module -Name $_.Name -AllVersions -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "`nRemoving AzureAD modules..."
    Get-Module -ListAvailable AzureAD | ForEach-Object {
        Write-Host "Removing: AzureAD"
        Uninstall-Module -Name AzureAD -AllVersions -Force -ErrorAction SilentlyContinue
    }   
    
    Write-Host "`nRemoving Microsoft Graph modules..."
    Get-Module -ListAvailable Microsoft.Graph | ForEach-Object {
        Write-Host "Removing: $($_.Name)"
        Uninstall-Module -Name $_.Name -AllVersions -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "`nRemoving AADInternals modules..."
    Get-Module -ListAvailable AADInternals | ForEach-Object {
        Write-Host "Removing: $($_.Name)"
        Uninstall-Module -Name $_.Name -AllVersions -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "`n--- All specified Azure modules have been removed ---`n"
}

Remove-AllAzureModules

Start-Sleep -Seconds 2

# Verify module removals
Write-Host "`n--- Verifying module removals ---`n"
$modulesToCheck = @("AzureRM", "Az", "AzureAD", "AzureADPreview", "Microsoft.Graph")
foreach ($mod in $modulesToCheck) {
    if (Get-Module -ListAvailable $mod) {
        Write-Warning "$mod modules still exist."
    } else {
        Write-Host "$mod modules removed."
    }
}

Write-Host "`n--- Reinstalling stable Azure modules ---`n"
# Install stable Az and AzureAD modules
Install-Module -Name Az -Scope CurrentUser -Force
Install-Module -Name AzureAD -Scope CurrentUser -Force

# AADInternals

# Install the module
Install-Module -Name "AADInternals" -Scope CurrentUser -Force
Install-Module -Name "AADInternals-Endpoints" -Scope CurrentUser -Force

# Import modules
Import-Module -Name "AADInternals"
Import-Module -Name "AADInternals-Endpoints"

# SQL

Install-Module -Name SqlServer -Scope CurrentUser -Force 
Import-Module -Name SqlServer

# AzTable I needed it for PWNDLabs

Install-Module AzTable -Force

# Microsoft Graph

Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force

# New function: Ensure additional Azure sub-modules (including Microsoft Graph) are installed.
function Ensure-AzureModules {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ModuleNames
    )
    foreach ($mod in $ModuleNames) {
        if (-not (Get-Module -ListAvailable $mod)) {
            Write-Host "$mod not found. Installing..."
            Install-Module -Name $mod -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "$mod installed successfully."
        } else {
            Write-Host "$mod is already installed."
        }
    }
}

# List of additional Azure sub-modules to ensure are installed (Microsoft.Graph included)
$additionalModules = @(
    "Az.Accounts",
    "Az.Compute",
    "Az.Network",
    "Az.Resources",
    "Az.Storage",
    "Az.KeyVault",
    "Az.Monitor",
    "Az.Security",
    "Az.Automation",
    "Az.Functions",
    "Microsoft.Graph"
)

Ensure-AzureModules -ModuleNames $additionalModules

# Function to ensure that winget (Windows Package Manager) is installed
function Ensure-Winget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget not found. Downloading and installing the official winget MSIX bundle..."
        # Download the official winget MSIX bundle from Microsoft's GitHub release page.
        $installerUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
        $installerPath = "$env:TEMP\winget.msixbundle"
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
        Write-Host "Installing winget package..."
        # Install the downloaded MSIX bundle. Note that Add-AppxPackage may require administrator privileges.
        Add-AppxPackage -Path $installerPath
        Remove-Item $installerPath
    }
    else {
        Write-Host "winget is already installed."
    }
}

Ensure-Winget

# Azure CLI check/install function using winget
function Ensure-AzCLI {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Write-Host "Azure CLI not found. Installing via winget..."
        winget install -e --id Microsoft.AzureCLI --accept-source-agreements --accept-package-agreements
    } else {
        Write-Host "Azure CLI is already installed. Updating via winget..."
        winget upgrade -e --id Microsoft.AzureCLI --accept-source-agreements --accept-package-agreements
    }
}

# Azure Function Core Tools check/install function using winget
function Ensure-FuncTools {
    if (-not (Get-Command func -ErrorAction SilentlyContinue)) {
        Write-Host "Azure Function Core Tools not found. Installing via winget..."
        winget install -e --id Microsoft.Azure.FunctionsCoreTools --accept-source-agreements --accept-package-agreements
    } else {
        Write-Host "Azure Function Core Tools already installed. Updating via winget..."
        winget upgrade -e --id Microsoft.Azure.FunctionsCoreTools --accept-source-agreements --accept-package-agreements
    }
}

#Install Git Module from winget
function Ensure-Git {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "Git not found. Installing via winget..."
        winget install --id Git.Git --accept-source-agreements --accept-package-agreements
    } else {
        Write-Host "Git is already installed. Updating via winget..."
        winget upgrade -e --id Git.Git --accept-source-agreements --accept-package-agreements
    }
}

# Call installers for CLI and Function Tools
Ensure-AzCLI
Ensure-FuncTools
Ensure-Git


# Function to clone GitHub repositories
function Clone-GitHubTools {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RepoURLs,
        [string]$DestinationPath = "."
    )
    
    # Create destination folder if it doesn't exist
    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath | Out-Null
    }
    
    foreach ($url in $RepoURLs) {
        Write-Host "Cloning repository from $url"
        # Extract repository name from URL (assumes URL ends with .git)
        $repoName = ($url.Split("/")[-1]).Replace(".git", "")
        $targetFolder = Join-Path $DestinationPath $repoName
        if (Test-Path $targetFolder) {
            Write-Host "Repository '$repoName' already exists in $DestinationPath, skipping clone."
        } else {
            git clone $url $targetFolder
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Successfully cloned '$repoName'."
            } else {
                Write-Warning "Failed to clone '$repoName' from $url."
            }
        }
    }
}

# Clone the specified GitHub repositories
$repos = @(
    "https://github.com/LuemmelSec/APEX.git",
    "https://github.com/hausec/PowerZure.git",
	"https://github.com/f-bader/TokenTacticsV2.git",
	"https://github.com/dirkjanm/ROADtools.git",
	"https://github.com/Azure/Stormspotter.git",
	"https://github.com/NetSPI/MicroBurst.git",
	"https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c",
	"https://github.com/dafthack/MFASweep.git",
	"https://github.com/dafthack/MSOLSpray.git",
	"https://github.com/Gerenios/AADInternals.git",
	"https://github.com/YasserREED/Office365Hacker.git",
	"https://github.com/lutzenfried/OffensiveCloud.git"
)
Clone-GitHubTools -RepoURLs $repos -DestinationPath "."

Write-Host "`n Environment cleaned, Azure modules (including Microsoft Graph) reinstalled, sub-modules ensured, and tools updated successfully.`n" -ForegroundColor Green
