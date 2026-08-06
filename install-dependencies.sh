#!/usr/bin/env bash
#
# install-dependencies.sh - Debian/Ubuntu/Kali build and runtime dependencies.
#
# Installs the Qt6 + CMake toolchain ANIMO builds against, PowerShell 7, and
# (optionally) the Azure CLI. For the PowerShell modules themselves, run
# `pwsh -File Install-AllModules.ps1` afterwards.
#
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[*] Updating package lists..."
sudo apt-get update

echo "[*] Installing toolchain and Qt6 development packages..."
sudo apt-get install -y --no-install-recommends \
  build-essential \
  cmake \
  ninja-build \
  curl \
  ca-certificates \
  qt6-base-dev \
  qt6-base-dev-tools \
  qt6-webengine-dev \
  qt6-webengine-dev-tools \
  libqt6svg6 \
  libqt6sql6 \
  libqt6sql6-sqlite \
  libssl-dev \
  python3 \
  python3-pip

# ---------------------------------------------------------------------------
# PowerShell 7
#
# Kali does not ship snapd and enabling it there is unreliable, so prefer the
# .deb Microsoft publishes on GitHub and fall back to snap only if that fails.
# ---------------------------------------------------------------------------

install_powershell_deb() {
    local arch deb_arch url tmp
    arch="$(dpkg --print-architecture)"
    case "$arch" in
        amd64) deb_arch="x64" ;;
        arm64) deb_arch="arm64" ;;
        *)     echo "[!] No PowerShell .deb for architecture '$arch'."; return 1 ;;
    esac

    echo "[*] Resolving latest PowerShell release..."
    local version
    version="$(curl -fsSL https://api.github.com/repos/PowerShell/PowerShell/releases/latest \
        | grep -oP '"tag_name":\s*"v\K[^"]+' || true)"
    if [ -z "$version" ]; then
        echo "[!] Could not determine the latest PowerShell version."
        return 1
    fi

    url="https://github.com/PowerShell/PowerShell/releases/download/v${version}/powershell_${version}-1.deb_${deb_arch}.deb"
    tmp="$(mktemp -d)"
    echo "[*] Downloading PowerShell ${version} (${deb_arch})..."
    if ! curl -fsSL -o "$tmp/powershell.deb" "$url"; then
        echo "[!] Download failed: $url"
        rm -rf "$tmp"
        return 1
    fi

    # apt-get install on a local .deb pulls its dependencies; dpkg alone would not.
    sudo apt-get install -y "$tmp/powershell.deb"
    rm -rf "$tmp"
}

install_powershell_snap() {
    command -v snap >/dev/null 2>&1 || sudo apt-get install -y snapd
    sudo snap install powershell --classic
}

if command -v pwsh >/dev/null 2>&1; then
    echo "[+] PowerShell already installed: $(pwsh --version)"
else
    echo "[*] Installing PowerShell 7..."
    if install_powershell_deb; then
        echo "[+] PowerShell installed from .deb."
    elif install_powershell_snap; then
        echo "[+] PowerShell installed from snap."
    else
        echo "[!] PowerShell install failed. ANIMO needs pwsh for its session"
        echo "    terminal - install it manually before running the server:"
        echo "    https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux"
    fi
fi

# ---------------------------------------------------------------------------
# Azure CLI (optional)
#
# The login scripts opportunistically call `az login` alongside Connect-AzAccount
# so operators can run `az` one-liners in the session terminal. If az is missing
# the login scripts skip it cleanly, so this is recommended but not required.
# ---------------------------------------------------------------------------

if command -v az >/dev/null 2>&1; then
    echo "[+] Azure CLI already installed."
else
    echo "[*] Installing Azure CLI..."
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash || {
        echo "[!] az cli install failed - continuing without it."
        echo "    Login scripts will skip az login."
    }
fi

# ---------------------------------------------------------------------------
# Python MSAL (required for the seamless device-code login flow)
#
# server/scripts/animo_device_code.py drives one MSAL device-code prompt and
# hands the resulting tokens to Az PS + az cli. Without msal the device-code
# session type fails at login time.
# ---------------------------------------------------------------------------

echo "[*] Installing Python MSAL for the device-code login helper..."
# python3-msal exists on Debian 12+ / Ubuntu 22.04+ / Kali rolling. Fall back
# to pip if the distro doesn't package a recent enough version.
if sudo apt-get install -y python3-msal 2>/dev/null; then
    echo "[+] python3-msal installed via apt."
else
    echo "[*] python3-msal not available via apt; installing with pip3..."
    pip3 install --user --quiet msal || {
        echo "[!] pip3 install msal failed. Install manually before running device-code login:"
        echo "    pip3 install msal"
    }
fi

echo
echo "[+] Dependencies installed."
echo "    Next: pwsh -File Install-AllModules.ps1"
echo "    Then: ./build.sh"
