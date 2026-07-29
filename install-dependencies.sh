#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Update package lists
sudo apt-get update

# Install toolchain + Qt6 deps
sudo apt-get install -y --no-install-recommends \
  build-essential \
  cmake \
  ninja-build \
  qt6-base-dev \
  qt6-tools-dev \
  qt6-tools-dev-tools \
  qt6-webengine-dev \
  qt6-webengine-dev-tools \
  qt6-websockets-dev \
  libqt6sql6 \
  libqt6sql6-sqlite \
  libssl-dev \
  snapd

sudo snap install powershell --classic

# Azure CLI - login scripts opportunistically call `az login` alongside
# Connect-AzAccount so operators can run `az` one-liners in the session
# terminal. If az isn't on PATH the login scripts skip it cleanly, so
# this install is optional but recommended.
if ! command -v az >/dev/null 2>&1; then
  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash || {
    echo "[!] az cli install failed - continuing without it. Login scripts will skip az login."
  }
fi

# Optional: reduce layer size in containers/CI
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*
