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
  snapd

sudo snap install powershell --classic

# Optional: reduce layer size in containers/CI
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*
