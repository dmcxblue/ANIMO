#!/usr/bin/env bash
set -euo pipefail

echo "[*] Checking toolchain..."
command -v cmake >/dev/null || { echo "[-] cmake not found"; exit 1; }
command -v c++ >/dev/null || echo "[!] C++ compiler not found in PATH"
if command -v ninja >/dev/null; then gen="-G Ninja"; else gen=""; fi

echo "[*] Checking Qt (qmake or pkg-config for Qt)..."
if command -v qmake >/dev/null; then echo "[+] qmake found: $(qmake -v | head -n1)"; else echo "[!] qmake not found (ok if using CMake find modules)"; fi

echo "[*] Preparing build directory..."
mkdir -p build
cd build

echo "[*] Configuring..."
cmake $gen -DCMAKE_BUILD_TYPE=Release ..

echo "[*] Building..."
cmake --build . --config Release -- -j$(nproc 2>/dev/null || sysctl -n hw.ncpu || echo 2)

echo "[*] Build done."
