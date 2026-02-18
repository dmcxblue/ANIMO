#!/usr/bin/bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/build"

rm -rf data

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(nproc || sysctl -n hw.ncpu || echo 4)

echo
echo "Binaries:"
echo "  $BUILD_DIR/server/AnimoServer"
echo "  $BUILD_DIR/client/AnimoClient"
