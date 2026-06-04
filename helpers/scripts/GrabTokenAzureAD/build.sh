#!/bin/bash
cd "$(dirname "$0")"

echo "[*] Building DLL (library)..."
dotnet build GrabTokenAzureAD.csproj -c Release --no-incremental -v q

echo ""
echo "[*] Building GrabTokenAzureAD.exe (OAuth only, supports parameters)..."
dotnet build GrabTokenAzureAD.Console.csproj -c Release --no-incremental -v q

echo ""
echo "[*] Building GrabToken.exe (Combined PRT + OAuth, hardcoded)..."
dotnet build GrabToken.csproj -c Release --no-incremental -v q

echo ""
echo "=== DLL Output ==="
ls -la bin/Release/netstandard2.0/GrabTokenAzureAD.dll bin/Release/net48/GrabTokenAzureAD.dll 2>/dev/null

echo ""
echo "=== EXE Output ==="
echo "GrabTokenAzureAD.exe - OAuth only, accepts command-line parameters"
ls -la bin/Release/net48/GrabTokenAzureAD.exe 2>/dev/null
echo ""
echo "GrabToken.exe - Combined PRT + OAuth, hardcoded values"
ls -la bin/Release/net48/GrabToken.exe 2>/dev/null
