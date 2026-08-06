param([string]$Resource='https://management.azure.com')
$ErrorActionPreference='Stop'

# ANIMO device-code login (seamless).
#
# ONE device code prompt gets you both az cli AND Az PowerShell logged in.
# A helper Python script (animo_device_code.py, extracted next to this script
# by the server) runs a real MSAL device flow using the Azure CLI client id
# (which is FOCI-eligible), populates $AZURE_CONFIG_DIR/msal_token_cache.json
# so `az` commands work, and hands the resulting AT/RT + FOCI-minted resource
# tokens back to us over stdout as one JSON line. We then bootstrap Az PS via
# Connect-AzAccount -AccessToken (+ GraphAccessToken / KeyVaultAccessToken)
# so Get-AzKeyVaultSecret, storage cmdlets, etc. work natively without a
# second prompt.
#
# The old flow (Connect-AzAccount -UseDeviceAuthentication) is gone: it never
# managed to log az cli in without prompting the operator for a second device
# code, and its Get-AzAccessToken call silently broke on Az PS 12+ (SecureString).

$helperPath = Join-Path $PSScriptRoot 'animo_device_code.py'
if (-not (Test-Path $helperPath)) {
    Write-Output "__ANIMO_LOGIN_FAIL__:MSAL helper missing at $helperPath"
    return
}

$py = $env:ANIMO_PYTHON
if ($py) {
    if (-not (Get-Command $py -EA SilentlyContinue)) {
        Write-Output "__ANIMO_LOGIN_FAIL__:ANIMO_PYTHON points to '$py' which is not on PATH"
        return
    }
} elseif (Get-Command python3 -EA SilentlyContinue) {
    $py = 'python3'
} elseif (Get-Command python -EA SilentlyContinue) {
    $py = 'python'
} else {
    Write-Output "__ANIMO_LOGIN_FAIL__:python3 not found on PATH (install python3 + pip3 install msal)"
    return
}

# Verify msal is importable up-front so we can give a clean error instead of
# waiting until after the user enters a device code.
try {
    $probe = (& $py -c "import msal, sys; sys.stdout.write(msal.__version__)" 2>&1)
} catch {
    Write-Output "__ANIMO_LOGIN_FAIL__:python probe threw: $($_.Exception.Message)"
    return
}
if ($LASTEXITCODE -ne 0) {
    Write-Output "__ANIMO_LOGIN_FAIL__:msal not installed for $py - run: pip3 install msal (got: $probe)"
    return
}
Write-Output "[Animo] MSAL $probe ready. Starting device code flow..."

# Run the helper. Stderr streams to the terminal (device code prompt + status).
# Stdout is exactly one JSON line at the end with all tokens. We split streams
# by redirecting stderr to stdout via 2>&1 and separating the JSON envelope
# from the human-readable lines.
$jsonLine = $null
try {
    & $py $helperPath --resource $Resource --tenant organizations 2>&1 | ForEach-Object {
        $line = "$_"
        # The helper's final result is a single JSON object on stdout.
        if ($line.StartsWith('{') -and $line.Contains('"status"')) {
            $jsonLine = $line
        } else {
            Write-Output $line
        }
    }
} catch {
    Write-Output "__ANIMO_LOGIN_FAIL__:MSAL helper crashed: $($_.Exception.Message)"
    return
}

if (-not $jsonLine) {
    Write-Output "__ANIMO_LOGIN_FAIL__:MSAL helper produced no JSON result"
    return
}

$r = $null
try { $r = $jsonLine | ConvertFrom-Json } catch {
    Write-Output "__ANIMO_LOGIN_FAIL__:Malformed helper output: $($_.Exception.Message)"
    return
}
if ($r.status -ne 'success') {
    $msg = if ($r.message) { $r.message } else { 'unknown MSAL error' }
    Write-Output "__ANIMO_LOGIN_FAIL__:$msg"
    return
}

# Emit token markers up-front, before Az PS bootstrap. The tokens are already
# valid at this point (MSAL succeeded + az cli cache is written); even if the
# Az PS Connect-AzAccount step later fails, the client should still receive
# the AT / RT / FOCI-minted resource tokens so the plugin windows work.
Write-Output "[Animo] Access Token ($Resource):"
Write-Output $r.access_token
Write-Output "__ANIMO_TOKEN__:$($r.access_token)"
if ($r.refresh_token)  { Write-Output "__ANIMO_REFRESH__:$($r.refresh_token)" }
if ($r.graph_token)    { Write-Output "__ANIMO_TOKEN_GRAPH__:$($r.graph_token)" }
if ($r.keyvault_token) { Write-Output "__ANIMO_TOKEN_KV__:$($r.keyvault_token)" }
if ($r.storage_token)  { Write-Output "__ANIMO_TOKEN_STORAGE__:$($r.storage_token)" }

# Confirm az cli sees the account (the helper wrote its MSAL cache + azureProfile.json).
try {
    if (Get-Command az -EA SilentlyContinue) {
        $azShow = (& az account show -o none 2>&1)
        if ($LASTEXITCODE -eq 0) {
            Write-Output "[Animo] az cli is logged in as $($r.upn) (msal cache + azureProfile.json populated)"
            try {
                $sub = (& az account show --query id -o tsv 2>$null)
                if ($sub) { Write-Output "[Animo] Active subscription: $sub  (switch with: az account set --subscription <id>)" }
            } catch {}
        } else {
            $azErr = ($azShow | Out-String).Trim()
            Write-Output "[Animo] az cli cache written but az account show failed: $azErr"
        }
    } else {
        Write-Output "[Animo] az cli not installed; skipping az verification (Az PS still logged in below)"
    }
} catch {}

# Bootstrap Az PowerShell with the AT (and FOCI-minted per-resource tokens).
# Connect-AzAccount -AccessToken is limited compared to a real interactive
# login - it can't mint fresh tokens on demand - so we pass the pre-minted
# GraphAccessToken and KeyVaultAccessToken to cover the common data planes.
try {
    Disconnect-AzAccount -EA SilentlyContinue | Out-Null
    Clear-AzContext -Force -EA SilentlyContinue | Out-Null

    $connectArgs = @{
        AccessToken   = $r.access_token
        AccountId     = $r.upn
        Tenant        = $r.tenant_id
        WarningAction = 'Ignore'
        ErrorAction   = 'Stop'
    }
    if ($r.graph_token)    { $connectArgs['GraphAccessToken']    = $r.graph_token }
    if ($r.keyvault_token) { $connectArgs['KeyVaultAccessToken'] = $r.keyvault_token }
    Connect-AzAccount @connectArgs | Out-Null

    $ctx = Get-AzContext -EA SilentlyContinue
    if ($ctx -and $ctx.Account) {
        Write-Output "[Animo] Az PowerShell logged in as $($r.upn) (tenant $($r.tenant_id))"
        if ($r.graph_token)    { Write-Output "[Animo] Graph AT pre-loaded (Connect-MgGraph -AccessToken ...)" }
        if ($r.keyvault_token) { Write-Output "[Animo] Key Vault AT pre-loaded (Get-AzKeyVaultSecret works)" }
        Write-Output "__ANIMO_LOGIN_OK__:$($r.upn)"
    } else {
        # Tokens are already emitted above; treat this as a partial-success -
        # the client still gets a usable session (plugin windows work), just
        # without an Az PS context in the terminal.
        Write-Output "[Animo] WARNING: Az PowerShell Connect-AzAccount returned no context - terminal Az cmdlets unavailable, plugin windows still work."
        Write-Output "__ANIMO_LOGIN_OK__:$($r.upn)"
    }
} catch {
    # Same rationale as above - don't nuke a successful MSAL login just because
    # Connect-AzAccount had a wobble.
    Write-Output "[Animo] WARNING: Az PowerShell bootstrap failed ($($_.Exception.Message)) - terminal Az cmdlets unavailable, plugin windows still work."
    Write-Output "__ANIMO_LOGIN_OK__:$($r.upn)"
}
