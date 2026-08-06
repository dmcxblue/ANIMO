param([string]$CredentialFile,[string]$Resource='https://management.azure.com')
$ErrorActionPreference='Stop'
try {
    if(-not(Test-Path $CredentialFile)){throw "Credential file not found"}
    $credJson=Get-Content $CredentialFile -Raw|ConvertFrom-Json
    $AppId=$credJson.appId
    $ClientSecret=$credJson.clientSecret
    $TenantId=$credJson.tenantId
    Remove-Item $CredentialFile -Force -EA SilentlyContinue
    $sec=ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $cred=[PSCredential]::new($AppId,$sec)
    Connect-AzAccount -ServicePrincipal -Credential $cred -TenantId $TenantId -EA Stop -WA Ignore|Out-Null

    # Connect-AzAccount doesn't pin a subscription for SPNs. Without one the Az
    # context is essentially scope-less: Get-AzResource / Get-AzVM / etc. silently
    # return nothing because their ARM query targets /subscriptions/<none>/...
    # Enumerate what this SPN can reach and select the first, so cmdlets Just Work.
    $subs = @()
    try { $subs = @(Get-AzSubscription -TenantId $TenantId -EA SilentlyContinue) } catch { $subs = @() }
    if ($subs -and $subs.Count -gt 0) {
        try { Set-AzContext -Subscription $subs[0].Id -TenantId $TenantId -EA Stop -WA Ignore | Out-Null } catch {}
        Write-Output ("[Animo] SPN has access to {0} subscription(s):" -f $subs.Count)
        foreach ($s in $subs) { Write-Output ("[Animo]   - {0}  ({1})" -f $s.Name, $s.Id) }
        Write-Output ("[Animo] Active subscription pinned: {0}" -f $subs[0].Name)
        Write-Output "[Animo] To switch: Set-AzContext -Subscription '<SubId>'"
    } else {
        Write-Output "[Animo] WARNING: this SPN has NO Azure RBAC assignments on any subscription in this tenant."
        Write-Output "[Animo] Az cmdlets like Get-AzResource / Get-AzVM will return nothing until the SPN is granted"
        Write-Output "[Animo] a role (Reader is enough for enumeration) on a subscription, RG, or resource."
    }

    # Also log az cli in with the same SPN creds so operators can use az one-liners
    # in the same terminal (az cli maintains a separate token cache from Az PS).
    # Silent no-op if az isn't on PATH.
    try {
        if (Get-Command az -EA SilentlyContinue) {
            $azOut = (& az login --service-principal -u $AppId -p $ClientSecret --tenant $TenantId --allow-no-subscriptions --output none) 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Output "[Animo] az cli logged in as SPN (both Az PS and az cli contexts active)"
                # Warm the az cli token cache for the chosen resource so both
                # toolchains have parity. Silent on failure - Az PS still emitted
                # __ANIMO_TOKEN__ below.
                try {
                    $azTok = (& az account get-access-token --resource $Resource -o tsv --query accessToken 2>$null)
                    if ($LASTEXITCODE -eq 0 -and $azTok) {
                        Write-Output "[Animo] az cli minted token for $Resource"
                    }
                } catch {}
            } else {
                Write-Output ("[Animo] az cli login failed (exit {0}): {1}" -f $LASTEXITCODE, ($azOut | Out-String).Trim())
            }
        } else {
            Write-Output "[Animo] az cli not installed; skipping az login (Az PS context is active)"
        }
    } catch {
        Write-Output "[Animo] az cli login error: $($_.Exception.Message)"
    }

    $ctx=Get-AzContext -EA SilentlyContinue
    if($ctx-and$ctx.Account){
        # Az PS 12+ returns .Token as SecureString by default (breaking change from Az 11).
        # Interpolating a SecureString straight into a string yields the literal
        # "System.Security.SecureString" - so unwrap it explicitly.
        try {
            $tok = Get-AzAccessToken -ResourceUrl $Resource -EA SilentlyContinue
            if ($tok -and $tok.Token) {
                $t = if ($tok.Token -is [System.Security.SecureString]) {
                    $tok.Token | ConvertFrom-SecureString -AsPlainText
                } else { $tok.Token }
                if ($t) {
                    Write-Output "[Animo] Access Token ($Resource):"
                    Write-Output $t
                    Write-Output "__ANIMO_TOKEN__:$t"
                }
            }
        } catch {}
        Write-Output "__ANIMO_LOGIN_OK__:$($ctx.Account)"
    }
    else{Write-Output "__ANIMO_LOGIN_FAIL__:No context"}
} catch {
    Write-Output "__ANIMO_LOGIN_FAIL__:$($_.Exception.Message)"
}
