param([string]$Username,[string]$Password,[string]$Resource='https://management.azure.com')
$ErrorActionPreference='Stop'
$mfa='AADSTS50076|AADSTS50079|AADSTS50158|AADSTS53003|AADSTS50074|AADSTS500121'
try {
    # Start from a clean context so a stale persisted AccessToken login can't shadow
    # this ROPC login (would otherwise serve expired tokens). With per-session
    # AZURE_CONFIG_DIR this only touches THIS session's context.
    Disconnect-AzAccount -EA SilentlyContinue|Out-Null
    Clear-AzContext -Force -EA SilentlyContinue|Out-Null
    $c=[PSCredential]::new($Username,(ConvertTo-SecureString $Password -AsPlainText -Force))
    Connect-AzAccount -Credential $c -EA Stop -WA Ignore|Out-Null
    $ctx=Get-AzContext -EA SilentlyContinue
    if($ctx-and$ctx.Account){
        # Az PS 12+ returns .Token as SecureString by default (breaking change from Az 11).
        # Interpolating a SecureString straight into a string yields the literal
        # "System.Security.SecureString" - so unwrap it explicitly.
        try {
            $tok = Get-AzAccessToken -ResourceUrl $Resource -EA Stop
            $t = if ($tok.Token -is [System.Security.SecureString]) {
                $tok.Token | ConvertFrom-SecureString -AsPlainText
            } else { $tok.Token }
            if ($t) {
                Write-Output "[Animo] Access Token ($Resource):"
                Write-Output $t
                Write-Output "__ANIMO_TOKEN__:$t"
            }
        } catch {}
        # Also log az cli in with the same ROPC creds so operators can use az one-liners
        # in the same terminal (az cli keeps a separate token cache from Az PS).
        try {
            if (Get-Command az -EA SilentlyContinue) {
                $tenantId = if ($ctx.Tenant) { $ctx.Tenant.Id } else { $null }
                $azArgs = @('login','-u',$Username,'-p',$Password,'--output','none')
                if ($tenantId) { $azArgs += @('--tenant', $tenantId) }
                $azOut = (& az @azArgs) 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Output "[Animo] az cli logged in (both Az PS and az cli contexts active)"
                    # Also mint a resource-specific token via az cli so both toolchains
                    # have a matching token for the chosen resource. Silent on failure -
                    # the Az PS __ANIMO_TOKEN__ above is what the server captures.
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
        Write-Output "__ANIMO_LOGIN_OK__:$($ctx.Account)"
    }
    else{Write-Output "__ANIMO_LOGIN_FAIL__:No context"}
} catch {
    $e=$_.Exception.Message
    if($e-match$mfa){Write-Output "__ANIMO_MFA_REQUIRED__:$($Matches[0]):$e"}
    else{Write-Output "__ANIMO_LOGIN_FAIL__:$e"}
}
