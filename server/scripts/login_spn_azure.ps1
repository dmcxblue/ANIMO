param([string]$CredentialFile)
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

    $ctx=Get-AzContext -EA SilentlyContinue
    if($ctx-and$ctx.Account){
        try{
            $tok=Get-AzAccessToken -EA SilentlyContinue
            if($tok-and$tok.Token){Write-Output "__ANIMO_TOKEN__:$($tok.Token)"}
        }catch{}
        Write-Output "__ANIMO_LOGIN_OK__:$($ctx.Account)"
    }
    else{Write-Output "__ANIMO_LOGIN_FAIL__:No context"}
} catch {
    Write-Output "__ANIMO_LOGIN_FAIL__:$($_.Exception.Message)"
}
