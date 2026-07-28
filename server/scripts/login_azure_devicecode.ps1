$ErrorActionPreference='Stop'
# Full interactive login: device code runs INSIDE Az, so the context keeps a real
# token cache + refresh token. Unlike -AccessToken, this lets Get-AzAccessToken mint
# any resource (KeyVault, Storage, Graph) on demand -> data-plane cmdlets work.
# The "enter the code XXXX" prompt is written to the warning/info streams; merge them
# to output so it streams live to the Session Tab.
try {
    # Clean context first so a stale persisted AccessToken login can't shadow this one.
    Disconnect-AzAccount -EA SilentlyContinue|Out-Null
    Clear-AzContext -Force -EA SilentlyContinue|Out-Null
    Connect-AzAccount -UseDeviceAuthentication -WA Continue -InformationAction Continue *>&1 |
        ForEach-Object { Write-Output $_ }
    $ctx=Get-AzContext -EA SilentlyContinue
    if($ctx-and$ctx.Account){
        try{$t=(Get-AzAccessToken -ResourceUrl 'https://management.azure.com' -EA Stop).Token;Write-Output "__ANIMO_TOKEN__:$t"}catch{}
        Write-Output "__ANIMO_LOGIN_OK__:$($ctx.Account)"
    }
    else{Write-Output "__ANIMO_LOGIN_FAIL__:No context after device-code login"}
} catch {
    Write-Output "__ANIMO_LOGIN_FAIL__:$($_.Exception.Message)"
}
