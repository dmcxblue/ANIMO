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
