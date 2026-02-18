param([string]$Username,[string]$Password)
$ErrorActionPreference='Stop'
$mfa='AADSTS50076|AADSTS50079|AADSTS50158|AADSTS53003|AADSTS50074|AADSTS500121'
try {
    $c=[PSCredential]::new($Username,(ConvertTo-SecureString $Password -AsPlainText -Force))
    Connect-AzAccount -Credential $c -EA Stop -WA Ignore|Out-Null
    $ctx=Get-AzContext -EA SilentlyContinue
    if($ctx-and$ctx.Account){Write-Output "__ANIMO_LOGIN_OK__:$($ctx.Account)"}
    else{Write-Output "__ANIMO_LOGIN_FAIL__:No context"}
} catch {
    $e=$_.Exception.Message
    if($e-match$mfa){Write-Output "__ANIMO_MFA_REQUIRED__:$($Matches[0]):$e"}
    else{Write-Output "__ANIMO_LOGIN_FAIL__:$e"}
}
