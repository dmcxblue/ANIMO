param([string]$Username,[string]$Password)
$ErrorActionPreference='Stop'
$mfa='AADSTS50076|AADSTS50079|AADSTS50158|AADSTS53003|AADSTS50074|AADSTS500121'
try {
    $c=[PSCredential]::new($Username,(ConvertTo-SecureString $Password -AsPlainText -Force))
    Connect-AzAccount -Credential $c -EA Stop -WA Ignore|Out-Null
    $t=(Get-AzAccessToken -AsSecureString -ResourceTypeName MSGraph).Token
    Connect-MgGraph -AccessToken $t -NoWelcome -EA Stop|Out-Null
    Clear-AzContext -Force
    Write-Output "__ANIMO_LOGIN_OK__:$Username"
} catch {
    $e=$_.Exception.Message
    if($e-match$mfa){Write-Output "__ANIMO_MFA_REQUIRED__:$($Matches[0]):$e"}
    else{Write-Output "__ANIMO_LOGIN_FAIL__:$e"}
}
