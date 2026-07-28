#!/usr/bin/env python3
"""
MSAL Authentication Helper for ANIMO
Handles Azure AD authentication with ROPC and interactive browser fallback.

Usage:
    python msal_auth.py --username USER --password PASS --resource RESOURCE [--client-id ID] [--tenant TENANT]
    python msal_auth.py --interactive --resource RESOURCE [--client-id ID] [--tenant TENANT]

Output (JSON on stdout):
    Success: {"status": "success", "access_token": "...", "refresh_token": "...", "id_token": "...", "tenant_id": "...", "upn": "..."}
    Error:   {"status": "error", "message": "..."}
    MFA:     {"status": "mfa_required", "message": "..."}
"""

import sys
import json
import argparse

# Default Azure PowerShell client ID
DEFAULT_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"

def output_json(data):
    """Output JSON to stdout and exit"""
    print(json.dumps(data), flush=True)
    sys.exit(0 if data.get("status") == "success" else 1)

def output_error(message):
    """Output error and exit"""
    output_json({"status": "error", "message": str(message)})

def output_mfa_required(message="MFA required"):
    """Output MFA required signal"""
    output_json({"status": "mfa_required", "message": str(message)})

def output_success(access_token, refresh_token=None, id_token=None, tenant_id=None, upn=None):
    """Output success with tokens"""
    result = {
        "status": "success",
        "access_token": access_token,
        "refresh_token": refresh_token or "",
        "id_token": id_token or "",
        "tenant_id": tenant_id or "",
        "upn": upn or ""
    }
    output_json(result)

def decode_jwt_claim(token, claim):
    """Extract a claim from a JWT without cryptographic verification.

    Note: This only parses claims from tokens already received from MSAL.
    Signature verification is handled by the MSAL library during acquisition.
    Do NOT use this to validate tokens from untrusted sources.
    """
    if not token or not isinstance(token, str):
        return None
    try:
        import base64
        parts = token.split('.')
        if len(parts) < 2:
            return None

        # Decode payload (part 1)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += '=' * padding

        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded)
        if not isinstance(data, dict):
            return None
        return data.get(claim)
    except Exception:
        return None

def try_ropc_login(username, password, resource, client_id, tenant):
    """Try Resource Owner Password Credential flow"""
    try:
        from msal import PublicClientApplication

        authority = f"https://login.microsoftonline.com/{tenant}"
        scopes = [f"{resource}/.default"]

        app = PublicClientApplication(client_id, authority=authority)
        result = app.acquire_token_by_username_password(username, password, scopes=scopes)

        if "access_token" in result:
            access_token = result["access_token"]
            refresh_token = result.get("refresh_token", "")
            id_token = result.get("id_token", "")

            # Extract tenant and UPN from tokens
            tenant_id = decode_jwt_claim(id_token, "tid") or decode_jwt_claim(access_token, "tid") or ""
            upn = decode_jwt_claim(id_token, "upn") or decode_jwt_claim(id_token, "preferred_username") or ""
            if not upn:
                upn = decode_jwt_claim(access_token, "upn") or decode_jwt_claim(access_token, "unique_name") or username

            return {
                "success": True,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "tenant_id": tenant_id,
                "upn": upn
            }
        else:
            # Check for MFA-related errors
            error = result.get("error", "")
            error_desc = result.get("error_description", "")

            mfa_codes = ["AADSTS50076", "AADSTS50079", "AADSTS50158",
                        "AADSTS53003", "AADSTS50074", "AADSTS500121"]

            for code in mfa_codes:
                if code in error_desc:
                    return {"mfa_required": True, "message": error_desc}

            return {"success": False, "message": error_desc or error or "ROPC login failed"}

    except Exception as e:
        return {"success": False, "message": str(e)}

def try_interactive_login(resource, client_id, tenant, expected_username=None):
    """Try interactive browser login.

    expected_username: the account this session is supposed to be for. We pass it as a
    login_hint and force the account picker (prompt=select_account) so a leftover browser
    SSO cookie for a different user can't silently sign us in as the wrong account. After
    login we verify the returned UPN matches, and fail on mismatch.
    """
    try:
        from msal import PublicClientApplication

        authority = f"https://login.microsoftonline.com/{tenant}"
        scopes = [f"{resource}/.default"]

        app = PublicClientApplication(client_id, authority=authority)

        # login_hint pre-fills the requested user; prompt=select_account defeats silent SSO.
        kwargs = {"scopes": scopes, "prompt": "select_account"}
        if expected_username:
            kwargs["login_hint"] = expected_username
        result = app.acquire_token_interactive(**kwargs)

        if "access_token" in result:
            access_token = result["access_token"]
            refresh_token = result.get("refresh_token", "")
            id_token = result.get("id_token", "")

            # Extract tenant and UPN
            tenant_id = decode_jwt_claim(id_token, "tid") or decode_jwt_claim(access_token, "tid") or ""
            upn = decode_jwt_claim(id_token, "upn") or decode_jwt_claim(id_token, "preferred_username") or ""
            if not upn:
                upn = decode_jwt_claim(access_token, "upn") or decode_jwt_claim(access_token, "unique_name") or ""

            # Guard against signing in as the wrong account (SSO shortcut, wrong pick).
            if expected_username and upn and upn.lower() != expected_username.lower():
                return {"success": False,
                        "message": f"Signed-in account '{upn}' does not match the requested "
                                   f"user '{expected_username}'. Aborted to avoid a mismatched session."}

            return {
                "success": True,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "tenant_id": tenant_id,
                "upn": upn
            }
        else:
            error = result.get("error", "")
            error_desc = result.get("error_description", "")
            return {"success": False, "message": error_desc or error or "Interactive login failed"}

    except Exception as e:
        return {"success": False, "message": str(e)}

def main():
    parser = argparse.ArgumentParser(description="MSAL Authentication Helper")
    parser.add_argument("--username", "-u", help="Username for ROPC")
    parser.add_argument("--password", "-p", help="Password for ROPC")
    parser.add_argument("--resource", "-r", required=True, help="Resource/audience URL")
    parser.add_argument("--client-id", "-c", default=DEFAULT_CLIENT_ID, help="Azure AD client ID")
    parser.add_argument("--tenant", "-t", default="organizations", help="Tenant (default: organizations)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Force interactive login")
    parser.add_argument("--ropc-only", action="store_true", help="Only try ROPC, don't fallback to interactive")

    args = parser.parse_args()

    # Validate arguments
    if not args.interactive and (not args.username or not args.password):
        output_error("Username and password required for ROPC login (or use --interactive)")

    # Check for msal module
    try:
        import msal
    except ImportError:
        output_error("MSAL module not installed. Run: pip install msal")

    if args.interactive:
        # Direct interactive login
        result = try_interactive_login(args.resource, args.client_id, args.tenant, args.username)
        if result.get("success"):
            output_success(
                result["access_token"],
                result["refresh_token"],
                result["id_token"],
                result["tenant_id"],
                result["upn"]
            )
        else:
            output_error(result.get("message", "Interactive login failed"))
    else:
        # Try ROPC first
        result = try_ropc_login(args.username, args.password, args.resource, args.client_id, args.tenant)

        if result.get("success"):
            output_success(
                result["access_token"],
                result["refresh_token"],
                result["id_token"],
                result["tenant_id"],
                result["upn"]
            )
        elif result.get("mfa_required"):
            if args.ropc_only:
                output_mfa_required(result.get("message", "MFA required"))
            else:
                # Fallback to interactive
                sys.stderr.write("[*] ROPC failed, launching interactive browser...\n")
                sys.stderr.flush()

                interactive_result = try_interactive_login(args.resource, args.client_id, args.tenant, args.username)
                if interactive_result.get("success"):
                    output_success(
                        interactive_result["access_token"],
                        interactive_result["refresh_token"],
                        interactive_result["id_token"],
                        interactive_result["tenant_id"],
                        interactive_result["upn"]
                    )
                else:
                    output_error(interactive_result.get("message", "Interactive login failed"))
        else:
            if args.ropc_only:
                output_error(result.get("message", "ROPC login failed"))
            else:
                # Fallback to interactive for any failure
                sys.stderr.write(f"[*] ROPC failed: {result.get('message', 'Unknown error')}\n")
                sys.stderr.write("[*] Launching interactive browser...\n")
                sys.stderr.flush()

                interactive_result = try_interactive_login(args.resource, args.client_id, args.tenant, args.username)
                if interactive_result.get("success"):
                    output_success(
                        interactive_result["access_token"],
                        interactive_result["refresh_token"],
                        interactive_result["id_token"],
                        interactive_result["tenant_id"],
                        interactive_result["upn"]
                    )
                else:
                    output_error(interactive_result.get("message", "Interactive login failed"))

if __name__ == "__main__":
    main()
