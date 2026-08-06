#!/usr/bin/env python3
"""
ANIMO Device Code Login (MSAL)

One device code prompt gets you tokens for BOTH az cli AND Az PowerShell.
Uses the Azure CLI client_id (FOCI-eligible) to acquire an RT that can be
redeemed for other FOCI clients (Az PS, Graph, Key Vault, Storage) without
a second prompt.

Writes az cli's MSAL cache to $AZURE_CONFIG_DIR/msal_token_cache.json and a
minimal azureProfile.json (populated from GET /subscriptions) so
`az account show` / `az keyvault secret list` / `az storage ...` Just Work.

Streams the device-code prompt to stderr (which pwsh forwards to the session
terminal). Emits ONE JSON line on stdout at the end:

    {"status":"success","access_token":"...","refresh_token":"...","id_token":"...",
     "tenant_id":"...","upn":"...","graph_token":"...","keyvault_token":"...",
     "storage_token":"..."}

Failures emit {"status":"error","message":"..."} and exit 1.
"""

import argparse
import json
import os
import sys
import time

# FOCI client IDs. A refresh token issued to any FOCI member can be redeemed
# for any other FOCI member without re-prompting the user - this is what makes
# the flow seamless across az cli, Az PS, Graph, etc.
AZ_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
AZ_PS_CLIENT_ID  = "1950a258-227b-4e31-a9cf-717495945fc2"

# Resource -> Az PS -*AccessToken param label. We mint these upfront so a single
# Connect-AzAccount call gives the operator working data-plane cmdlets for the
# most common services without needing to refresh the AT for each resource.
EXTRA_RESOURCES = [
    ("graph_token",    "https://graph.microsoft.com"),
    ("keyvault_token", "https://vault.azure.net"),
    ("storage_token",  "https://storage.azure.com"),
]


def emit(payload):
    """Print one JSON line to stdout and exit with matching status."""
    print(json.dumps(payload), flush=True)
    sys.exit(0 if payload.get("status") == "success" else 1)


def log_stderr(msg):
    sys.stderr.write(msg if msg.endswith("\n") else msg + "\n")
    sys.stderr.flush()


def decode_jwt_claim(token, claim):
    """Best-effort JWT claim extraction. Returns None on any failure."""
    if not token or not isinstance(token, str):
        return None
    try:
        import base64
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        if not isinstance(data, dict):
            return None
        return data.get(claim)
    except Exception:
        return None


def redeem_rt(msal_mod, client_id, refresh_token, scopes, authority):
    """FOCI: redeem an RT issued to one FOCI client for another."""
    try:
        app = msal_mod.PublicClientApplication(client_id, authority=authority)
        return app.acquire_token_by_refresh_token(refresh_token, scopes=scopes)
    except Exception as e:
        return {"error": str(e)}


def populate_azure_profile(az_cfg_dir, upn, tenant_id, access_token):
    """Write $AZURE_CONFIG_DIR/azureProfile.json so `az account show` returns
    something immediately. Subscriptions come from ARM's /subscriptions endpoint.

    Silently degrades if requests isn't installed, ARM rejects, or the write
    fails - none of it should abort the login."""
    try:
        import requests
    except Exception:
        return
    if not access_token or not upn:
        return

    subs = []
    try:
        r = requests.get(
            "https://management.azure.com/subscriptions?api-version=2020-01-01",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if r.status_code == 200:
            body = r.json()
            for s in body.get("value", []):
                subs.append({
                    "id": s.get("subscriptionId", ""),
                    "name": s.get("displayName", ""),
                    "state": s.get("state", "Enabled"),
                    "user": {"name": upn, "type": "user"},
                    "isDefault": False,
                    "tenantId": s.get("tenantId", tenant_id),
                    "homeTenantId": s.get("tenantId", tenant_id),
                    "environmentName": "AzureCloud",
                    "managedByTenants": s.get("managedByTenants", []),
                })
    except Exception as e:
        log_stderr(f"[Animo] Warning: could not enumerate subscriptions: {e}")

    if subs:
        subs[0]["isDefault"] = True

    profile = {
        "installationId": "",
        "subscriptions": subs,
    }
    try:
        prof_path = os.path.join(az_cfg_dir, "azureProfile.json")
        with open(prof_path, "w", encoding="utf-8") as f:
            json.dump(profile, f)
        os.chmod(prof_path, 0o600)
    except Exception as e:
        log_stderr(f"[Animo] Warning: could not write azureProfile.json: {e}")


def main():
    ap = argparse.ArgumentParser(description="ANIMO seamless device-code login (MSAL)")
    ap.add_argument("--resource", required=True,
                    help="Primary resource URL (audience of the ARM-family AT)")
    ap.add_argument("--tenant", default="organizations",
                    help="Tenant ID or 'organizations' (default, work/school accounts)")
    ap.add_argument("--client-id", default=AZ_CLI_CLIENT_ID,
                    help=f"Client ID for the device flow (default: Azure CLI, {AZ_CLI_CLIENT_ID})")
    args = ap.parse_args()

    try:
        import msal
    except ImportError:
        emit({"status": "error",
              "message": "MSAL not installed. Run: pip3 install msal"})

    authority = f"https://login.microsoftonline.com/{args.tenant}"
    scopes = [f"{args.resource}/.default"]

    # az cli's MSAL cache path. The server sets AZURE_CONFIG_DIR per session, so
    # populating this file makes `az` work in the session terminal without any
    # further login.
    az_cfg = os.environ.get("AZURE_CONFIG_DIR") or os.path.expanduser("~/.azure")
    try:
        os.makedirs(az_cfg, exist_ok=True)
    except Exception as e:
        emit({"status": "error", "message": f"Could not create {az_cfg}: {e}"})
    cache_path = os.path.join(az_cfg, "msal_token_cache.json")

    cache = msal.SerializableTokenCache()
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r") as f:
                cache.deserialize(f.read())
        except Exception:
            pass  # start fresh on corruption

    app = msal.PublicClientApplication(
        args.client_id, authority=authority, token_cache=cache
    )

    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        emit({"status": "error",
              "message": "initiate_device_flow failed: " + json.dumps(flow)})

    log_stderr(f"[Animo] {flow['message']}")
    log_stderr(f"[Animo] User code: {flow['user_code']}")
    log_stderr(f"[Animo] Verification URL: {flow.get('verification_uri', 'https://microsoft.com/devicelogin')}")
    log_stderr(f"[Animo] Waiting for authentication (expires in {flow['expires_in']}s)...")

    result = app.acquire_token_by_device_flow(flow)  # polls until user completes or timeout

    if "access_token" not in result:
        emit({"status": "error",
              "message": result.get("error_description")
                         or result.get("error")
                         or "Device flow failed with no error message"})

    # Persist az cli's MSAL cache so `az` commands work in this session.
    if cache.has_state_changed:
        try:
            with open(cache_path, "w") as f:
                f.write(cache.serialize())
            os.chmod(cache_path, 0o600)
            log_stderr(f"[Animo] Wrote az cli MSAL cache: {cache_path}")
        except Exception as e:
            log_stderr(f"[Animo] Warning: could not write MSAL cache: {e}")

    access_token  = result["access_token"]
    refresh_token = result.get("refresh_token", "")
    id_token      = result.get("id_token", "")
    tenant_id = (decode_jwt_claim(id_token, "tid")
                 or decode_jwt_claim(access_token, "tid") or "")
    upn = (decode_jwt_claim(id_token, "upn")
           or decode_jwt_claim(id_token, "preferred_username")
           or decode_jwt_claim(access_token, "upn")
           or decode_jwt_claim(access_token, "unique_name") or "")

    # Populate az cli's azureProfile.json (subscription list) so `az account
    # show` / `az account list` return the same data they would after a native
    # `az login`.
    populate_azure_profile(az_cfg, upn, tenant_id, access_token)

    # Mint per-resource ATs via FOCI so pwsh can hand them to Az PS in one
    # Connect-AzAccount call. Use the resolved tenant if we got one - "organizations"
    # can't mint data-plane tokens.
    resource_authority = f"https://login.microsoftonline.com/{tenant_id or args.tenant}"
    extras = {}
    if refresh_token:
        for label, res in EXTRA_RESOURCES:
            r = redeem_rt(msal, AZ_PS_CLIENT_ID, refresh_token,
                          [f"{res}/.default"], resource_authority)
            if "access_token" in r:
                extras[label] = r["access_token"]
            else:
                log_stderr(f"[Animo] FOCI mint {label} skipped: "
                           f"{r.get('error_description') or r.get('error') or 'unknown'}")

    emit({
        "status": "success",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "tenant_id": tenant_id,
        "upn": upn,
        **extras,
    })


if __name__ == "__main__":
    main()
