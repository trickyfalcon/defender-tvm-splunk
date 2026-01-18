#!/usr/bin/env python3
"""Defender TVM DELTA fetcher (Memory Optimized).

Fetches only vulnerability CHANGES (New/Fixed/Updated) since a specified time.
Ideal for daily scheduled runs to track remediation progress.

Sourcetype: defender:tvm:delta

Uses generators to stream data - Memory usage: ~500MB (catalog only)

Requires:
  pip install requests cryptography
"""

import argparse
import base64
import datetime as dt
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, Generator, List, Optional

import requests

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

API_BASE = "https://api.securitycenter.microsoft.com/api"
TOKEN_SCOPE = "https://api.securitycenter.microsoft.com/.default"

# Credentials from environment variables
HARDCODED_TENANT_ID = os.getenv("MDE_TENANT_ID", "")
HARDCODED_CLIENT_ID = os.getenv("MDE_CLIENT_ID", "")
HARDCODED_CLIENT_SECRET = os.getenv("MDE_CLIENT_SECRET", "")
HARDCODED_CERT_PATH = os.getenv("MDE_CERT_PATH", "")
HARDCODED_KEY_PATH = os.getenv("MDE_KEY_PATH", "")

# Splunk HEC (from environment variables)
HEC_ENDPOINT = os.getenv("HEC_ENDPOINT", "")
HEC_TOKEN = os.getenv("HEC_TOKEN", "")
HEC_INDEX = "defender"
HEC_SOURCE = "defender-tvm-delta"
SOURCETYPE = "defender:tvm:delta"


def _parse_iso(s: Optional[str]) -> Optional[dt.datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        parsed = dt.datetime.fromisoformat(s)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except Exception:
        return None


def _age_days(iso: Optional[str]) -> Optional[int]:
    d = _parse_iso(iso)
    if not d:
        return None
    return max(0, (dt.datetime.now(dt.timezone.utc) - d).days)


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _create_client_assertion(tenant_id: str, client_id: str, cert_path: str, key_path: str) -> str:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library required. Install: pip install cryptography")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    thumbprint = cert.fingerprint(hashes.SHA1())
    x5t = _base64url_encode(thumbprint)
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t": x5t}
    payload = {
        "aud": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "exp": now + 600, "iss": client_id, "jti": str(uuid.uuid4()),
        "nbf": now, "sub": client_id, "iat": now,
    }
    header_b64 = _base64url_encode(json.dumps(header).encode())
    payload_b64 = _base64url_encode(json.dumps(payload).encode())
    message = f"{header_b64}.{payload_b64}".encode()
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_base64url_encode(signature)}"


def get_token_with_cert(tenant_id: str, client_id: str, cert_path: str, key_path: str, verify: object) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_assertion": _create_client_assertion(tenant_id, client_id, cert_path, key_path),
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "grant_type": "client_credentials",
        "scope": TOKEN_SCOPE,
    }
    resp = requests.post(url, data=data, timeout=30, verify=verify)
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_token(tenant_id: str, client_id: str, client_secret: str, verify: object) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id, "client_secret": client_secret,
        "grant_type": "client_credentials", "scope": TOKEN_SCOPE,
    }
    resp = requests.post(url, data=data, timeout=30, verify=verify)
    resp.raise_for_status()
    return resp.json()["access_token"]


def paged_get_streaming(
    url: str, headers: Dict[str, str], verify: object,
    limit: Optional[int] = None, max_retries: int = 5, retry_wait: int = 5,
    continue_on_error: bool = False, request_delay: float = 0.0,
) -> Generator[Dict[str, Any], None, None]:
    """Generator that yields records one at a time (memory efficient)."""
    next_url = url
    count = 0
    while next_url:
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = requests.get(next_url, headers=headers, timeout=60, verify=verify)
            except requests.RequestException:
                if attempt > max_retries:
                    if continue_on_error:
                        return
                    raise
                time.sleep(retry_wait)
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt > max_retries:
                    if continue_on_error:
                        return
                    resp.raise_for_status()
                wait = int(resp.headers.get("Retry-After", retry_wait))
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                if continue_on_error:
                    return
                resp.raise_for_status()
            break
        payload = resp.json()
        for record in payload.get("value", []):
            yield record
            count += 1
            if limit and count >= limit:
                return
        next_url = payload.get("@odata.nextLink")
        if request_delay:
            time.sleep(request_delay)


def paged_get(url: str, headers: Dict[str, str], verify: object, **kwargs) -> List[Dict[str, Any]]:
    """Non-streaming version for catalog (needs dict lookup)."""
    return list(paged_get_streaming(url, headers, verify, **kwargs))


def send_hec_raw(session: requests.Session, lines: List[str], verify: object) -> None:
    if not lines:
        return
    url = f"{HEC_ENDPOINT}?sourcetype={SOURCETYPE}&index={HEC_INDEX}&source={HEC_SOURCE}"
    headers = {"Authorization": f"Splunk {HEC_TOKEN}"}
    resp = session.post(url, headers=headers, data=("\n".join(lines) + "\n").encode(), timeout=60, verify=verify)
    resp.raise_for_status()


def build_event(record: Dict[str, Any], catalog_entry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build CIM-compliant event from delta record."""
    cve = record.get("cveId")
    first_seen = record.get("firstSeenTimestamp")
    delta_status = record.get("status")

    event = {
        "dest": record.get("deviceName"),
        "asset_id": record.get("deviceId"),
        "cve": cve,
        "cvss": record.get("cvssScore"),
        "severity": record.get("vulnerabilitySeverityLevel"),
        "delta_status": delta_status,  # New, Fixed, Updated
        "event_timestamp": record.get("eventTimestamp"),
        "exploit_available": record.get("exploitabilityLevel") in ("ExploitIsPublic", "ExploitIsVerified", "ExploitIsInKit"),
        "exploitability": record.get("exploitabilityLevel"),
        "patch_available": record.get("securityUpdateAvailable"),
        "age_days": _age_days(first_seen),
        "os": record.get("osPlatform"),
        "first_seen": first_seen,
        "last_seen": record.get("lastSeenTimestamp"),
        "software_vendor": record.get("softwareVendor"),
        "software_name": record.get("softwareName"),
        "software_version": record.get("softwareVersion"),
        "rbac_group": record.get("rbacGroupName"),
    }

    # Enrich from catalog
    if catalog_entry:
        event["published_date"] = catalog_entry.get("publishedOn")
        event["updated_date"] = catalog_entry.get("updatedOn")
        event["description"] = catalog_entry.get("description")
        event["cvss_vector"] = catalog_entry.get("cvssVector")
        event["epss"] = catalog_entry.get("epss")
        event["public_exploit"] = catalog_entry.get("publicExploit")
        event["exploit_verified"] = catalog_entry.get("exploitVerified")
        event["exploit_in_kit"] = catalog_entry.get("exploitInKit")
        event["exploit_types"] = catalog_entry.get("exploitTypes")
        event["exploit_uris"] = catalog_entry.get("exploitUris")
        if catalog_entry.get("publishedOn"):
            event["age_days"] = _age_days(catalog_entry.get("publishedOn"))

    return event


def main() -> int:
    parser = argparse.ArgumentParser(description="Defender TVM Delta Fetcher")
    parser.add_argument("--tenant-id", default=os.getenv("MDE_TENANT_ID"))
    parser.add_argument("--client-id", default=os.getenv("MDE_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("MDE_CLIENT_SECRET"))
    parser.add_argument("--cert-path", default=os.getenv("MDE_CERT_PATH"))
    parser.add_argument("--key-path", default=os.getenv("MDE_KEY_PATH"))
    parser.add_argument("--since", help="ISO timestamp (e.g., '2025-01-15T00:00:00Z')")
    parser.add_argument("--since-hours", type=int, default=25, help="Hours to look back (default: 25)")
    parser.add_argument("--include-catalog", action="store_true", help="Enrich with catalog data")
    parser.add_argument("--send-hec", action="store_true", help="Send to Splunk HEC")
    parser.add_argument("--hec-batch-size", type=int, default=500, help="Events per HEC batch")
    parser.add_argument("--output", help="Write to JSONL file")
    parser.add_argument("--limit", type=int, default=0, help="Max records (0=unlimited)")
    parser.add_argument("--api-sleep", type=float, default=1.0, help="Seconds between API pages")
    parser.add_argument("--max-retries", type=int, default=5)
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--ca-bundle", default=os.getenv("REQUESTS_CA_BUNDLE"))
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    # Apply hardcoded defaults
    args.tenant_id = args.tenant_id or HARDCODED_TENANT_ID
    args.client_id = args.client_id or HARDCODED_CLIENT_ID
    args.client_secret = args.client_secret or HARDCODED_CLIENT_SECRET
    args.cert_path = args.cert_path or HARDCODED_CERT_PATH
    args.key_path = args.key_path or HARDCODED_KEY_PATH

    use_cert = args.cert_path and args.key_path
    if not args.tenant_id or not args.client_id:
        sys.stderr.write("Missing credentials.\n")
        return 2
    if not use_cert and not args.client_secret:
        sys.stderr.write("Provide --cert-path/--key-path OR --client-secret.\n")
        return 2

    verify = False if args.insecure else (args.ca_bundle or True)

    # Authenticate
    if use_cert:
        sys.stderr.write(f"Authenticating with certificate: {args.cert_path}\n")
        token = get_token_with_cert(args.tenant_id, args.client_id, args.cert_path, args.key_path, verify)
    else:
        sys.stderr.write("\n")
        sys.stderr.write("=" * 70 + "\n")
        sys.stderr.write("DEPRECATION WARNING: Client secret authentication is deprecated.\n")
        sys.stderr.write("Please migrate to certificate-based authentication.\n")
        sys.stderr.write("Use --cert-path and --key-path options instead of --client-secret.\n")
        sys.stderr.write("=" * 70 + "\n\n")
        sys.stderr.write("Authenticating with client secret (legacy)\n")
        token = get_token(args.tenant_id, args.client_id, args.client_secret, verify)

    headers = {"Authorization": f"Bearer {token}"}
    hec_session = requests.Session()
    hec_buffer: List[str] = []
    output_handle = open(args.output, "a", encoding="utf-8") if args.output else None

    # Load catalog for enrichment
    catalog_by_id: Dict[str, Dict[str, Any]] = {}
    if args.include_catalog:
        sys.stderr.write("Fetching vulnerability catalog for enrichment...\n")
        for item in paged_get(f"{API_BASE}/vulnerabilities", headers, verify,
                              max_retries=args.max_retries, continue_on_error=args.continue_on_error,
                              request_delay=args.api_sleep):
            key = item.get("id") or item.get("name")
            if key:
                catalog_by_id[key] = item
        sys.stderr.write(f"Loaded {len(catalog_by_id)} CVEs from catalog.\n")

    # Calculate since time
    if args.since:
        since_time = args.since
    else:
        since_dt = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=args.since_hours)
        since_time = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    sys.stderr.write(f"Fetching vulnerability CHANGES since {since_time}...\n")
    delta_url = f"{API_BASE}/machines/SoftwareVulnerabilityChangesByMachine?sinceTime={since_time}"

    event_count = 0
    status_counts: Dict[str, int] = {}

    for record in paged_get_streaming(
        delta_url, headers, verify,
        limit=args.limit if args.limit > 0 else None,
        max_retries=args.max_retries,
        continue_on_error=args.continue_on_error,
        request_delay=args.api_sleep,
    ):
        status = record.get("status", "Unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

        cve_id = record.get("cveId")
        catalog_entry = catalog_by_id.get(cve_id) if cve_id else None

        hec_event = {
            "time": int(time.time()),
            "source": HEC_SOURCE,
            "sourcetype": SOURCETYPE,
            "event": {
                **build_event(record, catalog_entry),
                "raw": record,
            },
        }
        line = json.dumps(hec_event)
        event_count += 1

        if output_handle:
            output_handle.write(line + "\n")
        if args.send_hec:
            hec_buffer.append(line)
            if len(hec_buffer) >= args.hec_batch_size:
                send_hec_raw(hec_session, hec_buffer, verify)
                hec_buffer.clear()
        if not output_handle and not args.send_hec:
            print(line)

        if event_count % 10000 == 0:
            sys.stderr.write(f"  Processed {event_count} records...\n")

    # Flush remaining
    if args.send_hec and hec_buffer:
        send_hec_raw(hec_session, hec_buffer, verify)
    if output_handle:
        output_handle.close()

    # Summary
    sys.stderr.write(f"Retrieved {event_count} delta records.\n")
    for status, count in sorted(status_counts.items()):
        sys.stderr.write(f"  {status}: {count}\n")
    sys.stderr.write(f"Wrote {event_count} events.\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
