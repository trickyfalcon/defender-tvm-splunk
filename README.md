# Microsoft Defender TVM to Splunk Exporter

A Python utility that fetches vulnerability data from Microsoft Defender for Endpoint (MDE) Threat & Vulnerability Management (TVM) APIs and streams it to Splunk HEC for security monitoring, dashboards, and metrics.

**Author:** Mohammed Ali
**License:** MIT

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scheduling with Cron](#scheduling-with-cron)
- [Splunk Integration](#splunk-integration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **Two Export Modes**: Separate scripts for bulk (full snapshot) and delta (changes only)
- **Memory Optimized**: Streaming architecture uses ~500MB regardless of dataset size
- **Catalog Enrichment**: Enriches data with published dates, EPSS scores, descriptions, exploit details
- **Splunk HEC Integration**: Streams events directly to Splunk HTTP Event Collector
- **Clear Sourcetypes**: `defender:tvm:bulk` and `defender:tvm:delta` for easy dashboard building
- **Certificate Authentication**: Secure 20-year certificate-based auth (recommended)
- **Rate Limit Handling**: Built-in retry logic with exponential backoff for 429/5xx responses
- **Fault Tolerant**: `--continue-on-error` flag allows partial runs to succeed

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DATA FLOW                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────┐         ┌─────────────────────┐                   │
│  │ defender-tvm-bulk.py│         │defender-tvm-delta.py│                   │
│  │                     │         │                     │                   │
│  │ Fetches ALL current │         │ Fetches CHANGES     │                   │
│  │ vulnerabilities     │         │ (New/Fixed/Updated) │                   │
│  │                     │         │                     │                   │
│  │ ~454K records       │         │ ~85K records/day    │                   │
│  │ ~5-10 min runtime   │         │ ~5 min runtime      │                   │
│  └──────────┬──────────┘         └──────────┬──────────┘                   │
│             │                               │                               │
│             ▼                               ▼                               │
│  ┌─────────────────────┐         ┌─────────────────────┐                   │
│  │ defender:tvm:bulk   │         │ defender:tvm:delta  │                   │
│  │    (sourcetype)     │         │    (sourcetype)     │                   │
│  └──────────┬──────────┘         └──────────┬──────────┘                   │
│             │                               │                               │
│             └───────────────┬───────────────┘                               │
│                             ▼                                               │
│                    ┌─────────────────┐                                      │
│                    │   Splunk HEC    │                                      │
│                    │  index=defender │                                      │
│                    └─────────────────┘                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

API Endpoints Used:
  • /machines/SoftwareVulnerabilitiesByMachine     ← Bulk (all current vulns)
  • /machines/SoftwareVulnerabilityChangesByMachine ← Delta (changes only)
  • /vulnerabilities                               ← Catalog enrichment
```

---

## Prerequisites

### Software Requirements

- Python 3.8 or higher
- `requests` library
- `cryptography` library (for certificate auth)

### Microsoft Entra (Azure AD) App Registration

You need an App Registration in Microsoft Entra with the following API permissions:

| Permission | Type | Description |
|------------|------|-------------|
| `Vulnerability.Read.All` | Application | Read vulnerability information |
| `Machine.Read.All` | Application | Read machine information |

#### Step 1: Create the App Registration

1. Go to [Microsoft Entra Admin Center](https://entra.microsoft.com)
2. In the left sidebar, click **Applications** → **App registrations**
3. Click **+ New registration** at the top
4. Fill in the registration form:
   - **Name**: `Defender-TVM-Splunk-Exporter` (or your preferred name)
   - **Supported account types**: Select "Accounts in this organizational directory only"
   - **Redirect URI**: Leave blank (not needed for this application)
5. Click **Register**

#### Step 2: Note Your IDs

After registration, you'll be on the app's Overview page. Copy these values:

- **Application (client) ID** → This is your `MDE_CLIENT_ID`
- **Directory (tenant) ID** → This is your `MDE_TENANT_ID`

#### Step 3: Configure API Permissions

1. In the left sidebar, click **API permissions**
2. Click **+ Add a permission**
3. Select **APIs my organization uses**
4. Search for and select **WindowsDefenderATP**
5. Select **Application permissions** (not Delegated)
6. Check the following permissions:
   - `Vulnerability.Read.All`
   - `Machine.Read.All`
7. Click **Add permissions**
8. Click **Grant admin consent for [Your Organization]** (requires admin privileges)
9. Verify that all permissions show a green checkmark under "Status"

#### Step 4: Configure Authentication (Choose One Method)

**Option A: Certificate Authentication (Recommended)**

1. First, generate a certificate on your server:
   ```bash
   openssl req -x509 -nodes -newkey rsa:2048 \
     -keyout defender-tvm.key \
     -out defender-tvm.crt \
     -days 7300 \
     -subj "/CN=Defender-TVM-Splunk-Exporter/O=YourOrg"
   ```
2. In the Entra portal, go to **Certificates & secrets**
3. Click the **Certificates** tab
4. Click **Upload certificate**
5. Select your `defender-tvm.crt` file and click **Add**
6. Note the **Thumbprint** shown after upload

**Option B: Client Secret Authentication**

1. In the Entra portal, go to **Certificates & secrets**
2. Click the **Client secrets** tab
3. Click **+ New client secret**
4. Enter a description (e.g., "Splunk Exporter") and select an expiration
5. Click **Add**
6. **Immediately copy the secret Value** (it won't be shown again) → This is your `MDE_CLIENT_SECRET`

#### Step 5: Verify Setup

Your app registration is complete. You should have:

| Item | Environment Variable |
|------|---------------------|
| Tenant ID | `MDE_TENANT_ID` |
| Client ID | `MDE_CLIENT_ID` |
| Client Secret (Option B) | `MDE_CLIENT_SECRET` |
| Certificate Path (Option A) | `MDE_CERT_PATH` |
| Key Path (Option A) | `MDE_KEY_PATH` |

### Splunk HEC Configuration

#### Step 1: Enable HTTP Event Collector

1. In Splunk Web, go to **Settings** → **Data Inputs**
2. Click **HTTP Event Collector**
3. Click **Global Settings** (top right)
4. Set **All Tokens** to **Enabled**
5. Note your **HTTP Port Number** (default: 8088)
6. Click **Save**

#### Step 2: Create an Index

1. Go to **Settings** → **Indexes**
2. Click **New Index**
3. Enter **Index Name**: `defender`
4. Set appropriate size limits for your environment
5. Click **Save**

#### Step 3: Create an HEC Token

1. Go to **Settings** → **Data Inputs** → **HTTP Event Collector**
2. Click **New Token**
3. Enter **Name**: `defender-tvm-exporter`
4. Click **Next**
5. Select **Allowed Indexes**: `defender`
6. Set **Default Index**: `defender`
7. Click **Review** → **Submit**
8. **Copy the Token Value** → This is your `HEC_TOKEN`

#### Step 4: Determine Your HEC Endpoint

Your HEC endpoint URL format:
- **Splunk Cloud**: `https://http-inputs-<your-stack>.splunkcloud.com:443/services/collector/raw`
- **Splunk Enterprise**: `https://<your-server>:8088/services/collector/raw`

This is your `HEC_ENDPOINT` environment variable.

---

## Installation

```bash
# Create directory on server
mkdir -p /opt/Defender-splunk
cd /opt/Defender-splunk

# Copy files
# - defender-tvm-bulk.py
# - defender-tvm-delta.py
# - cron-bulk.sh
# - cron-delta.sh
# - defender-tvm.crt
# - defender-tvm.key

# Install dependencies
pip3 install requests cryptography

# Make scripts executable
chmod +x cron-bulk.sh cron-delta.sh

# Secure the private key
chmod 600 defender-tvm.key

# Create log files
touch /var/log/defender-tvm-bulk.log
touch /var/log/defender-tvm-delta.log
```

---

## Configuration

### Environment Variables

All credentials are configured via environment variables. Create a `.env` file or export them in your shell:

```bash
# Microsoft Defender / Entra ID
export MDE_TENANT_ID="your-tenant-id"
export MDE_CLIENT_ID="your-client-id"

# Option A: Certificate auth (recommended)
export MDE_CERT_PATH="/opt/Defender-splunk/defender-tvm.crt"
export MDE_KEY_PATH="/opt/Defender-splunk/defender-tvm.key"

# Option B: Client secret auth
export MDE_CLIENT_SECRET="your-client-secret"

# Splunk HEC
export HEC_ENDPOINT="https://your-splunk-instance:8088/services/collector/raw"
export HEC_TOKEN="your-hec-token"
```

For cron jobs, add these exports to `/etc/environment` or source them in the cron scripts.

### Generate Certificate (20-year validity)

If using certificate authentication:

```bash
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout defender-tvm.key \
  -out defender-tvm.crt \
  -days 7300 \
  -subj "/CN=Defender-TVM-Splunk-Exporter/O=YourOrg"

# View thumbprint (needed for Azure upload)
openssl x509 -in defender-tvm.crt -noout -fingerprint -sha1

# Secure the private key
chmod 600 defender-tvm.key
```

Upload `defender-tvm.crt` to the Azure AD App Registration (see Step 4 in Prerequisites).

---

## Usage

### Delta Export (Daily Changes)

Fetches only New/Fixed/Updated vulnerabilities since specified time.

```bash
# Basic usage (last 25 hours)
python3 defender-tvm-delta.py \
    --cert-path defender-tvm.crt \
    --key-path defender-tvm.key \
    --include-catalog \
    --send-hec

# Custom lookback
python3 defender-tvm-delta.py \
    --cert-path defender-tvm.crt \
    --key-path defender-tvm.key \
    --since-hours 48 \
    --include-catalog \
    --send-hec

# Output to file instead
python3 defender-tvm-delta.py \
    --cert-path defender-tvm.crt \
    --key-path defender-tvm.key \
    --include-catalog \
    --output delta.jsonl
```

**Expected output:**
```
Authenticating with certificate: defender-tvm.crt
Fetching vulnerability catalog for enrichment...
Loaded 286980 CVEs from catalog.
Fetching vulnerability CHANGES since 2026-01-17T01:00:00Z...
Retrieved 85153 delta records.
  Fixed: 52307
  New: 19763
  Updated: 13083
Wrote 85153 events.
```

### Bulk Export (Full Snapshot)

Fetches all current vulnerabilities across all machines.

```bash
# Basic usage
python3 defender-tvm-bulk.py \
    --cert-path defender-tvm.crt \
    --key-path defender-tvm.key \
    --include-catalog \
    --send-hec

# With rate limiting
python3 defender-tvm-bulk.py \
    --cert-path defender-tvm.crt \
    --key-path defender-tvm.key \
    --include-catalog \
    --send-hec \
    --api-sleep 1.0 \
    --hec-batch-size 500
```

**Expected output:**
```
Authenticating with certificate: defender-tvm.crt
Fetching vulnerability catalog for enrichment...
Loaded 286980 CVEs from catalog.
Fetching ALL vulnerabilities via bulk endpoint...
  Processed 50000 records...
  Processed 100000 records...
  ...
Retrieved 454437 vulnerability records.
  Critical: 12543
  High: 89234
  Medium: 234567
  Low: 118093
Wrote 454437 events.
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--cert-path` | Path to certificate file | - |
| `--key-path` | Path to private key file | - |
| `--include-catalog` | Enrich with catalog data (EPSS, published date, etc.) | Off |
| `--send-hec` | Send events to Splunk HEC | Off |
| `--hec-batch-size` | Events per HEC batch | 500 |
| `--output FILE` | Write to JSONL file | - |
| `--limit N` | Max records (0=unlimited) | 0 |
| `--api-sleep SECS` | Delay between API pages | 1.0 |
| `--since-hours N` | Hours to look back (delta only) | 25 |
| `--continue-on-error` | Don't fail on transient errors | Off |

---

## Scheduling with Cron

### Setup Cron Jobs

```bash
# Edit crontab
crontab -e

# Add these lines:
0 5 * * * /opt/Defender-splunk/cron-delta.sh
30 5 * * * /opt/Defender-splunk/cron-bulk.sh
```

This runs:
- **5:00 AM** - Delta export (changes from last 25 hours)
- **5:30 AM** - Bulk export (full current state)

### Verify Cron

```bash
# List cron jobs
crontab -l

# Check logs
tail -50 /var/log/defender-tvm-delta.log
tail -50 /var/log/defender-tvm-bulk.log

# Check cron service
systemctl status crond
```

---

## Splunk Integration

### Sourcetypes

| Sourcetype | Description | Script |
|------------|-------------|--------|
| `defender:tvm:bulk` | Full vulnerability snapshot | defender-tvm-bulk.py |
| `defender:tvm:delta` | Changes (New/Fixed/Updated) | defender-tvm-delta.py |

### Event Structure

**Bulk Event:**
```json
{
  "time": 1768601086,
  "source": "defender-tvm-bulk",
  "sourcetype": "defender:tvm:bulk",
  "event": {
    "dest": "WORKSTATION-01",
    "cve": "CVE-2024-1234",
    "cvss": 7.8,
    "severity": "High",
    "vuln_status": "Active",
    "published_date": "2024-01-10T00:00:00Z",
    "epss": 0.00215,
    "software_name": "chrome",
    "raw": {...}
  }
}
```

**Delta Event:**
```json
{
  "time": 1768601086,
  "source": "defender-tvm-delta",
  "sourcetype": "defender:tvm:delta",
  "event": {
    "dest": "WORKSTATION-01",
    "cve": "CVE-2024-1234",
    "delta_status": "Fixed",
    "severity": "High",
    "published_date": "2024-01-10T00:00:00Z",
    "epss": 0.00215,
    "raw": {...}
  }
}
```

### Dashboard Queries

**Current Total Vulnerabilities:**
```spl
index=defender sourcetype="defender:tvm:bulk" earliest=-1d
| stats count as total_vulns, dc(cve) as unique_cves, dc(dest) as affected_hosts
```

**Vulnerabilities by Severity:**
```spl
index=defender sourcetype="defender:tvm:bulk" earliest=-1d
| stats count by severity
| sort -count
```

**Fixed This Week:**
```spl
index=defender sourcetype="defender:tvm:delta" delta_status="Fixed" earliest=-7d
| stats count as fixed_count
```

**New This Week:**
```spl
index=defender sourcetype="defender:tvm:delta" delta_status="New" earliest=-7d
| stats count as new_count
```

**Monthly Remediation Trend:**
```spl
index=defender sourcetype="defender:tvm:delta" earliest=-30d
| timechart span=1d count by delta_status
```

**Top 10 Most Vulnerable Hosts:**
```spl
index=defender sourcetype="defender:tvm:bulk" earliest=-1d
| stats count as vuln_count by dest
| sort -vuln_count
| head 10
```

**Critical Vulns with Exploits:**
```spl
index=defender sourcetype="defender:tvm:bulk" earliest=-1d severity="Critical" exploit_available=true
| stats count by cve, software_name
| sort -count
```

**Remediation Rate:**
```spl
index=defender sourcetype="defender:tvm:delta" earliest=-30d
| stats count(eval(delta_status="New")) as new,
        count(eval(delta_status="Fixed")) as fixed
| eval remediation_rate = round(fixed / (new + fixed) * 100, 1) . "%"
```

**Combined Overview Dashboard:**
```spl
| multisearch
    [ search index=defender sourcetype="defender:tvm:bulk" earliest=-1d
      | stats count as current_total, dc(cve) as unique_cves ]
    [ search index=defender sourcetype="defender:tvm:delta" delta_status="Fixed" earliest=-7d
      | stats count as fixed_7d ]
    [ search index=defender sourcetype="defender:tvm:delta" delta_status="New" earliest=-7d
      | stats count as new_7d ]
| stats values(*) as *
| eval net_change = new_7d - fixed_7d
```

### Catalog Enrichment Fields

When using `--include-catalog`, these fields are added:

| Field | Description |
|-------|-------------|
| `published_date` | When the CVE was published |
| `updated_date` | When the CVE was last updated |
| `description` | Full vulnerability description |
| `cvss_vector` | CVSS v3 vector string |
| `epss` | EPSS probability score (0-1) |
| `public_exploit` | Whether a public exploit exists |
| `exploit_verified` | Whether exploit is verified |
| `exploit_in_kit` | Whether exploit is in exploit kits |
| `exploit_types` | Types of exploits available |
| `exploit_uris` | URLs to exploit resources |

---

## Troubleshooting

### Common Issues

**1. Authentication Failed**
```
Error: AADSTS700016: Application not found
```
→ Verify Tenant ID and Client ID are correct

**2. Certificate Error**
```
Error: AADSTS700027: Client assertion failed signature validation
```
→ Ensure certificate is uploaded to Azure AD and thumbprint matches

**3. Permission Denied**
```
Error: 403 Forbidden
```
→ Grant `Vulnerability.Read.All` and `Machine.Read.All` with admin consent

**4. Rate Limited**
```
Error: 429 Too Many Requests
```
→ Increase `--api-sleep` value

**5. Splunk HEC Error**
```
Error: 403 Forbidden (HEC)
```
→ Verify HEC token and ensure index exists

### Debug Mode

```bash
# Test with limited records, no HEC
python3 defender-tvm-delta.py \
    --cert-path defender-tvm.crt \
    --key-path defender-tvm.key \
    --limit 10

# Check what would be sent
python3 defender-tvm-bulk.py \
    --cert-path defender-tvm.crt \
    --key-path defender-tvm.key \
    --limit 5 | jq .
```

### Log Locations

- Delta logs: `/var/log/defender-tvm-delta.log`
- Bulk logs: `/var/log/defender-tvm-bulk.log`
- System cron: `/var/log/cron`

---

## License

MIT License

Copyright (c) 2025 Mohammed Ali

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
