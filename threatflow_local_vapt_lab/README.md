# ThreatFlow Local VAPT Training Lab

A deliberately misconfigured **local-only** web app for demonstrating the ThreatFlow AI VAPT workflow.

## Safety boundary
- Binds only to `127.0.0.1`.
- Contains no real accounts, credentials, customer data, or secrets.
- Do not change the bind address to `0.0.0.0` or expose it publicly.
- Only point scanners at `http://127.0.0.1:8765`.

## Run on Windows PowerShell
```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn lab.app:app --host 127.0.0.1 --port 8765
```
Open `http://127.0.0.1:8765`.

## Intended training observations
- Permissive CORS (`Access-Control-Allow-Origin: *`).
- Missing common browser security headers.
- Public API documentation.
- An unauthenticated demo-only `/admin` page.
- Informational application metadata.

These are observations, not CVE claims. The VAPT agent must preserve raw evidence, distinguish observations from confirmed vulnerabilities, and never invent CVEs or CVSS scores.

## Suggested checks
1. Visit `/`, `/api/info`, `/admin`, and `/docs`.
2. Capture response headers with an HTTP inspection tool.
3. If installed, run Nmap only against `127.0.0.1`.
4. If using OWASP ZAP, set its target explicitly to `http://127.0.0.1:8765`.
5. Keep active validation disabled unless an operator explicitly approves a specific action.

Stop the server with `Ctrl+C`.
