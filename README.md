# 🛡️ IntelliResponse — SOC Memory Agent
### *AI Agent That Learns from Every Security Verdict Using Hindsight*

Built for the **Vectorize "AI Agents That Learn Using Hindsight"**.

IntelliResponse is an autonomous tier-1 security operations center (SOC) triage agent. Unlike stateless chatbots or basic vector search retrievers that forget past calls, IntelliResponse uses **Hindsight persistent memory** to turn analyst verdicts, repeat offender profiles, and past false-positive sources into a continuously learning decision layer.

---

## 🚀 The Demo 

1. **Beat 1: The Stateless Baseline (Memory OFF)**
   - Alert: Routine monthly port sweep / failed SSH login from internal scanner `198.51.100.7`.
   - Without memory, standard rules flag it as **MEDIUM (45% confidence)** and recommend disruptive blocking.
2. **Beat 2: The Memory Moment (Memory ON, 20 Historical Incidents)**
   - Re-run the exact same alert.
   - Hindsight instantly recalls `INC-003`, `INC-006`, `INC-007`, and `INC-020`.
   - The agent detects 4/4 past false positives, **auto-downgrades risk to LOW (12% confidence)**, and recommends `allowlist_scanner` instead of blocking.
   - **Time saved: ~18 minutes** per tier-1 analyst alert.
3. **Beat 3: New Attacker in Known Malicious Subnet**
   - Alert: New IP `192.0.2.180` doing SSH brute force.
   - Hindsight recalls `INC-004`, `INC-008`, `INC-015`, and `INC-019` in the same `/24` range.
   - The agent **elevates risk to HIGH** and recommends playbook actions proven effective in prior incidents.
4. **Beat 4: Dangerous Repeat C2 Beaconing**
   - Alert: Periodic DNS TXT lookups from `10.20.7.12` to `c2-sync.example`.
   - Hindsight recalls `INC-018` where persistence survived re-imaging via a scheduled task.
   - Recommends deep host isolation, scheduled task audit, and DNS domain sinkholing.

---

## 🛠️ Architecture: Seven-Stage Pipeline

```
[ Ingest Log ]
      │
      ▼
[ 1. Parse ]       --> Regex IOC extraction (IPs, domains, hashes, services, volumes)
      │
      ▼
[ 2. Recall ]      --> Hindsight semantic recall + structured incident ledger index
      │
      ▼
[ 3. Enrich ]      --> Public threat intel (CISA KEV, AlienVault OTX, cached OSINT)
      │
      ▼
[ 4. Correlate ]   --> MITRE ATT&CK mapping + learned category TPR + Bayesian smoothing
      │
      ▼
[ 5. Recommend ]   --> Defensive actions ranked by historical effectiveness
      │
      ▼
[ 6. Reason ]      --> Groq LLM summary (with deterministic fallback)
      │
      ▼
[ 7. Report ]      --> Explainable audit report with side-by-side memory delta & verdict feedback
```

---

## 💻 How to Run

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Optional Environment Setup (`.env`)
```bash
cp .env.example .env
# Add HINDSIGHT_API_KEY and GROQ_API_KEY if available.
# Zero-key mode works immediately via local mirror & deterministic fallback!
```

### 3. Launch the Streamlit App
```bash
streamlit run app.py
```
Open your browser at **`http://localhost:8501`** (or `http://127.0.0.1:8501/?v=5`).

For production, do not expose Streamlit directly to the public internet. Put it
behind an authenticated HTTPS reverse proxy or an identity-aware access gateway,
restrict network access, and configure trusted proxy headers correctly.


## SIEM API (optional)

The webhook API is a separate service from the Streamlit UI. Install dependencies
from `requirements.txt` (or the audited `requirements.lock`), set `IR_API_KEY` to a
random secret of **32+ characters** (placeholders and short keys are rejected and the
API stays closed), then run:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"   # generate a key
uvicorn api:app --host 127.0.0.1 --port 8000 --no-server-header
```

Every request except `/health` needs the header `X-API-Key: <your-secret>`.

```bash
# 1) Triage: the response includes a one-time "report_id"
curl -s -H "X-API-Key: $IR_API_KEY" -H "Content-Type: application/json" \
  -d '{"raw_alert": "Failed password for root from 198.51.100.7 ... failures=40"}' \
  http://127.0.0.1:8000/v1/triage

# 2) Verdict: reference the report by id (reports sent by the client are never trusted)
curl -s -H "X-API-Key: $IR_API_KEY" -H "Content-Type: application/json" \
  -d '{"report_id": "<id from step 1>", "verdict": "TRUE_POSITIVE", "actions_taken": ["block_ip"], "note": "confirmed"}' \
  http://127.0.0.1:8000/v1/verdict
```

A `report_id` is single-use and expires after an hour. `actions_taken` entries must
match `[A-Za-z0-9_-]{1,60}` (max 20). Request bodies over 1 MB are rejected, including
chunked uploads. The app limits each client IP to `IR_RATE_LIMIT` requests/minute and
locks a client out after 10 failed key attempts per minute. Outbound OSINT lookups only
happen when the operator sets `IR_LIVE_OSINT=1`.

The `/health` endpoint returns only a minimal liveness status. CORS is disabled by
default; if a browser client is required, set `IR_CORS_ORIGINS` to an explicit
comma-separated allowlist. Do not expose the service directly to the public internet:
place it behind TLS termination, a firewall or reverse proxy, and gateway rate limiting
(the built-in limiter is per-process and sees the proxy's IP unless configured otherwise).
Keep `.env` and `.ir_store.json` out of Git.

Set `IR_UI_PASSWORD` to put a password gate in front of the Streamlit UI (including the
memory-reset control). For anything beyond localhost, use SSO or an authenticating proxy.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q tests          # security regression tests
pip-audit -r requirements.lock --no-deps --disable-pip
```

## Security notes before deployment

- Never commit real API keys, `.env`, local incident stores, or exported incident
  data. Use repository/host secret management for production credentials.
- Treat alert logs and OSINT/LLM output as untrusted data; verify recommendations
  with an analyst before taking containment actions.
- Run the app with a dedicated low-privilege account and persistent storage with
  restrictive filesystem permissions.
- The included API key check is an application-level control, not a replacement
  for HTTPS, network controls, rate limiting, audit logging, or secret rotation.
