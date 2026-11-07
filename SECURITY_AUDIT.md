# IntelliResponse security review

## Scope and method
Static review of the Python source, configuration, dependency manifest and README, plus
dynamic tests of the API and memory layer (`tests/test_security.py`, 23 tests) and a
`pip-audit` scan of the resolved dependency set (`requirements.lock`, 53 packages: no
known vulnerabilities on the scan date). This is not a penetration test.

## Revision 1 findings (previously fixed)
1. SIEM API had no authentication - now requires `X-API-Key`, fails closed, constant-time compare.
2. Permissive credentialed CORS - disabled by default, exact-origin allowlist, no credentials.
3. Excessive input exposure - alert length, verdict values and note length bounded.
4. Operational information exposure - `/health` minimal; interactive docs disabled.
5. Local incident store shipped in the archive - removed and git-ignored.
6. API runtime dependencies undocumented - added to `requirements.txt`.

## Revision 2 findings (this revision)
| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| 1 | High | Verdict forgery: `actions_taken` and report fields were written unescaped into the pipe-delimited memory record; later `key=value` parts overrode earlier ones (a TRUE_POSITIVE could be stored as FALSE_POSITIVE). | Strict allow-lists for every field (category, IP, service, actions, risk, numbers); `one_line` strips every `\|` and newline; `parse_incident` rejects duplicate/unknown keys and unknown verdicts. |
| 2 | Medium | `/v1/verdict` trusted a client-supplied `report`, allowing arbitrary incident writes and 500s on malformed values. | Server issues a single-use, expiring `report_id` at triage; verdict takes only that id. |
| 3 | Medium | 1 MB body limit bypassable via chunked transfer; list items unbounded. | Streaming ASGI body limit; per-item pattern and length limits. |
| 4 | Medium | Unbounded memory/disk growth (records, HTTP cache); no rate limiting. | `IR_MAX_RECORDS` cap, bounded HTTP cache and response size, per-client rate limit and auth-failure lockout. |
| 5 | Medium | Shared `Memory` mutated from a thread pool without a lock; shared temp-file name. | Re-entrant lock around all mutations; `mkstemp` unique temp files; id allocation is atomic. |
| 6 | Medium | CSV formula injection in the ledger export. | Cells starting with `= + - @` are neutralised. |
| 7 | Low-Med | Store file created world-readable (0644). | Created 0600 in a 0700 directory. |
| 8 | Low | Non-ASCII `X-API-Key` caused HTTP 500. | Bytes comparison; unhandled errors return a generic 500. |
| 9 | Low | Example key was a known weak value; `.env` key ignored (read before load). | Keys under 32 chars or placeholders rejected; `.env` loaded first; example key blank. |
| 10 | Low | Incomplete private-IP check. | `ipaddress` (`is_global`) with strict parsing. |
| 11 | Low | Model/remote text rendered as markdown (links/images could leak or phish). | Links, images, HTML stripped and URLs defanged before display. |
| 12 | Low | Per-request `live_osint` let clients trigger outbound calls; Hindsight/Groq URLs unvalidated and shown with credentials. | Operator-controlled `IR_LIVE_OSINT`; http(s) only, HTTPS required except localhost, no embedded credentials, URLs redacted in UI. |
| 13 | Low | Streamlit reset/export reachable by anyone who can open the UI. | Optional `IR_UI_PASSWORD` gate. |
| 14 | Info | No dependency lockfile. | `requirements.lock` added and audited; version upper bounds added. |

## Revision 3 findings (full re-scan)
Tools: bandit, ruff (S/F/B rules), detect-secrets, pip-audit, fuzzing (2,000 inputs), timing tests,
45 adversarial checks against a live uvicorn server (`tests/live_server_check.py`), 23 pytest tests.

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| 15 | High | **Alert-suppression by log injection.** The first `from <ip>` anywhere in the text became the source, so an attacker who controls any logged field (e.g. a username) could inject a known-benign scanner IP and drop a real attack from MEDIUM 0.69 to LOW 0.12. | Every source indicator is collected. If the text names more than one possible source (or another non-internal IP), memory-based downgrades (known-benign, prior-FP) are disabled, confidence cannot fall below the stateless baseline, and the reasons say why. |
| 16 | Medium | **Regex DoS.** `DOM_RE` is quadratic: a crafted 12 KB alert cost about 2.3 s of CPU, and regex work holds the GIL so it stalls the whole server. | Tokenised extraction with a 253-char token cap. Worst case is now about 6 ms. |
| 17 | Low-Med | `failures=`/`count=` with thousands of digits raised `ValueError` (HTTP 500 / UI crash). | Digit-bounded parsing plus clamped `_safe_int`. |
| 18 | Low | The auth-failure lockout also blocked the *correct* key, so an attacker sharing a client's IP could deny the SOC its own API. | Only invalid attempts are throttled; a valid key is never locked out. |
| 19 | Low | SHA-1 used for record identity (collision-prone; bandit B324 HIGH). | SHA-256, with automatic migration of existing stores. |
| 20 | Low | `urlopen` without an explicit scheme guard (B310). | `https://`-only guard, plus a bounded response size. |
| 21 | Info | `Server:` header disclosed the stack; silent `except: pass` blocks; minor lint. | `--no-server-header` documented, failures logged at debug, lint fixed. |

Accepted/false positives: bandit B105 and detect-secrets on `data.py:26` (an action-description string
containing the word "password"); detect-secrets on a test fixture credential.

## Remaining deployment requirements
- Generate a unique `IR_API_KEY` (32+ chars) and store it in a secret manager; never commit `.env`.
- Deploy behind HTTPS, network allowlisting and gateway rate limiting; the built-in limiter is per-process.
- Put Streamlit behind SSO or an authenticating proxy for any non-local exposure (`IR_UI_PASSWORD` is a minimal gate).
- Restrict access to `.ir_store.json` and encrypt backups; incident logs can contain sensitive infrastructure details.
- Re-run `pip-audit` in CI regularly; new advisories appear after this scan.
- Existing stores created by earlier versions may hold forged records; records with duplicate keys are now ignored on load, but review old data.
- Add an audit log (auth failures, verdicts, resets) shipped to your SIEM; the app currently keeps only a 300-event in-memory trail.
- Treat LLM output as untrusted: only output sanitisation is in place, so prompt injection from log text can still skew the *wording* of a summary (never the score or actions).
- Run an authenticated integration test and a deployment-specific penetration test before production use.
