"""Authenticated IntelliResponse SIEM integration API.

Set IR_API_KEY (32+ characters) to enable the API. The health endpoint exposes only
a minimal liveness response; every other endpoint requires ``X-API-Key``.

Flow: ``POST /v1/triage`` returns a report with a one-time ``report_id``;
``POST /v1/verdict`` references that id. The server never trusts a report body
supplied by the client.
"""
from __future__ import annotations

import collections
import hmac
import logging
import os
import secrets
import threading
import time
from typing import Annotated, List, Literal, Optional

from pydantic import BaseModel, Field

from config import get_settings, load_dotenv

load_dotenv()  # so IR_API_KEY etc. in .env are honoured before they are read below

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
except ImportError:
    FastAPI = None

from agent import Memory, investigate, record_outcome

log = logging.getLogger("intelliresponse.api")

MAX_BODY_BYTES = 1_000_000
MIN_KEY_LENGTH = 32
_PLACEHOLDER_KEYS = {"replace_with_a_long_random_secret", "changeme", "secret", "password"}

API_KEY = (os.getenv("IR_API_KEY") or "").strip()
API_KEY_VALID = len(API_KEY) >= MIN_KEY_LENGTH and API_KEY.lower() not in _PLACEHOLDER_KEYS
if not API_KEY_VALID:
    log.error(
        "IR_API_KEY is unset, a placeholder, or shorter than %d characters: all "
        "authenticated endpoints will return 401. Generate one with: "
        "python -c 'import secrets; print(secrets.token_urlsafe(48))'",
        MIN_KEY_LENGTH,
    )

ALLOWED_ORIGINS = [
    item.strip()
    for item in os.getenv("IR_CORS_ORIGINS", "").split(",")
    if item.strip() and item.strip() != "*"
]
_RATE_LIMIT = max(1, int(os.getenv("IR_RATE_LIMIT", "60") or 60))  # requests / minute / client
_AUTH_FAIL_LIMIT = 10  # failed authentications / minute / client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class SlidingWindowLimiter:
    """Small in-process limiter. Use a gateway for multi-process deployments."""

    def __init__(self, limit: int, window: float = 60.0, max_clients: int = 10_000):
        self.limit, self.window, self.max_clients = limit, window, max_clients
        self._hits: dict[str, collections.deque] = {}
        self._lock = threading.Lock()

    def _prune(self, q: collections.deque, now: float) -> None:
        while q and now - q[0] > self.window:
            q.popleft()

    def count(self, client: str) -> int:
        now = time.monotonic()
        with self._lock:
            q = self._hits.get(client)
            if not q:
                return 0
            self._prune(q, now)
            return len(q)

    def hit(self, client: str) -> bool:
        """Record a hit; return False if the client is over the limit."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > self.max_clients:
                for key in [k for k, q in self._hits.items() if not q or now - q[-1] > self.window]:
                    self._hits.pop(key, None)
                if len(self._hits) > self.max_clients:
                    self._hits.clear()
            q = self._hits.setdefault(client, collections.deque())
            self._prune(q, now)
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


class ReportStore:
    """Bounded, expiring, single-use store of reports this server produced."""

    def __init__(self, max_items: int = 500, ttl: float = 3600.0):
        self.max_items, self.ttl = max_items, ttl
        self._items: "collections.OrderedDict[str, tuple[float, dict]]" = collections.OrderedDict()
        self._lock = threading.Lock()

    def put(self, report: dict) -> str:
        rid = secrets.token_urlsafe(18)
        now = time.monotonic()
        with self._lock:
            while self._items and (
                len(self._items) >= self.max_items
                or now - next(iter(self._items.values()))[0] > self.ttl
            ):
                self._items.popitem(last=False)
            self._items[rid] = (now, report)
        return rid

    def take(self, rid: str) -> dict | None:
        with self._lock:
            entry = self._items.pop(rid, None)
        if not entry or time.monotonic() - entry[0] > self.ttl:
            return None
        return entry[1]


class BodyLimitMiddleware:
    """Pure ASGI middleware that enforces a body limit while streaming.

    Checking ``Content-Length`` alone is bypassable with chunked transfer encoding,
    so the bytes actually received are counted. When the limit is crossed the 413
    is sent immediately and the application is told the client disconnected.
    """

    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def reject(status: int, detail: str):
            body = ('{"detail":"%s"}' % detail).encode()
            await send({"type": "http.response.start", "status": status,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})

        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    return await reject(413, "Request too large")
            except ValueError:
                return await reject(400, "Invalid Content-Length")

        total = 0
        started = False
        rejected = False

        async def limited_receive():
            nonlocal total, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    rejected = True
                    if not started:
                        await reject(413, "Request too large")
                    return {"type": "http.disconnect"}
            return message

        async def tracking_send(message):
            nonlocal started
            if rejected:
                return  # response already sent; drop anything the app tries to add
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        await self.app(scope, limited_receive, tracking_send)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
if FastAPI:
    app = FastAPI(
        title="IntelliResponse API",
        version="1.2.0",
        description="Defensive SOC memory agent webhook receiver",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.add_middleware(BodyLimitMiddleware, max_bytes=MAX_BODY_BYTES)

    # No wildcard origins and no credentialed cross-origin access.
    if ALLOWED_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=ALLOWED_ORIGINS,
            allow_credentials=False,
            allow_methods=["POST", "GET"],
            allow_headers=["Content-Type", "X-API-Key"],
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.exception("unhandled error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal error"})

    mem = Memory()
    reports = ReportStore()
    rate = SlidingWindowLimiter(_RATE_LIMIT)
    auth_failures = SlidingWindowLimiter(_AUTH_FAIL_LIMIT)

    ActionName = Annotated[str, Field(min_length=1, max_length=60, pattern=r"^[A-Za-z0-9_-]+$")]

    class TriageRequest(BaseModel):
        raw_alert: str = Field(min_length=1, max_length=get_settings().max_alert_chars)
        use_memory: bool = True
        live_osint: bool = False

    class VerdictRequest(BaseModel):
        report_id: str = Field(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
        verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE"]
        actions_taken: List[ActionName] = Field(default_factory=list, max_length=20)
        note: Optional[str] = Field(default="", max_length=400)

    def _client(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def require_api_key(request: Request, x_api_key: str | None = Header(default=None)) -> None:
        client = _client(request)
        supplied = (x_api_key or "").encode("utf-8", errors="replace")
        # Fail closed: unavailable until a strong secret is configured. Comparing
        # bytes avoids a TypeError (HTTP 500) on non-ASCII header values.
        valid = bool(
            API_KEY_VALID and supplied and hmac.compare_digest(supplied, API_KEY.encode("utf-8"))
        )
        if not valid:
            # Throttle only *invalid* attempts. A correct key is never locked out, so an
            # attacker sharing a client's IP cannot deny the SOC access to its own API.
            if auth_failures.count(client) >= _AUTH_FAIL_LIMIT:
                raise HTTPException(status_code=429, detail="Too many failed attempts")
            auth_failures.hit(client)
            raise HTTPException(status_code=401, detail="Unauthorized")
        if not rate.hit(client):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/v1/triage")
    def triage_endpoint(req: TriageRequest, _: None = Depends(require_api_key)):
        if not req.raw_alert.strip():
            raise HTTPException(status_code=400, detail="Alert logs cannot be empty.")
        # Outbound OSINT lookups are an operator decision (IR_LIVE_OSINT), not a per-request one.
        live = bool(req.live_osint and get_settings().live_osint)
        report = investigate(req.raw_alert, mem, use_memory=req.use_memory, live=live)
        return {**report, "report_id": reports.put(report)}

    @app.post("/v1/verdict")
    def verdict_endpoint(req: VerdictRequest, _: None = Depends(require_api_key)):
        report = reports.take(req.report_id)
        if report is None:
            raise HTTPException(
                status_code=404,
                detail="Unknown, expired or already-used report_id. Run /v1/triage first.",
            )
        try:
            inc_id = record_outcome(mem, report, req.verdict, req.actions_taken, req.note or "")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"saved_as": inc_id, "status": "memory_updated"}
