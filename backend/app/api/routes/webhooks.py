"""Inbound webhooks: POST /api/webhooks/checkmarx (app/services/cx_webhook.py).

Not signed in, so no session and no CSRF token: a delivery is authenticated
by its HMAC signature alone. Size and rate limited; a valid scan event only
queues a fast check and returns 202 at once.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.db.session import session_scope
from app.services import cx_webhook, fastcheck, settings_store

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _answer(code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=code, content={"detail": message})


def _secret_if_enabled() -> str | None:
    with session_scope() as session:
        if not cx_webhook.enabled(session):
            return None
        return settings_store.get_secret(session, settings_store.KEY_CX_WEBHOOK_SECRET)


def _record(result: str, hint: dict[str, str]) -> None:
    with session_scope() as session:
        cx_webhook.note_delivery(session, result=result, hint=hint)


async def _body(request: Request) -> bytes | None:
    """The body, or None once it is larger than the limit (not read further)."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > cx_webhook.MAX_BODY_BYTES:
                return None
        except ValueError:
            return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > cx_webhook.MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/checkmarx", include_in_schema=False)
async def checkmarx_webhook(request: Request) -> JSONResponse:
    secret = await run_in_threadpool(_secret_if_enabled)
    if secret is None:
        return _answer(status.HTTP_404_NOT_FOUND, "Not Found")
    if cx_webhook.rate_limited():
        cx_webhook.note_rejected("too many deliveries")
        return _answer(status.HTTP_429_TOO_MANY_REQUESTS, "Too many deliveries.")
    body = await _body(request)
    if body is None:
        cx_webhook.note_rejected("body too large")
        return _answer(413, "The body is too large.")
    if not cx_webhook.signature_valid(
        secret, body, request.headers.get(cx_webhook.SIGNATURE_HEADER)
    ):
        cx_webhook.note_rejected("missing or bad signature")
        return _answer(status.HTTP_401_UNAUTHORIZED, "Missing or bad signature.")
    payload = cx_webhook.parse(body)
    if payload is None:
        cx_webhook.note_rejected("not a JSON object")
        return _answer(status.HTTP_400_BAD_REQUEST, "The body is not a JSON object.")
    event = request.headers.get(cx_webhook.EVENT_HEADER)
    hint = cx_webhook.hint_of(event, payload)
    if not cx_webhook.is_scan_event(event, payload):
        await run_in_threadpool(_record, "ignored: not a scan event", hint)
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content={"queued": False})
    outcome = fastcheck.request(trigger="webhook", hint=hint)
    shown = {
        fastcheck.QUEUED: "fast check queued",
        fastcheck.MERGED: "merged into the queued fast check",
    }.get(outcome, "ignored: the fast check is not running")
    await run_in_threadpool(_record, shown, hint)
    queued = outcome != fastcheck.NOT_RUNNING
    return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content={"queued": queued})
