"""DPoP nonce issuance, replay protection, and proof binding.

A DPoP proof is accepted only when it echoes a live server nonce, stays
bound to the issuing client, the request method and URI, and the presented
access token, and carries a fresh proof identifier.  The helpers work on
plain dictionaries so the same rules can serve an HTTP handler or an offline
batch checker.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any

_DEFAULT_NONCE_TTL = 60
_DEFAULT_JTI_TTL = 60
_ATH_HASHES = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}


def issue_nonce(
    store: dict[str, Any],
    client: str,
    now: float,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Issue a fresh nonce bound to a client and a short deadline.

    The store owns the nonce table under the ``nonces`` key.  The returned
    mapping is a snapshot; later changes to the stored record do not alter it.
    The policy may set ``nonce_ttl`` in seconds, otherwise sixty seconds are
    used.  A non-positive or malformed lifetime falls back to the default.
    """

    if not isinstance(store, dict):
        raise TypeError("store must be a dictionary")
    if not isinstance(client, str) or not client:
        raise ValueError("client must be a non-empty string")

    ttl = policy.get("nonce_ttl", _DEFAULT_NONCE_TTL)
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0:
        ttl = _DEFAULT_NONCE_TTL

    nonces = store.setdefault("nonces", {})
    if not isinstance(nonces, dict):
        nonces = {}
        store["nonces"] = nonces

    nonce = secrets.token_urlsafe(24)
    while nonce in nonces:
        nonce = secrets.token_urlsafe(24)

    record = {
        "nonce": nonce,
        "client": client,
        "issued_at": now,
        "expires_at": now + ttl,
        "used": False,
    }
    nonces[nonce] = record
    return dict(record)


def check_nonce(
    store: dict[str, Any],
    nonce: str,
    client: str,
    now: float,
) -> bool:
    """Consume a server nonce if it belongs to the client and is still live.

    A nonce is accepted at most once and only through its expiry instant.
    A nonce presented by a different client is rejected.
    """

    if (
        not isinstance(store, dict)
        or not isinstance(nonce, str)
        or not nonce
        or not isinstance(client, str)
        or not client
        or isinstance(now, bool)
        or not isinstance(now, (int, float))
    ):
        return False

    nonces = store.get("nonces")
    if not isinstance(nonces, dict):
        return False
    record = nonces.get(nonce)
    if not isinstance(record, dict):
        return False
    if record.get("used"):
        return False
    if record.get("client") != client:
        return False

    expires_at = record.get("expires_at")
    if (
        not isinstance(expires_at, (int, float))
        or isinstance(expires_at, bool)
        or now > expires_at
    ):
        return False

    record["used"] = True
    return True


def check_echo(payload: dict[str, Any], nonce: str) -> bool:
    """Check that the proof payload echoes the current server nonce."""

    if not isinstance(payload, dict):
        return False
    echoed = payload.get("nonce")
    if not isinstance(echoed, str) or not echoed:
        return False
    if not isinstance(nonce, str) or not nonce:
        return False
    return hmac.compare_digest(echoed.encode("utf-8"), nonce.encode("utf-8"))


def check_htm_htu(payload: dict[str, Any], method: str, url: str) -> bool:
    """Check that the proof is bound to the request method and URI.

    The method is compared without regard to case.  The URI is compared as
    supplied, with no prefix, suffix, or normalization handling here.
    """

    if not isinstance(payload, dict):
        return False
    htm = payload.get("htm")
    htu = payload.get("htu")
    if not all(isinstance(value, str) and value for value in (htm, htu, method, url)):
        return False
    return htm.upper() == method.upper() and htu == url


def check_jti(
    store: dict[str, Any],
    jti: str,
    now: float,
    ttl: float,
) -> bool:
    """Accept a proof identifier only once inside its replay window.

    Expired identifiers are purged before the candidate is examined.  A fresh
    identifier is recorded with a deadline of ``now`` plus ``ttl``.  The store
    owns the identifier table under the ``jtis`` key.
    """

    if not isinstance(store, dict) or not isinstance(jti, str) or not jti:
        return False
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        return False
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0:
        return False

    jtis = store.setdefault("jtis", {})
    if not isinstance(jtis, dict):
        jtis = {}
        store["jtis"] = jtis

    for seen_jti, deadline in list(jtis.items()):
        if (
            not isinstance(deadline, (int, float))
            or isinstance(deadline, bool)
            or deadline <= now
        ):
            jtis.pop(seen_jti, None)

    if jti in jtis:
        return False

    jtis[jti] = now + ttl
    return True


def check_ath(payload: dict[str, Any], access_token: str) -> bool:
    """Check the proof token digest against the presented access token.

    The digest is the unpadded base64url encoding of a hash over the UTF-8
    token bytes.  SHA-256 is the default when the proof omits ``ath_alg``;
    both SHA-256 and SHA-512 may be named explicitly once.
    """

    if not isinstance(payload, dict):
        return False
    if not isinstance(access_token, str) or not access_token:
        return False
    ath = payload.get("ath")
    if not isinstance(ath, str) or not ath:
        return False
    alg = payload.get("ath_alg")
    if alg is None:
        hasher = _ATH_HASHES["sha-256"]
    else:
        if not isinstance(alg, str):
            return False
        hasher = _ATH_HASHES.get(alg.lower())
        if hasher is None:
            return False

    digest = hasher(access_token.encode("utf-8")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(expected.encode("ascii"), ath.encode("utf-8"))


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Return policy problems, empty when the policy covers the contract.

    A sound policy requires nonce issuance, one-time nonce redemption, and
    access-token digest binding.
    """

    if not isinstance(policy, dict):
        return ["policy must be a mapping"]

    problems: list[str] = []
    if not policy.get("nonce_required"):
        problems.append("nonce is not required")
    if not policy.get("nonce_one_time"):
        problems.append("nonce is not one-time")
    if not policy.get("ath_required"):
        problems.append("access token digest is not required")
    return problems


def proof_batch(
    requests: list[dict[str, Any]],
    store: dict[str, Any],
    now: float,
) -> dict[str, Any]:
    """Validate a sequence of proof requests independently.

    Each request carries its own client, nonce, payload, method, URL, access
    token, and optional identifier lifetime.  The result contains one entry
    per input, the accepted and rejected indices, and an aggregate flag.
    """

    if isinstance(requests, (str, bytes)) or not isinstance(requests, list):
        raise TypeError("requests must be a list")
    if not isinstance(store, dict):
        raise TypeError("store must be a dictionary")

    results: list[dict[str, Any]] = []
    accepted: list[int] = []
    rejected: list[int] = []

    for index, request in enumerate(requests):
        errors: list[str] = []
        if not isinstance(request, dict):
            errors.append("request must be a mapping")
        else:
            payload = request.get("payload")
            nonce = request.get("nonce")
            client = request.get("client")
            method = request.get("method")
            url = request.get("url")
            access_token = request.get("access_token")
            jti_ttl = request.get("jti_ttl", _DEFAULT_JTI_TTL)

            if not check_echo(payload, nonce):
                errors.append("nonce echo")
            if not check_htm_htu(payload, method, url):
                errors.append("method or URL")
            if not check_ath(payload, access_token):
                errors.append("access token digest")

            if not errors:
                jti = payload.get("jti") if isinstance(payload, dict) else None
                if not check_jti(store, jti, now, jti_ttl):
                    errors.append("proof identifier")
                elif not check_nonce(store, nonce, client, now):
                    errors.append("server nonce")

        ok = not errors
        if ok:
            accepted.append(index)
        else:
            rejected.append(index)
        results.append({"index": index, "ok": ok, "errors": errors})

    return {
        "results": results,
        "accepted": accepted,
        "rejected": rejected,
        "ok": not rejected,
    }