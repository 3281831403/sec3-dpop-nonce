"""Public behaviour checks for the DPoP nonce exercise."""

import base64
import hashlib

from dpopn import (
    check_ath,
    check_echo,
    check_htm_htu,
    check_nonce,
    issue_nonce,
    proof_batch,
)

NOW = 1_700_000_000
CLIENT = "alice"
URL = "https://api.example/items"
ACCESS_TOKEN = "access-token-public"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _ath(token: str) -> str:
    return _b64(hashlib.sha256(token.encode("utf-8")).digest())


def _policy(**overrides):
    values = {
        "nonce_required": True,
        "nonce_one_time": True,
        "ath_required": True,
        "nonce_ttl": 30,
    }
    values.update(overrides)
    return values


def _request(nonce, client=CLIENT, token=ACCESS_TOKEN, jti="jti-public"):
    payload = {
        "nonce": nonce,
        "htm": "POST",
        "htu": URL,
        "jti": jti,
        "ath": _ath(token),
        "ath_alg": "sha-256",
    }
    return {
        "client": client,
        "nonce": nonce,
        "payload": payload,
        "method": "POST",
        "url": URL,
        "access_token": token,
        "jti_ttl": 60,
    }


def test_issued_nonce_is_live_and_single_use():
    store = {}
    issued = issue_nonce(store, CLIENT, NOW, _policy())

    assert issued["nonce"]
    assert issued["client"] == CLIENT
    assert issued["expires_at"] > NOW
    assert check_nonce(store, issued["nonce"], CLIENT, NOW) is True
    assert check_nonce(store, issued["nonce"], CLIENT, NOW + 1) is False


def test_echo_must_equal_the_current_nonce():
    store = {}
    current = issue_nonce(store, CLIENT, NOW, _policy())
    stale = issue_nonce(store, CLIENT, NOW, _policy())

    assert check_echo({"nonce": current["nonce"]}, current["nonce"]) is True
    assert check_echo({"nonce": stale["nonce"]}, current["nonce"]) is False
    assert check_echo({}, current["nonce"]) is False


def test_method_and_url_are_bound_to_the_proof():
    valid = {"htm": "POST", "htu": URL}
    extended = {"htm": "POSTER", "htu": URL + "/extra"}

    assert check_htm_htu(valid, "POST", URL) is True
    assert check_htm_htu(extended, "POST", URL) is False


def test_token_digest_must_match_the_access_token():
    wrong = _b64(hashlib.sha256(b"a different token").digest())

    assert check_ath({"ath": wrong}, ACCESS_TOKEN) is False
    assert check_ath({"ath": _ath(ACCESS_TOKEN)}, ACCESS_TOKEN) is True


def test_batch_checks_two_requests_independently():
    store = {}
    first = issue_nonce(store, CLIENT, NOW, _policy())

    result = proof_batch(
        [
            _request(first["nonce"], token="token-one", jti="jti-one"),
            _request("nonce-never-issued", token="token-two", jti="jti-two"),
        ],
        store,
        NOW,
    )

    assert [item["ok"] for item in result["results"]] == [True, False]
    assert result["accepted"] == [0]
    assert result["rejected"] == [1]
    assert result["ok"] is False