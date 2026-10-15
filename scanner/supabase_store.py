"""Minimal Supabase Auth/PostgREST client for explicit report persistence.

This module uses only the publishable/anon key and a per-Streamlit-session user
access token. It deliberately has no service-role or admin API support.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


REPORT_COLUMNS = "id,created_at,run_id,source_sha256,summary,tool_versions"
REQUEST_TIMEOUT_SECONDS = 12


class SupabaseUnavailable(RuntimeError):
    """A safe-to-display Supabase configuration or request error."""


def configuration() -> tuple[str, str] | None:
    url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    key = os.environ.get("SUPABASE_ANON_KEY", "").strip()
    if not url or not key:
        try:
            import streamlit as st

            url = url or str(st.secrets.get("SUPABASE_URL", "")).strip().rstrip("/")
            key = key or str(st.secrets.get("SUPABASE_ANON_KEY", "")).strip()
        except Exception:
            # Missing Streamlit secrets is the normal local-only configuration.
            pass
    if not url or not key:
        return None
    if not url.startswith("https://"):
        return None
    return url, key


def rls_is_verified() -> bool:
    if os.environ.get("MICROSCOPE_SUPABASE_RLS_VERIFIED", "").strip() == "1":
        return True
    try:
        import streamlit as st

        return str(st.secrets.get("MICROSCOPE_SUPABASE_RLS_VERIFIED", "")).strip() == "1"
    except Exception:
        return False


def _request(path: str, *, method: str, body: dict[str, Any] | None = None,
             access_token: str | None = None, query: dict[str, str] | None = None,
             prefer: str | None = None) -> Any:
    configured = configuration()
    if configured is None:
        raise SupabaseUnavailable("Supabase is not configured with an HTTPS URL and publishable key.")
    base_url, anon_key = configured
    url = f"{base_url}{path}"
    if query:
        url += "?" + urlencode(query)
    headers = {"apikey": anon_key, "Content-Type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    if prefer:
        headers["Prefer"] = prefer
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
    request = Request(url, data=payload, headers=headers, method=method)
    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            content = response.read()
    except HTTPError as exc:
        # Never include request bodies, tokens, or provider response text here.
        raise SupabaseUnavailable(f"Supabase request failed (HTTP {exc.code}).") from None
    except (URLError, TimeoutError, OSError):
        raise SupabaseUnavailable("Supabase could not be reached. Local reports remain available.") from None
    if not content:
        return None
    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise SupabaseUnavailable("Supabase returned an unreadable response.") from None


def sign_in(email: str, password: str) -> dict[str, Any]:
    if not email.strip() or not password:
        raise SupabaseUnavailable("Enter both an email and password.")
    response = _request(
        "/auth/v1/token", method="POST",
        query={"grant_type": "password"},
        body={"email": email.strip(), "password": password},
    )
    user = response.get("user") if isinstance(response, dict) else None
    if not isinstance(response, dict) or not response.get("access_token") or not isinstance(user, dict) or not user.get("id"):
        raise SupabaseUnavailable("Sign-in did not return a usable session.")
    return response


def sign_out(access_token: str) -> None:
    _request("/auth/v1/logout", method="POST", access_token=access_token)


def refresh_session(refresh_token: str) -> dict[str, Any]:
    response = _request(
        "/auth/v1/token", method="POST", query={"grant_type": "refresh_token"},
        body={"refresh_token": refresh_token},
    )
    user = response.get("user") if isinstance(response, dict) else None
    if not isinstance(response, dict) or not response.get("access_token") or not isinstance(user, dict) or not user.get("id"):
        raise SupabaseUnavailable("Session refresh did not return a usable session.")
    return response


def session_record(response: dict[str, Any]) -> dict[str, Any]:
    """Keep only session fields needed by this Streamlit browser session."""
    user = response.get("user") or {}
    if not isinstance(user, dict):
        raise SupabaseUnavailable("Supabase session data was malformed.")
    return {
        "access_token": response["access_token"],
        "refresh_token": response.get("refresh_token", ""),
        "expires_at": time.time() + int(response.get("expires_in", 3600)),
        "user_id": str(user["id"]),
        "email": str(user.get("email") or ""),
    }


def list_reports(access_token: str) -> list[dict[str, Any]]:
    result = _request(
        "/rest/v1/reports", method="GET", access_token=access_token,
        query={"select": REPORT_COLUMNS, "order": "created_at.desc", "limit": "100"},
    )
    if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
        raise SupabaseUnavailable("Saved reports returned an unexpected format.")
    return result


def save_report(access_token: str, payload: dict[str, Any]) -> dict[str, Any]:
    result = _request(
        "/rest/v1/reports", method="POST", access_token=access_token,
        body=payload, prefer="return=representation",
    )
    if not isinstance(result, list) or not result or not isinstance(result[0], dict):
        raise SupabaseUnavailable("The saved report was not returned by Supabase.")
    return result[0]
