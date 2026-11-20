#!/usr/bin/env python3
"""Shared helpers for ISE audit pull/report scripts."""
from __future__ import annotations

import json
import os
from typing import Any

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings()


def make_session(user: str, password: str, insecure: bool) -> requests.Session:
    s = requests.Session()
    s.auth = HTTPBasicAuth(user, password)
    s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    s.verify = not insecure
    return s


def unwrap(payload: Any) -> list:
    if payload is None:
        return []
    if isinstance(payload, dict) and "response" in payload:
        return payload["response"] or []
    if isinstance(payload, list):
        return payload
    return [payload]


def is_login_html(text: str) -> bool:
    t = (text or "").lstrip().lower()
    return t.startswith("<!doctype") or t.startswith("<html")


def get_json(
    session: requests.Session,
    url: str,
    *,
    timeout: int = 60,
    allow_redirects: bool = True,
) -> tuple[int, Any, str]:
    """Return (status, parsed_or_none, raw_text)."""
    r = session.get(url, timeout=timeout, allow_redirects=allow_redirects)
    text = r.text or ""
    if r.status_code in (301, 302, 303, 307, 308):
        return r.status_code, None, text
    if is_login_html(text):
        return r.status_code, None, "HTML_LOGIN"
    if not text.strip():
        return r.status_code, None, text
    try:
        return r.status_code, r.json(), text
    except Exception:
        return r.status_code, None, text[:500]


def flatten_condition(cond: Any, depth: int = 0) -> str:
    """Turn nested OpenAPI condition trees into a readable one-liner."""
    if not cond:
        return ""
    if not isinstance(cond, dict):
        return str(cond)
    ctype = cond.get("conditionType") or ""
    neg = "NOT " if cond.get("isNegate") else ""

    if ctype in ("ConditionAndBlock", "ConditionOrBlock"):
        op = " AND " if "And" in ctype else " OR "
        kids = cond.get("children") or []
        parts = [flatten_condition(c, depth + 1) for c in kids]
        parts = [p for p in parts if p]
        inner = op.join(parts)
        return f"{neg}({inner})" if parts else f"{neg}{ctype}"

    if ctype == "ConditionReference":
        name = cond.get("name") or cond.get("id") or "ref"
        return f"{neg}ref:{name}"

    if ctype == "ConditionAttributes":
        d = cond.get("dictionaryName") or ""
        a = cond.get("attributeName") or ""
        op = cond.get("operator") or "="
        v = cond.get("attributeValue")
        if v is None:
            v = cond.get("dictionaryValue")
        return f"{neg}{d}.{a} {op} {v}"

    if ctype == "ConditionAndBlock" or ctype == "ConditionOrBlock":
        return neg + ctype

    name = cond.get("name")
    if name:
        return f"{neg}{name}"
    return f"{neg}{ctype or json.dumps(cond, ensure_ascii=False)[:120]}"


def build_lookup(items: list, id_key: str = "id", name_key: str = "name") -> dict:
    out = {}
    for it in items:
        if isinstance(it, dict) and id_key in it:
            out[it[id_key]] = it.get(name_key, it[id_key])
    return out


def env_cred(host=None, user=None, password=None):
    host = (host or os.environ.get("ISE_HOST") or "").strip()
    host = host.removeprefix("https://").removeprefix("http://").rstrip("/")
    user = user or os.environ.get("ISE_USER") or os.environ.get("IDENTITY_SERVICES_ENGINE_USERNAME")
    password = password or os.environ.get("ISE_PASS") or os.environ.get(
        "IDENTITY_SERVICES_ENGINE_PASSWORD"
    )
    return host, user, password


def write_json(path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
