from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

from ..models.auth import LoginRequest, SessionInfo
from .session_manager import store_session


def _extract_token_from_json(body: Any, path: str) -> Optional[str]:
    try:
        if isinstance(body, str):
            body = json.loads(body)
    except json.JSONDecodeError:
        return None

    if not isinstance(body, dict):
        return None

    current = body
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    if isinstance(current, (str, int, float)):
        return str(current)
    return None


def login_and_store_session(payload: LoginRequest) -> SessionInfo:
    session = requests.Session()

    method = payload.method.upper()
    headers = payload.headers or {}

    request_kwargs: Dict[str, Any] = {
        "url": payload.login_url,
        "headers": headers,
        "allow_redirects": payload.follow_redirects,
        "timeout": payload.timeout,
    }

    if payload.json_body is not None:
        request_kwargs["json"] = payload.json_body
    elif payload.body is not None:
        request_kwargs["data"] = payload.body

    response = session.request(method=method, **request_kwargs)

    cookies = session.cookies.get_dict()
    stored_headers: Dict[str, str] = {}

    if payload.token_path:
        token = _extract_token_from_json(response.text, payload.token_path)
        if token:
            header_name = payload.token_header_name or "Authorization"
            prefix = payload.token_prefix or ""
            stored_headers[header_name] = f"{prefix}{token}"

    if payload.persist_response_headers:
        for header in payload.persist_response_headers:
            if header in response.headers:
                stored_headers[header] = response.headers[header]

    parsed = urlparse(payload.login_url)
    session_domain = payload.domain or parsed.hostname or ""

    store_session(session_domain, cookies=cookies, headers=stored_headers)

    preview_body = response.text[:500]

    return SessionInfo(
        domain=session_domain,
        status_code=response.status_code,
        cookies=cookies,
        headers=stored_headers,
        body_preview=preview_body,
    )
