import json
from datetime import datetime
from typing import Any, Dict

from ..db.database import get_db_connection


def store_session(domain: str, cookies: Dict[str, str] | None = None, headers: Dict[str, str] | None = None) -> None:
    """
    Persist session information for a domain. Cookies and headers are stored as JSON strings.
    """
    cookies_json = json.dumps(cookies or {})
    headers_json = json.dumps(headers or {})

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        INSERT INTO sessions (domain, cookies, headers, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            cookies=excluded.cookies,
            headers=excluded.headers,
            updated_at=excluded.updated_at
        ''',
        (domain, cookies_json, headers_json, datetime.utcnow()),
    )
    conn.commit()
    conn.close()


def get_session(domain: str) -> dict[str, Any] | None:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT domain, cookies, headers, updated_at FROM sessions WHERE domain = ?", (domain,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "domain": row["domain"],
        "cookies": json.loads(row["cookies"] or "{}"),
        "headers": json.loads(row["headers"] or "{}"),
        "updated_at": row["updated_at"],
    }


def _domain_candidates(host: str) -> list[str]:
    parts = host.split(".")
    candidates = [host]
    for i in range(1, len(parts)):
        candidate = ".".join(parts[i:])
        if candidate:
            candidates.append(candidate)
    return candidates


def get_session_headers_for_host(host: str) -> Dict[str, str]:
    """
    Retrieve stored headers for a host. Falls back from full host to parent domains.
    """
    if not host:
        return {}

    conn = get_db_connection()
    cursor = conn.cursor()
    headers: Dict[str, str] = {}

    for candidate in _domain_candidates(host):
        cursor.execute("SELECT cookies, headers FROM sessions WHERE domain = ?", (candidate,))
        row = cursor.fetchone()
        if row:
            cookies = json.loads(row["cookies"] or "{}")
            if cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

            stored_headers = json.loads(row["headers"] or "{}")
            headers.update(stored_headers)
            break

    conn.close()
    return headers


def list_sessions() -> list[dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT domain, cookies, headers, updated_at FROM sessions ORDER BY updated_at DESC")
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "domain": row["domain"],
            "cookies": json.loads(row["cookies"] or "{}"),
            "headers": json.loads(row["headers"] or "{}"),
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def delete_session(domain: str) -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE domain = ?", (domain,))
    conn.commit()
    conn.close()
