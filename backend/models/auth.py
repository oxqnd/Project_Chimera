from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    domain: str = Field(..., description="Domain for which the session should be stored (e.g., example.com)")
    login_url: str = Field(..., description="Full URL for the authentication endpoint")
    method: str = Field(default="POST", description="HTTP method to use when authenticating")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Headers to include in the login request")
    body: Optional[str] = Field(default=None, description="Raw request body (used when json_body is absent)")
    json_body: Optional[Dict[str, Any]] = Field(default=None, description="JSON payload for the login request")
    follow_redirects: bool = Field(default=True, description="Whether to follow redirects during authentication")
    timeout: int = Field(default=30, description="Timeout for the login request in seconds")
    token_path: Optional[str] = Field(
        default=None,
        description="Dot-separated path within the JSON response to extract a token (e.g., 'data.access_token')",
    )
    token_prefix: Optional[str] = Field(
        default="Bearer ",
        description="Prefix applied to extracted tokens before storing (defaults to 'Bearer ')",
    )
    token_header_name: Optional[str] = Field(
        default="Authorization",
        description="Header name used to store extracted tokens (defaults to 'Authorization')",
    )
    persist_response_headers: Optional[List[str]] = Field(
        default=None,
        description="List of response headers to persist into the session store (case-sensitive).",
    )


class SessionInfo(BaseModel):
    domain: str
    status_code: int
    cookies: Dict[str, str]
    headers: Dict[str, str]
    body_preview: str
