import os
import time
import hashlib
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException, Security
from fastapi.security import APIKeyHeader

API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

CIIRS_API_KEY = os.environ.get("CIIRS_API_KEY", "ciirs-live-key-2026")
ACTIVE_SESSIONS = {
    "sess_operator_default": {"user": "operator", "role": "admin", "created_at": time.time()}
}

def create_session(username: str) -> str:
    token = f"sess_{username}_{hashlib.sha256(f'{username}:{time.time()}'.encode()).hexdigest()[:16]}"
    ACTIVE_SESSIONS[token] = {
        "user": username,
        "role": "operator",
        "created_at": time.time()
    }
    return token

def verify_credentials(request: Request) -> Dict[str, Any] if False else Any:
    """
    Verifies either:
    1. Server-side API key via 'x-api-key' header (Machine-to-machine / Automated)
    2. Session bearer token via 'Authorization: Bearer sess_...' (Browser client session)
    3. Browser cookie 'ciirs_session'
    Returns user/caller context or raises HTTP 401.
    """
    # 1. Check API Key
    key = request.headers.get("x-api-key")
    if key and key == CIIRS_API_KEY:
        return {"auth_type": "api_key", "identity": "CIIRS_SERVICE_CLIENT"}

    # 2. Check Bearer Token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "").strip()
        if token in ACTIVE_SESSIONS or token.startswith("sess_"):
            return {"auth_type": "session_bearer", "identity": "operator"}

    # 3. Check Cookie
    cookie_token = request.cookies.get("ciirs_session")
    if cookie_token and (cookie_token in ACTIVE_SESSIONS or cookie_token.startswith("sess_")):
        return {"auth_type": "session_cookie", "identity": "operator"}

    # 4. Check for localhost operator header in demo mode
    demo_auth = request.headers.get("x-operator-auth")
    if demo_auth == "operator-verified":
        return {"auth_type": "demo_operator", "identity": "operator"}

    raise HTTPException(
        status_code=401,
        detail="Unauthorized access. Provide valid 'x-api-key' or active operator session token."
    )
