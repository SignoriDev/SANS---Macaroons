from __future__ import annotations
import secrets
from typing import Dict, Optional

# Insecure session store: session_id -> username
_SESSIONS: Dict[str, str] = {}

def create_session(user: str) -> str:
    sid = secrets.token_urlsafe(24)
    _SESSIONS[sid] = user
    return sid

def get_user_from_session(session_id: Optional[str]) -> Optional[str]:
    if not session_id:
        return None
    return _SESSIONS.get(session_id)
