from fastapi import APIRouter, HTTPException, Query

from ..core.authentication import login_and_store_session
from ..core.session_manager import delete_session, get_session, list_sessions
from ..models.auth import LoginRequest, SessionInfo

router = APIRouter()


@router.post("/auth/login", response_model=SessionInfo)
def authenticate(request: LoginRequest):
    try:
        return login_and_store_session(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/auth/sessions")
def get_sessions(domain: str | None = Query(default=None, description="Filter sessions by domain substring")):
    sessions = list_sessions()
    if domain:
        domain_lower = domain.lower()
        sessions = [s for s in sessions if domain_lower in s["domain"].lower()]
    return sessions


@router.get("/auth/sessions/{domain}", response_model=SessionInfo | None)
def get_session_detail(domain: str):
    session = get_session(domain)
    if not session:
        return None
    return SessionInfo(
        domain=session["domain"],
        status_code=200,
        cookies=session["cookies"],
        headers=session["headers"],
        body_preview="Session restored from store.",
    )


@router.delete("/auth/sessions/{domain}")
def clear_session(domain: str):
    delete_session(domain)
    return {"message": f"Session for {domain} removed."}
