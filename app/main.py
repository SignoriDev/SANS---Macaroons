from __future__ import annotations

from fastapi import FastAPI, Cookie, Header, HTTPException
from pydantic import BaseModel, Field

from app.storage import InMemoryFS
from app.auth_session import create_session, get_user_from_session
from app.auth_macaroons import mint_macaroon, verify_macaroon

app = FastAPI(title="Week 1 Track B: Macaroons")

FS = InMemoryFS()


class LoginReq(BaseModel):
    user: str = Field(min_length=1, max_length=64)


class MintReq(BaseModel):
    user: str = Field(min_length=1, max_length=64)
    path_prefix: str = Field(min_length=1, max_length=256, description="e.g., /tmp/alice/")
    ttl_seconds: int = Field(ge=1, le=86400, description="token TTL in seconds")


class WriteReq(BaseModel):
    user: str = Field(min_length=1, max_length=64)
    path: str = Field(min_length=1, max_length=256)
    contents: str = Field(min_length=0, max_length=10_000)


@app.post("/login")
def login(req: LoginReq):
    # Baseline, insecure: returns a session cookie which implicitly confers broad authority.
    sid = create_session(req.user)
    return {"session_id": sid, "note": "baseline session created (ambient authority)"}


@app.post("/mint")
def mint(req: MintReq):
    # TODO: students implement mint_macaroon() in app/auth_macaroons.py
    token = mint_macaroon(req.user, req.path_prefix, req.ttl_seconds)
    return {"macaroon": token}


def _extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    if not authorization.lower().startswith("bearer "):
        return None
    return authorization.split(" ", 1)[1].strip() or None


@app.post("/write")
def write_file(
    req: WriteReq,
    authorization: str | None = Header(default=None),
    session: str | None = Cookie(default=None),
):
    # Insecure baseline path (session cookies): you can write anywhere once logged in.
    # Students should switch to macaroons (explicit least privilege).
    bearer = _extract_bearer(authorization)

    if bearer:
        # Preferred: macaroon-based authorization
        verify_macaroon(bearer, user=req.user, path=req.path)
    else:
        # Baseline behavior kept for debugging. Tests expect macaroons; they will fail until you implement them.
        u = get_user_from_session(session)
        if u != req.user:
            raise HTTPException(status_code=401, detail="invalid or missing session for user")

    FS.write(path=req.path, owner=req.user, contents=req.contents)
    return {"ok": True, "path": req.path}


@app.get("/read")
def read_file(path: str):
    # Intentionally unauthenticated read; not the focus of this lab.
    try:
        owner, contents = FS.read(path=path)
    except KeyError:
        raise HTTPException(status_code=404, detail="not found")
    return {"path": path, "owner": owner, "contents": contents}
