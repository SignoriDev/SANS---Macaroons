from __future__ import annotations

import time
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app

transport = ASGITransport(app=app)

@pytest.mark.anyio
async def test_path_traversal_blocked_by_prefix():
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Mint a macaroon for alice limited to /tmp/alice/
        r = await ac.post("/mint", json={"user": "alice", "path_prefix": "/tmp/alice/", "ttl_seconds": 60})
        assert r.status_code == 200
        mac = r.json()["macaroon"]

        # Attempt to write outside allowed prefix
        r2 = await ac.post(
            "/write",
            headers={"Authorization": f"Bearer {mac}"},
            json={"user": "alice", "path": "/etc/passwd", "contents": "oops"},
        )
        assert r2.status_code == 403
        assert "path_prefix" in r2.text or "prefix" in r2.text


@pytest.mark.anyio
async def test_expired_macaroon_rejected():
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/mint", json={"user": "alice", "path_prefix": "/tmp/alice/", "ttl_seconds": 1})
        assert r.status_code == 200
        mac = r.json()["macaroon"]

        time.sleep(2)

        r2 = await ac.post(
            "/write",
            headers={"Authorization": f"Bearer {mac}"},
            json={"user": "alice", "path": "/tmp/alice/note.txt", "contents": "hello"},
        )
        assert r2.status_code == 403
        assert "expire" in r2.text.lower()


@pytest.mark.anyio
async def test_user_binding_enforced():
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/mint", json={"user": "alice", "path_prefix": "/tmp/alice/", "ttl_seconds": 60})
        assert r.status_code == 200
        mac = r.json()["macaroon"]

        # Try to use alice's macaroon while claiming to be bob
        r2 = await ac.post(
            "/write",
            headers={"Authorization": f"Bearer {mac}"},
            json={"user": "bob", "path": "/tmp/alice/steal.txt", "contents": "hi"},
        )
        assert r2.status_code == 403
        assert "user" in r2.text.lower()
