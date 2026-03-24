# Week 1 (Track B): Macaroons – Delegatable, Least-Privilege Authorization

This is a small FastAPI service intentionally written in an **insecure** way (ambient authority / confused-deputy flavor),
then refactored to use **macaroons** for explicit, delegatable authority.

## Learning goals (2 hours)
- Understand why **session cookies** are ambient authority for downstream actions.
- Mint a macaroon with **first-party caveats** (resource scope + expiry).
- Verify macaroons server-side and **refuse requests** that exceed scope.
- Gain hands-on familiarity with macaroons using the [`pymacaroons`](https://github.com/ecordell/pymacaroons) library.

## What you build
A mini "file write" API:
- `POST /login` -> returns a session cookie (baseline, insecure)
- `POST /mint` -> mints a macaroon (**TODO: implement in `app/auth_macaroons.py`**)
- `POST /write` -> writes a payload to a "path" (in-memory). Must be authorized.

Baseline behavior:
- If you have a session cookie, you can write **any path**. (Bad)
Target behavior:
- With a macaroon, you can only write within the allowed `path_prefix` and only before `expires_at`.

---

## Quickstart

### 1) Create a venv (Python>=3.10) + install deps
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 2) Run tests (you should see failures until you implement macaroons)
```bash
pytest -q
```

### 3) Run the service
```bash
uvicorn app.main:app --reload
```

---

## Your tasks (what to implement)

### Task A — Implement macaroon minting
In `app/auth_macaroons.py`, implement:
- `mint_macaroon(user: str, path_prefix: str, ttl_seconds: int) -> str`
- Caveats:
  - `user = <username>`
  - `path_prefix = <prefix>` (e.g., `/tmp/alice/`)
  - `expires_at = <unix_ts>` (current time + ttl)

### Task B — Implement macaroon verification
In `app/auth_macaroons.py`, implement:
- `verify_macaroon(token: str, *, user: str, path: str) -> None`
- Requirements:
  - Must verify signature (shared root key)
  - Must enforce:
    - user matches
    - path starts with `path_prefix`
    - current time <= expires_at
- On failure: raise `HTTPException(status_code=403, detail="...")` with a helpful detail.

### Task C — Switch `/write` to require macaroons
In `app/main.py`, change `/write` to accept **either**:
- `Authorization: Bearer <macaroon>` (preferred)
- (Optional) keep session cookie path only for local debugging

The tests assume that `/write` is protected by macaroons.

---

## Design notes (intended to echo "Confused Deputy")
- Session cookies are *ambient authority*: once logged in, downstream calls can accidentally do too much.
- Macaroons make authority **explicit** and **attenuatable** via caveats.

---

## Suggested 2-hour flow for students
1. Run tests and inspect failures (10 min)
2. Read `auth_macaroons.py` skeleton and caveat format (10 min)
3. Implement minting (20 min)
4. Implement verification (40 min)
5. Wire `/write` to use macaroons (20 min)
6. Re-run tests and confirm all pass (10 min)

---

## Expected test outcomes
- `test_path_traversal_blocked_by_prefix` should PASS after you implement prefix caveat.
- `test_expired_macaroon_rejected` should PASS after expiry caveat.
- `test_user_binding_enforced` should PASS after user caveat.

Good luck — and please keep your implementation simple and readable.
