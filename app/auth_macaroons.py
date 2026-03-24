from __future__ import annotations

import time
from typing import Tuple

from fastapi import HTTPException
from pymacaroons import Macaroon
from pymacaroons.verifier import Verifier

# Root key used to sign macaroons (shared secret, server-side only).
# In a real service this would live in a secret manager / HSM.
ROOT_KEY = b"CHANGE_ME_IN_PROD_root_key_for_week1_exercise"

# Location is informational; identifier can be used for auditing / lookup.
LOCATION = "iot-sec-week1"
IDENTIFIER = "write-capability"

# Caveat keys (simple first-party caveats encoded as 'k = v' strings)
CAV_USER = "user"
CAV_PATH_PREFIX = "path_prefix"
CAV_EXPIRES_AT = "expires_at"


def _parse_caveat(caveat: str) -> Tuple[str, str]:
    """Parse a first-party caveat formatted as 'k = v'."""
    if " = " not in caveat:
        raise ValueError(f"bad caveat format: {caveat!r}")
    k, v = caveat.split(" = ", 1)
    return k.strip(), v.strip()


def mint_macaroon(user: str, path_prefix: str, ttl_seconds: int) -> str:
    """
    TODO (students): Mint a macaroon for `user` allowing writes only under `path_prefix`
    until now + ttl_seconds.

    Return the serialized macaroon (string).
    """
    expires_at = int(time.time()) + ttl_seconds

    macaroon = Macaroon(
        location=LOCATION,
        identifier=IDENTIFIER,
        key=ROOT_KEY
    )

    macaroon.add_first_party_caveat(f"{CAV_USER} = {user}")
    macaroon.add_first_party_caveat(f"{CAV_PATH_PREFIX} = {path_prefix}")
    macaroon.add_first_party_caveat(f"{CAV_EXPIRES_AT} = {expires_at}")

    return macaroon.serialize()


def verify_macaroon(token: str, *, user: str, path: str) -> None:
    """
    TODO (students): Verify token signature AND enforce caveats:
      - user matches
      - path startswith path_prefix
      - time.time() <= expires_at

    On any failure, raise HTTPException(403, detail="...").

    Returns None if authorized.
    """
    try:
        m = Macaroon.deserialize(token)
        verifier = _make_verifier(expected_user=user, requested_path=path)
        verifier.verify(m, ROOT_KEY)
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"Invalid or unauthorized macaroon: {e}")


# ---------------------------
# Reference caveat verifier helpers
# ---------------------------

def _make_verifier(*, expected_user: str, requested_path: str) -> Verifier:
    """Create a verifier with predicates for all first-party caveats."""
    v = Verifier()

    def predicate(cav: str) -> bool:
        try:
            k, val = _parse_caveat(cav)
        except ValueError:
            raise ValueError(f"Invalid caveat format: {cav}")

        if k == CAV_USER:
            if val != expected_user:
                raise ValueError("user mismatch")
            return True

        if k == CAV_PATH_PREFIX:
            # Enforce prefix restriction on the requested path
            if not requested_path.startswith(val):
                raise ValueError("path_prefix restriction failed")
            return True

        if k == CAV_EXPIRES_AT:
            try:
                exp = int(val)
            except ValueError:
                raise ValueError("invalid expire format")
            if int(time.time()) > exp:
                raise ValueError("macaroon expired")
            return True

        # Unknown caveat => fail closed
        raise ValueError(f"unknown caveat: {k}")

    v.satisfy_general(predicate)
    return v
