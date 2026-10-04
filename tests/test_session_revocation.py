"""A password change must end the sessions issued under the old password.

Sessions are stateless JWT cookies with a 24h lifetime. A token that carried only the
user id stayed valid after an admin reset the password or the user changed it, so the
step anyone takes after a stolen cookie — reset the password — did nothing for a day.
The token is now bound to a fingerprint of the password hash and re-checked on read.
"""

from __future__ import annotations

import pytest

COOKIE = "logstotal_auth"


@pytest.mark.parametrize("claim", [None, 7, {}, [], "é" * 32, "0" * 32, ""])
async def test_malformed_password_claim_is_unauthenticated(test_client, regular_user, claim):
    from fastapi_users.jwt import generate_jwt

    from app.auth.users import get_jwt_strategy

    strategy = get_jwt_strategy()
    data = {"sub": str(regular_user.id), "aud": strategy.token_audience, "pwd": claim}
    token = generate_jwt(data, strategy.encode_key, strategy.lifetime_seconds, algorithm=strategy.algorithm)
    assert await _me(test_client, token) == 401


async def _login(client, email: str, password: str = "testpass123") -> str:
    client.cookies.clear()
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": password})
    assert resp.status_code in (200, 204, 303), f"login failed for {email}: {resp.status_code}"
    token = client.cookies.get(COOKIE)
    assert token
    return token


async def _me(client, token: str) -> int:
    client.cookies.clear()
    client.cookies.set(COOKIE, token)
    return (await client.get("/api/users/me")).status_code


async def test_admin_password_reset_revokes_the_targets_existing_session(test_client, admin_user, regular_user):
    stolen = await _login(test_client, "user@test.example.com")
    assert await _me(test_client, stolen) == 200

    await _login(test_client, "admin@test.example.com")
    resp = await test_client.post(f"/admin/users/{regular_user.id}/set-password", data={"password": "a-new-strong-pass-42"}, follow_redirects=False)
    assert resp.status_code == 303
    assert "error" not in resp.headers["location"]

    assert await _me(test_client, stolen) == 401, "a cookie issued before the reset still authenticates"
    # The new password signs in as usual.
    fresh = await _login(test_client, "user@test.example.com", "a-new-strong-pass-42")
    assert await _me(test_client, fresh) == 200


async def test_self_service_password_change_revokes_the_old_session(test_client, regular_user):
    stolen = await _login(test_client, "user@test.example.com")

    test_client.cookies.clear()
    test_client.cookies.set(COOKIE, stolen)
    resp = await test_client.patch("/api/users/me", json={"password": "a-new-strong-pass-42", "current_password": "testpass123"})
    assert resp.status_code == 200

    assert await _me(test_client, stolen) == 401, "a cookie issued before the password change still authenticates"


async def test_admin_resetting_their_own_password_stays_signed_in(test_client, admin_user):
    """The default-password banner sends the admin here; the reset must not sign them out."""
    await _login(test_client, "admin@test.example.com")
    old = test_client.cookies.get(COOKIE)
    resp = await test_client.post(f"/admin/users/{admin_user.id}/set-password", data={"password": "a-new-strong-pass-42"}, follow_redirects=False)
    assert resp.status_code == 303
    assert "error" not in resp.headers["location"]

    new = test_client.cookies.get(COOKIE)
    assert new and new != old
    assert await _me(test_client, new) == 200
    assert await _me(test_client, old) == 401


async def test_a_session_survives_an_unrelated_profile_update(test_client, regular_user):
    token = await _login(test_client, "user@test.example.com")
    test_client.cookies.clear()
    test_client.cookies.set(COOKIE, token)
    resp = await test_client.patch("/api/users/me", json={"display_name": "Renamed"})
    assert resp.status_code == 200
    assert await _me(test_client, token) == 200
