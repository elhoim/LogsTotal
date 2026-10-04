"""The account controls belong to every signed-in user, including the basic role."""

from html.parser import HTMLParser

import pytest


class _Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.ids = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids[attrs["id"]] = (tag, attrs)


@pytest.fixture(params=["user_client", "member_client", "admin_client"])
def signed_in_client(request):
    return request.getfixturevalue(request.param)


async def test_signed_in_navigation_has_account_controls(signed_in_client):
    response = await signed_in_client.get("/jobs")
    assert response.status_code == 200
    html = response.text
    elements = _Elements(html).ids
    assert "account-menu-trigger" in elements
    assert elements["account-menu-trigger"][1]["aria-controls"] == "account-menu"
    assert elements["account-dialog"][0] == "dialog"
    assert elements["account-dialog"][1]["aria-labelledby"] == "account-dialog-title"
    assert 'autocomplete="current-password"' in html
    assert 'autocomplete="new-password"' in html
    assert "Change email" in html and "Change password" in html
    assert html.index("/static/account-menu.js?") < html.index("/static/vendor/alpine.min.js?")


async def test_anonymous_navigation_does_not_offer_account_changes(test_client):
    response = await test_client.get("/auth/login")
    assert response.status_code == 200
    assert "account-menu-trigger" not in _Elements(response.text).ids
    assert "account-dialog" not in _Elements(response.text).ids
    assert "/static/account-menu.js" not in response.text


async def test_email_change_keeps_session_and_uses_new_email_for_next_login(user_client):
    response = await user_client.patch("/api/users/me", json={"email": "updated@test.example.com", "current_password": "testpass123"})
    assert response.status_code == 200
    assert response.json()["email"] == "updated@test.example.com"
    assert "current_password" not in response.json()
    assert (await user_client.get("/api/users/me")).status_code == 200
    assert "updated@test.example.com" in (await user_client.get("/jobs")).text

    await user_client.post("/auth/cookie/logout")
    old = await user_client.post("/auth/cookie/login", data={"username": "user@test.example.com", "password": "testpass123"})
    assert old.status_code == 400
    new = await user_client.post("/auth/cookie/login", data={"username": "updated@test.example.com", "password": "testpass123"})
    assert new.status_code == 204
