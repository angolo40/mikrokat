"""Optional sign-in through an OpenID Connect provider such as Authentik, Keycloak or Authelia."""
import base64
import hashlib
import json
import secrets
import time
import urllib.parse
import urllib.request

import store

PENDING_SECONDS = 300
pending = {}


class SignInError(Exception):
    """A sign-in that must be refused. The message is shown to the user."""


def fetch_json(url, data=None, headers=None):
    request = urllib.request.Request(url, data=data, headers={"Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def metadata():
    issuer = store.settings["oidc_issuer"].rstrip("/")
    return fetch_json(f"{issuer}/.well-known/openid-configuration")


def begin(redirect_uri):
    """Return (provider url, state) for a new sign-in."""
    now = time.time()
    for key in [k for k, v in pending.items() if v["at"] < now - PENDING_SECONDS]:
        del pending[key]
    s = store.settings
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    pending[state] = {"at": now, "nonce": nonce, "verifier": verifier}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode({"response_type": "code", "client_id": s["oidc_client_id"], "redirect_uri": redirect_uri,
                                    "scope": s["oidc_scopes"], "state": state, "nonce": nonce,
                                    "code_challenge": challenge, "code_challenge_method": "S256"})
    return f"{metadata()['authorization_endpoint']}?{query}", state


def decode_token(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def finish(code, state, redirect_uri):
    """Exchange the code and return the user name, or raise SignInError."""
    s = store.settings
    started = pending.pop(state, None)
    if not started or started["at"] < time.time() - PENDING_SECONDS:
        raise SignInError("This sign-in has expired. Please try again.")
    meta = metadata()
    form = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "client_id": s["oidc_client_id"],
                                   "client_secret": s["oidc_client_secret"], "code_verifier": started["verifier"]}).encode()
    tokens = fetch_json(meta["token_endpoint"], form, {"Content-Type": "application/x-www-form-urlencoded"})
    # The token comes straight from the provider over TLS, so these claim checks are the ones that matter here.
    claims = decode_token(tokens["id_token"])
    audience = claims.get("aud")
    audience = audience if isinstance(audience, list) else [audience]
    if claims.get("iss") != meta["issuer"] or s["oidc_client_id"] not in audience or claims.get("exp", 0) < time.time() or claims.get("nonce") != started["nonce"]:
        raise SignInError("The provider's answer did not pass the checks.")
    user = fetch_json(meta["userinfo_endpoint"], headers={"Authorization": f"Bearer {tokens['access_token']}"})
    groups = user.get("groups") or claims.get("groups") or []
    name = user.get("preferred_username") or user.get("email") or claims.get("sub", "unknown")
    if s["oidc_group"] not in groups:
        raise SignInError(f"{name} is not in the group that can use Mikrokat.")
    return name
