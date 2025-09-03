from __future__ import annotations

from typing import Optional

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q
from jwt import PyJWKClient
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .jwks import get_jwks
from .models import OIDCProfile

User = get_user_model()


def _get_bearer_token(request) -> Optional[str]:
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if not auth or not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip()


def _unique_username(base: str) -> str:
    """
    Create a unique username derived from `base` (<=150 chars).
    If base already exists, append _2, _3, ...
    """
    base = (base or "user")[:150]
    candidate = base
    i = 1
    while User.objects.filter(username=candidate).exists():
        i += 1
        suffix = f"_{i}"
        candidate = (base[: 150 - len(suffix)]) + suffix
    return candidate


class BearerJWTAuthentication(BaseAuthentication):
    """
    Verifies an incoming Bearer JWT (RS256) against Keycloak (or Azure AD later),
    enforces issuer/audience/exp, extracts an oid/sub, and maps it to a Django user.
    Optionally auto-provisions a Django user and links an OIDCProfile(oid=...).
    """

    def authenticate(self, request):
        token = _get_bearer_token(request)
        if not token:
            return None  # no credentials; let IsAuthenticated reject

        # --- 1) Validate signature & standard claims ---
        # Optional early check: ensure the token's 'kid' exists in current JWKS.
        # (Not strictly required when using PyJWKClient, but gives a clearer error.)
        try:
            unverified = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise AuthenticationFailed(f"Malformed token header: {e}")

        kid = unverified.get("kid")
        jwks = get_jwks(settings.OIDC_JWKS_URL)
        keys_by_kid = {k.get("kid"): k for k in jwks.get("keys", [])}
        if kid not in keys_by_kid:
            raise AuthenticationFailed("Unknown signing key (kid not found in JWKS)")

        # Resolve the signing key via PyJWKClient
        try:
            jwk_client = PyJWKClient(settings.OIDC_JWKS_URL)
            signing_key = jwk_client.get_signing_key_from_jwt(token).key
        except Exception as e:
            raise AuthenticationFailed(f"Unable to resolve signing key: {e}")

        # Decode & validate
        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=getattr(settings, "OIDC_ACCEPTED_ALGS", ["RS256"]),
                audience=settings.OIDC_AUDIENCE,
                issuer=settings.OIDC_ISSUER,
                options={"verify_exp": True},
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token expired")
        except jwt.InvalidAudienceError:
            raise AuthenticationFailed("Invalid token: audience doesn't match")
        except jwt.InvalidIssuerError:
            raise AuthenticationFailed("Invalid token: issuer doesn't match")
        except jwt.PyJWTError as e:
            raise AuthenticationFailed(f"Invalid token: {e}")

        # --- 2) Extract subject/identity ---
        # Prefer Azure AD-style 'oid'; fall back to 'sub' (Keycloak default)
        oid = claims.get("oid") or claims.get("sub")
        if not oid:
            raise AuthenticationFailed("No oid/sub in token")

        email = claims.get("email")
        preferred_username = claims.get("preferred_username") or email or oid

        # --- 3) Map/Provision Django user and link OIDCProfile(oid) ---
        try:
            # Already linked subject?
            prof = OIDCProfile.objects.select_related("user").get(oid=oid)
            user = prof.user

        except OIDCProfile.DoesNotExist:
            if not getattr(settings, "OIDC_AUTO_PROVISION_USERS", True):
                raise AuthenticationFailed("User not provisioned")

            # Try to reuse an existing user by username/email first
            user = None
            if preferred_username:
                user = User.objects.filter(username=preferred_username).first()
            if not user and email:
                # reuse by email if any non-empty email matches
                user = User.objects.filter(Q(email=email) & ~Q(email="")).first()

            # Create a new user if none found; ensure unique username
            if not user:
                username = _unique_username(preferred_username or oid[:12])
                user = User.objects.create_user(username=username, email=email or "")

            # Link OIDCProfile idempotently
            with transaction.atomic():
                OIDCProfile.objects.get_or_create(user=user, oid=oid)

        # Attach claims for downstream views (optional)
        request.auth = claims
        return (user, token)
