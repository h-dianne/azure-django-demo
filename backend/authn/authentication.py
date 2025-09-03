import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from jwt import PyJWKClient
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .jwks import get_jwks
from .models import OIDCProfile

User = get_user_model()


def _get_bearer_token(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip()


class BearerJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = _get_bearer_token(request)
        if not token:
            return None

        # Fetch JWKS and pick key by 'kid'
        unverified = jwt.get_unverified_header(token)
        kid = unverified.get("kid")
        jwks = get_jwks(settings.OIDC_JWKS_URL)
        keys = {k["kid"]: k for k in jwks.get("keys", [])}
        key = keys.get(kid)
        if not key:
            raise AuthenticationFailed("Unknown signing key")

        # Build public key and decode
        jwk_client = PyJWKClient(settings.OIDC_JWKS_URL)
        signing_key = jwk_client.get_signing_key_from_jwt(token).key

        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=settings.OIDC_ACCEPTED_ALGS,
                audience=settings.OIDC_AUDIENCE,
                issuer=settings.OIDC_ISSUER,
                options={"verify_exp": True},
            )
        except jwt.PyJWTError as e:
            raise AuthenticationFailed(f"Invalid token: {e}")

        # Prefer 'oid' (Azure AD style) but fall back to 'sub'
        oid = claims.get("oid") or claims.get("sub")
        if not oid:
            raise AuthenticationFailed("No oid/sub in token")

        # OPTIONAL: username/email from claims
        preferred_username = (
            claims.get("preferred_username") or claims.get("email") or oid
        )

        # Map token subject to Django user
        try:
            prof = OIDCProfile.objects.select_related("user").get(oid=oid)
            user = prof.user
        except OIDCProfile.DoesNotExist:
            if settings.OIDC_AUTO_PROVISION_USERS:
                # Create a minimal user + OIDCProfile
                user = User.objects.create_user(username=preferred_username)
                OIDCProfile.objects.create(user=user, oid=oid)
            else:
                raise AuthenticationFailed("User not provisioned")

        # Attach claims (optional) for views
        request.auth = claims
        return (user, token)
