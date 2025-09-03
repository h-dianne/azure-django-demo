import requests
from django.core.cache import cache

CACHE_KEY = "oidc_jwks"
CACHE_TTL = 24 * 60 * 60  # 24hr


def get_jwks(jwks_url: str) -> dict:
    jwks = cache.get(CACHE_KEY)
    if jwks:
        return jwks
    resp = requests.get(jwks_url, timeout=5)
    resp.raise_for_status()
    jwks = resp.json()
    cache.set(CACHE_KEY, jwks, CACHE_TTL)
    return jwks
