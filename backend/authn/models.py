from django.conf import settings
from django.db import models


class OIDCProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="oidc_profile"
    )
    oid = models.CharField(max_length=64, unique=True)

    def __str__(self):
        return f"{self.user.username} ({self.oid})"
