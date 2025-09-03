from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


class HelloView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        auth = getattr(request, "auth", {})  # set in authentication

        # Handle case where auth is a string (JWT token) instead of decoded claims
        if isinstance(auth, str):
            claims = (
                getattr(request.user, "claims", {})
                if hasattr(request.user, "claims")
                else {}
            )
        elif isinstance(auth, dict):
            claims = auth
        else:
            claims = {}

        who = (
            claims.get("preferred_username") or claims.get("email") or claims.get("sub")
        )
        return Response({"message": "hello", "user": who})
