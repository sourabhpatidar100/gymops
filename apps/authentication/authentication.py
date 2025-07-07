from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from common.redis_handlers import redis_service
import logging

from common.response import build_response

logger = logging.getLogger(__name__)


class RedisJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication that validates tokens against Redis
    to ensure they haven't been invalidated (e.g., on logout)
    """
    
    def authenticate(self, request):
        try:
            raw_token = self.get_raw_token(request)
            if raw_token is None:
                return None

            validated_token = self.get_validated_token(raw_token)
            user = self.get_user(validated_token)
            user_id = validated_token.get("user_id")

            if not user_id:
                raise AuthenticationFailed("Invalid token: missing user_id")

            # Decode raw_token if it's bytes
            if isinstance(raw_token, bytes):
                raw_token = raw_token.decode("utf-8")

            # Check if token exists in Redis for this user
            if not redis_service.is_token_valid(user_id, raw_token):
                raise AuthenticationFailed("Session expired or token is no longer valid.")

            return (user, validated_token)

        except InvalidToken as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise AuthenticationFailed("Invalid or expired token.")
        except AuthenticationFailed as e:
            raise e
        except Exception as e:
            logger.error(f"Unexpected authentication error: {str(e)}")
            raise AuthenticationFailed("Authentication failed.")

    def get_raw_token(self, request):
        header = self.get_header(request)
        if header is None:
            return None
        return self.get_raw_token_from_header(header)

    def get_raw_token_from_header(self, header):
        if isinstance(header, bytes):
            header = header.decode("utf-8")

        parts = header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthenticationFailed(
                "Authorization header must be: Bearer <token>"
            )

        return parts[1]
