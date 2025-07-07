import redis
import json
import logging
from datetime import datetime, timedelta
from django.conf import settings
from rest_framework_simplejwt.tokens import AccessToken
from decouple import config
from typing import Optional, Dict, Any
import jwt
from drf_spectacular.utils import extend_schema
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

logger = logging.getLogger(__name__)


class RedisService:
    """
    Redis service for managing JWT tokens
    """
    
    def __init__(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(
                host=str(config('REDIS_HOST', default='localhost')),
                port=config('REDIS_PORT', default=6379, cast=int),
                db=config('REDIS_DB', default=0, cast=int),
                decode_responses=True
            )
            # Test connection
            self.redis_client.ping()
            logger.info("Redis connection established successfully")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            self.redis_client = None
    
    def _get_token_key(self, user_id: int, token_type: str = "access") -> str:
        """
        Generate Redis key for token storage
        
        Args:
            user_id: User ID
            token_type: Type of token (access/refresh)
            
        Returns:
            Redis key string
        """
        return f"user:{user_id}:{token_type}_token"
    
    def _get_token_expiry(self, token: str) -> int:
        """
        Get token expiry time in seconds
        
        Args:
            token: JWT token string
            
        Returns:
            Expiry time in seconds
        """
        try:
            # Decode token without validation to get expiry
            decoded_payload = jwt.decode(
                token, 
                options={"verify_signature": False}
            )
            exp_timestamp = decoded_payload.get('exp', 0)
            current_timestamp = datetime.now().timestamp()
            return int(exp_timestamp - current_timestamp)
        except Exception as e:
            logger.error(f"Error decoding token expiry: {str(e)}")
            return 1800  # Default 30 minutes
    
    def store_access_token(self, user_id: int, access_token: str, refresh_token: Optional[str] = None) -> bool:
        """
        Store access token in Redis with expiry
        
        Args:
            user_id: User ID
            access_token: JWT access token
            refresh_token: JWT refresh token (optional)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            logger.warning("Redis not available, skipping token storage")
            return False
            
        try:
            # Calculate token expiry
            expiry_seconds = self._get_token_expiry(access_token)
            
            # Create token data
            token_data = {
                "access_token": access_token,
                "user_id": user_id,
                "created_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + timedelta(seconds=expiry_seconds)).isoformat()
            }
            
            # Store access token in Redis with expiry
            access_key = self._get_token_key(user_id, "access")
            self.redis_client.setex(
                access_key,
                expiry_seconds,
                json.dumps(token_data)
            )
            
            # Store refresh token separately if provided
            if refresh_token:
                refresh_expiry = self._get_token_expiry(refresh_token)
                refresh_data = {
                    "refresh_token": refresh_token,
                    "user_id": user_id,
                    "created_at": datetime.now().isoformat(),
                    "expires_at": (datetime.now() + timedelta(seconds=refresh_expiry)).isoformat()
                }
                
                refresh_key = self._get_token_key(user_id, "refresh")
                self.redis_client.setex(
                    refresh_key,
                    refresh_expiry,
                    json.dumps(refresh_data)
                )
            
            logger.info(f"Tokens stored in Redis for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing tokens: {str(e)}")
            return False
    
    def update_access_token(self, user_id: int, new_access_token: str) -> bool:
        """
        Update access token in Redis when refreshed
        
        Args:
            user_id: User ID
            new_access_token: New JWT access token
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            logger.warning("Redis not available, skipping token update")
            return False
            
        try:
            # Get existing token data
            key = self._get_token_key(user_id, "access")
            existing_data = self.redis_client.get(key)
            
            if existing_data:
                # Parse existing data
                token_data = json.loads(str(existing_data))
                
                # Update with new access token
                token_data["access_token"] = new_access_token
                token_data["updated_at"] = datetime.now().isoformat()
                
                # Calculate new expiry
                expiry_seconds = self._get_token_expiry(new_access_token)
                token_data["expires_at"] = (datetime.now() + timedelta(seconds=expiry_seconds)).isoformat()
                
                # Store updated data
                self.redis_client.setex(
                    key,
                    expiry_seconds,
                    json.dumps(token_data)
                )
                
                logger.info(f"Access token updated in Redis for user {user_id}")
                return True
            else:
                logger.warning(f"No existing token found for user {user_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating access token: {str(e)}")
            return False
    
    def delete_access_token(self, user_id: int, access_token: Optional[str] = None) -> bool:
        """
        Delete access token from Redis on logout
        
        Args:
            user_id: User ID
            access_token: Access token to validate before deletion (optional)
            
        Returns:
            True if successful or token already expired, False on error
        """
        if not self.redis_client:
            logger.warning("Redis not available, skipping token deletion")
            return True  # Consider it successful if Redis is not available
            
        try:
            key = self._get_token_key(user_id, "access")
            existing_data = self.redis_client.get(key)
            
            if not existing_data:
                logger.info(f"No token found for user {user_id} (already expired or not stored)")
                return True
            
            # If access_token provided, validate it matches
            if access_token:
                token_data = json.loads(str(existing_data))
                stored_token = token_data.get("access_token")
                
                if stored_token != access_token:
                    logger.warning(f"Token mismatch for user {user_id}")
                    return False
            
            # Check if token is still valid
            token_data = json.loads(str(existing_data))
            expires_at_str = token_data.get("expires_at")
            
            if expires_at_str:
                expires_at = datetime.fromisoformat(expires_at_str)
                if datetime.now() > expires_at:
                    logger.info(f"Token for user {user_id} already expired, no deletion needed")
                    return True
            
            # Delete the token
            self.redis_client.delete(key)
            logger.info(f"Access token deleted from Redis for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting access token: {str(e)}")
            return False
    
    def delete_user_tokens(self, user_id: int) -> bool:
        """
        Delete all tokens for a specific user from Redis
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False on error
        """
        if not self.redis_client:
            logger.warning("Redis not available, skipping token deletion")
            return True  # Consider it successful if Redis is not available
            
        try:
            # Delete access token
            access_key = self._get_token_key(user_id, "access")
            self.redis_client.delete(access_key)
            
            # Delete refresh token if exists
            refresh_key = self._get_token_key(user_id, "refresh")
            self.redis_client.delete(refresh_key)
            
            logger.info(f"Tokens deleted from Redis for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting user tokens: {str(e)}")
            return False
    
    def get_token_data(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get stored token data for a user
        
        Args:
            user_id: User ID
            
        Returns:
            Token data dictionary or None if not found
        """
        if not self.redis_client:
            return None
            
        try:
            key = self._get_token_key(user_id, "access")
            data = self.redis_client.get(key)
            if data:
                return json.loads(str(data))
            return None
        except Exception as e:
            logger.error(f"Error getting token data: {str(e)}")
            return None
    
    def is_token_valid(self, user_id: int, access_token: str) -> bool:
        """
        Check if stored token is valid and matches provided token
        
        Args:
            user_id: User ID
            access_token: Access token to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not self.redis_client:
            logger.warning("Redis not available, denying authentication!")
            return False  # Deny authentication if Redis is not available
        
        try:
            token_data = self.get_token_data(user_id)
            if not token_data:
                logger.warning(f"No token data found in Redis for user {user_id}")
                return False  # Deny authentication if no Redis data
            
            stored_token = token_data.get("access_token")
            if not stored_token:
                logger.warning(f"No access token found in Redis data for user {user_id}")
                return False  # Deny authentication if no stored token
            
            if stored_token != access_token:
                logger.warning(f"Token mismatch for user {user_id}. Stored: {stored_token[:20]}..., Provided: {access_token[:20]}...")
                return False
            
            # Check expiry
            expires_at_str = token_data.get("expires_at")
            if expires_at_str:
                try:
                    expires_at = datetime.fromisoformat(expires_at_str)
                    if datetime.now() > expires_at:
                        logger.warning(f"Token expired for user {user_id}")
                        return False
                except Exception as e:
                    logger.warning(f"Error parsing expiry for user {user_id}: {str(e)}")
                    return False  # Deny authentication if expiry parsing fails
            
            logger.info(f"Token validation successful for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error validating token for user {user_id}: {str(e)}")
            return False  # Deny authentication if validation fails


# Global Redis service instance
redis_service = RedisService()

class RedisJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        raw_token = self.get_raw_token(request)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        user_id = validated_token.get('user_id')
        if not user_id:
            raise AuthenticationFailed("No user_id in token")

        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            raise AuthenticationFailed("Invalid user_id in token")

        if not redis_service.is_token_valid(user_id, raw_token.decode()):
            raise AuthenticationFailed('Token has been invalidated or user logged out')

        user = self.get_user(validated_token)
        return (user, validated_token) 