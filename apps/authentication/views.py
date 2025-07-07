from django.shortcuts import render

# Create your views here.
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import serializers
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.exceptions import AuthenticationFailed, InvalidToken, TokenError
from .serializers import RegisterSerializer, LoginSerializer, LogoutSerializer, ChangePasswordSerializer, ForgetPasswordRequestSerializer, ForgetPasswordSerializer
from common.response import build_response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
import re
from django.db import transaction
from apps.authentication.models import User, PasswordReset
from apps.authentication.permissions import IsAdmin
from common.redis_handlers import redis_service
from django.utils.crypto import get_random_string
from django.utils.timezone import now
from django.conf import settings
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from common.task import send_async_email
from datetime import timedelta
from rest_framework.generics import GenericAPIView
from django.core.mail import send_mail
from drf_spectacular.utils import extend_schema
from drf_spectacular import openapi

class LoginAPIView(TokenObtainPairView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                # Get tokens from validated data
                tokens = serializer.validated_data
                access_token = tokens.get('access')
                refresh_token = tokens.get('refresh')
                
                # Get user from serializer
                user = serializer.user
                
                # Store tokens in Redis
                if access_token and user:
                    redis_service.store_access_token(
                        user_id=user.id,
                        access_token=access_token,
                        refresh_token=refresh_token
                    )
                
                return build_response(
                    message="Login successful.",
                    data=tokens,
                    status=status.HTTP_200_OK
                )
            else:
                return build_response(
                    message="Validation failed.",
                    errors=serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            return build_response(
                message="Login failed due to unexpected error.",
                errors={"detail": [str(e)]},
                status=status.HTTP_400_BAD_REQUEST
            )


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
            
            # Get the new access token
            tokens = serializer.validated_data
            new_access_token = tokens.get('access')
            
            # Extract user ID from the refresh token
            try:
                refresh_token = request.data.get('refresh')
                if refresh_token:
                    decoded_token = RefreshToken(refresh_token)
                    user_id = decoded_token['user_id']
                    
                    # Update access token in Redis
                    if new_access_token and user_id:
                        redis_service.update_access_token(
                            user_id=user_id,
                            new_access_token=new_access_token
                        )
            except Exception as e:
                # Log error but don't fail the request
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to update token in Redis: {str(e)}")
            
            return build_response(
                message="Token refreshed successfully.",
                data=tokens,
                status=status.HTTP_200_OK
            )
        except serializers.ValidationError as validation_error:
            return build_response(
                message="Invalid refresh token.",
                errors=validation_error.detail,
                status=status.HTTP_400_BAD_REQUEST
            )
        except InvalidToken as token_error:
            return build_response(
                message="Invalid or expired refresh token.",
                errors={"non_field_errors": ["Invalid or expired refresh token."]},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except TokenError as token_error:
            return build_response(
                message="Token error occurred.",
                errors={"non_field_errors": [str(token_error)]},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            return build_response(
                message="Token refresh failed due to unexpected error.",
                errors={"detail": [str(e)]},
                status=status.HTTP_400_BAD_REQUEST
            )




class RegisterView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    @extend_schema(
        request=RegisterSerializer,
        responses={201: RegisterSerializer}
    )
    @transaction.atomic
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return build_response(
                message="Registration successful. Temporary password sent to your email.",
                data={"email": user.email},
                status=status.HTTP_201_CREATED
            )
        return build_response(
            message="Validation failed.",
            errors=serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


class LogoutAPIView(APIView):
    """
    API endpoint for user logout. Blacklists refresh token to prevent reuse.
    
    Request Body:
    {
        "refresh_token": "your_refresh_token_here"
    }
    
    Response:
    {
        "status": 200,
        "message": "Logout successful.",
        "data": null,
        "errors": null
    }
    """
    # Remove authentication requirement for logout
    permission_classes = []
    authentication_classes = []  # Disable authentication completely

    @extend_schema(
        request=LogoutSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "example": 200},
                    "message": {"type": "string", "example": "Logout successful."},
                    "data": {"type": "null"},
                    "errors": {"type": "null"}
                }
            },
            400: {
                "type": "object",
                "properties": {
                    "status": {"type": "integer", "example": 400},
                    "message": {"type": "string", "example": "Validation failed."},
                    "data": {"type": "null"},
                    "errors": {"type": "object"}
                }
            }
        },
        tags=["auth"]
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        
        if not serializer.is_valid():
            return build_response(
                message="Validation failed.",
                errors=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Get the refresh token from validated data
            refresh_token = serializer.validated_data.get('refresh_token')
            if not refresh_token:
                return build_response(
                    message="Refresh token is required.",
                    errors={"refresh_token": ["Refresh token is required."]},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Extract user ID from refresh token for Redis deletion
            user_id = None
            try:
                decoded_token = RefreshToken(refresh_token)
                user_id = decoded_token['user_id']
                
                # Delete all tokens for this user from Redis
                if user_id:
                    redis_service.delete_user_tokens(int(user_id))
                    
            except Exception as e:
                # Log error but don't fail the logout
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to delete tokens from Redis: {str(e)}")
            
            # Blacklist the refresh token
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as e:
                # Log error but don't fail the logout
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to blacklist refresh token: {str(e)}")
            
            return build_response(
                message="Logout successful. You have been logged out.",
                data=None,
                status=status.HTTP_200_OK
            )
            
        except serializers.ValidationError as e:
            return build_response(
                message="Invalid refresh token.",
                errors={"refresh_token": ["Invalid or expired refresh token."]},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return build_response(
                message="Logout failed due to unexpected error.",
                errors={"detail": [str(e)]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ChangePasswordAPIView(APIView):
    """
    Allows an authenticated user to reset their password by providing their current password,
    a new password, and a confirmation of the new password.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=ChangePasswordSerializer,
        responses={
            200: OpenApiResponse(description="Password reset successful."),
            400: OpenApiResponse(description="Validation errors."),
            401: OpenApiResponse(description="Authentication required."),
        },
        summary="Change password",
        description="Authenticated users can change their password by providing the current password and a new password.",
        tags=["auth"]
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={"request": request}
        )
        if serializer.is_valid():
            request.user.set_password(serializer.validated_data["new_password"])
            request.user.save()
            return build_response(
                message="Password changed successfully.",
                data=None,
                status=status.HTTP_200_OK
            )
        return build_response(
            message="Password change failed.",
            errors=serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

class RequestForgetPassword(APIView):
    permission_classes = []
    @extend_schema(
        request=ForgetPasswordRequestSerializer,
        responses={200: OpenApiResponse(description="Password reset email sent successfully.")},
        summary="Request password reset email",
        description="Send an email with a password reset link to the user if the email exists."
    )
    def post(self, request):
        serializer = ForgetPasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = User.objects.get(email__iexact=email)

        # Generate unique token
        token = get_random_string(length=32)
        PasswordReset.objects.create(email=user.email, token=token, created_at=now())

        # Generate reset URL
        reset_url = request.build_absolute_uri(f"/auth/password-reset/confirm/{token}/")

        # Send reset email
        context = {
            "user": user,
            "reset_url": reset_url,
            "site_name": get_current_site(request).name,
        }
        email_body = render_to_string("password_reset.html", context)
        send_mail(
            subject="Password Reset Request",
            message="",
            html_message=email_body,
            recipient_list=[user.email],
            from_email=settings.DEFAULT_FROM_EMAIL,
        )

        return Response(
            {"message": "Password reset email sent successfully."},
            status=status.HTTP_200_OK,
        )

class ForgetPassword(GenericAPIView):
    permission_classes = []
    serializer_class = ForgetPasswordSerializer

    def get(self, request, token):
        expire_in_min = int(getattr(settings, "PASSWORD_RESET_TOKEN_EXPIRE", 30))
        reset_entry = PasswordReset.objects.filter(token=token).first()
        if reset_entry:
            expiration_time = reset_entry.created_at + timedelta(minutes=expire_in_min)
            if now() > expiration_time:
                return render(request, "password_reset_error.html", {"error_message": "Token expired."})
            return render(request, "password_reset_form.html", {"token": token})
        else:
            return render(request, "password_reset_error.html", {"error_message": "Invalid token."})

    def post(self, request, token):
        reset_entry = PasswordReset.objects.filter(token=token).first()
        if not reset_entry:
            return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

        expire_in_min = int(getattr(settings, "PASSWORD_RESET_TOKEN_EXPIRE", 30))
        expiration_time = reset_entry.created_at + timedelta(minutes=expire_in_min)
        if now() > expiration_time:
            return Response({"error": "The password reset token has expired."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_password = serializer.validated_data["new_password"]

        user = User.objects.filter(email=reset_entry.email).first()
        if not user:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()
        reset_entry.delete()
        return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)