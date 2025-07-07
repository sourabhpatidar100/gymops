from common.task import send_temp_password_email
from rest_framework import serializers
from .models import User
import secrets
import re
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import date
from django.utils.timezone import now
from apps.authentication.models import User  # adjust if path differs
import secrets
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password

class LoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        try:
            data = super().validate(attrs)
            return data
        except Exception as e:
            error_message = str(e)
            
            # Check if user exists first
            email = attrs.get('email', '')
            password = attrs.get('password', '')
            
            # Try to authenticate to determine the specific error
            user = authenticate(email=email, password=password)
            
            if user is None:
                # Check if user exists with this email
                user_exists = User.objects.filter(email=email).exists()
                if user_exists:
                    # User exists but password is wrong
                    raise serializers.ValidationError({
                        "password": ["Wrong password. Please check your password."]
                    })
                else:
                    # User doesn't exist
                    raise serializers.ValidationError({
                        "email": ["Invalid email. No account found with this email address."]
                    })
            else:
                # If we reach here, there might be other issues
                raise serializers.ValidationError({
                    "non_field_errors": ["Authentication failed. Please try again."]
                })

class RegisterSerializer(serializers.ModelSerializer):
    dob = serializers.DateField(required=False)
    height = serializers.FloatField(required=False, default=None)
    weight = serializers.FloatField(required=False, default=None)
    role = serializers.IntegerField(required=False, default=3)

    class Meta:
        model = User
        fields = ['email', 'phone_number', 'height', 'weight', 'role', 'dob']
        extra_kwargs = {
            'email': {'required': True},
            'phone_number': {'required': True},
        }

    def validate_email(self, value):
        email = value.strip().lower()
        email_regex = r"^[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            raise serializers.ValidationError("Invalid email format.")
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email is already registered.")
        return email

    def validate_phone_number(self, value):
        phone = value.strip()
        if not re.match(r"^[6-9]\d{9}$", phone):
            raise serializers.ValidationError("Phone number must be 10 digits and start with 9, 8, 7, or 6.")
        if User.objects.filter(phone_number=phone).exists():
            raise serializers.ValidationError("Phone number is already registered.")
        return phone

    def validate_role(self, value):
        if value not in [1, 2, 3]:
            raise serializers.ValidationError("Invalid role value. Must be 1 (admin), 2 (trainer), or 3 (member).")
        return value

    def validate_dob(self, value):
        if not value:
            return None
        today = date.today()
        if value > today:
            raise serializers.ValidationError("Date of birth cannot be in the future.")
        age = today.year - value.year - ((today.month, today.day) < (value.month, value.day))
        if age < 18:
            raise serializers.ValidationError("User must be at least 18 years old.")
        return value

    def validate_height(self, value):
        if value is not None and (value < 30 or value > 300):
            raise serializers.ValidationError("Height must be between 30 cm and 300 cm.")
        return value

    def validate_weight(self, value):
        if value is not None and (value < 10 or value > 500):
            raise serializers.ValidationError("Weight must be between 10 kg and 500 kg.")
        return value

    def create(self, validated_data):
        email = validated_data['email'].lower()
        phone_number = validated_data['phone_number']
        dob = validated_data.get('dob')

        age = None
        if dob:
            today = date.today()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

        temp_password = secrets.token_urlsafe(12)

        user = User.objects.create_user(
            email=email,
            phone_number=phone_number,
            height=validated_data.get('height'),
            weight=validated_data.get('weight'),
            role=validated_data.get('role', 3),
            dob=dob,
            age=age,
            password=temp_password
        )

        send_temp_password_email.delay(user.email, temp_password)
        return user


class LogoutSerializer(serializers.Serializer):
    """
    Serializer for logout API
    """
    refresh_token = serializers.CharField(
        required=True,
        help_text="The refresh token to blacklist"
    )
    
    def validate_refresh_token(self, value):
        """
        Validate that the refresh token is valid
        """
        try:
            # Try to decode the token to check if it's valid
            token = RefreshToken(value)
            return value
        except Exception:
            raise serializers.ValidationError("Invalid refresh token.")

class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        request = self.context["request"]
        user = request.user

        # Check if current password matches the user's password in the database
        if not check_password(data["current_password"], user.password):
            raise serializers.ValidationError(
                {"current_password": "Current password is incorrect."}
            )

        # Validate new password and confirm password match
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                {"new_password": "New password and confirm password do not match."}
            )

        # Additional password validation (e.g., complexity, reuse prevention)
        if data["current_password"] == data["new_password"]:
            raise serializers.ValidationError(
                {
                    "new_password": "New password cannot be the same as the current password."
                }
            )

        return data

class ForgetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        user = User.objects.filter(email__iexact=value).first()
        if not user:
            raise serializers.ValidationError("No user found with this email.")
        return value

class ForgetPasswordSerializer(serializers.Serializer):
    new_password = serializers.RegexField(
        regex=r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
        write_only=True,
        error_messages={
            "invalid": (
                "Password must be at least 8 characters long with at least one uppercase letter, one number, and one special character."
            )
        },
    )
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match.")
        return data



