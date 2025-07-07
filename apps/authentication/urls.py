from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from .views import LoginAPIView, CustomTokenRefreshView, RegisterView, LogoutAPIView, ChangePasswordAPIView, RequestForgetPassword, ForgetPassword

urlpatterns = [
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path("reset-password/", ChangePasswordAPIView.as_view(), name="reset-password"),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('forgot-password/', RequestForgetPassword.as_view(), name='forgot-password'),
    path('password-reset/confirm/<str:token>/', ForgetPassword.as_view(), name='password-reset-confirm'),
]



