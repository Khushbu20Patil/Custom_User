from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
from user.views import UserRegistrationView, UserLoginView, UserLogoutView, UserUpdateView, ChangePasswordView, UserDeleteView, Verifyotp, OtpForFPView, VerifyotpForFP, ResendOtpPasswordView, ResendOtpRegisterView, CustomTokenObtainPairView
urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('update/', UserUpdateView.as_view(), name='update'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    path('change_password/', ChangePasswordView.as_view(), name='change_password'),
    path('delete/', UserDeleteView.as_view(), name='delete'),
    path('otp/', Verifyotp.as_view(), name='otp'),
    path('resend_otp_for_Verify/', ResendOtpRegisterView.as_view(), name='resend'),

    path('resend_otp_for_password/', ResendOtpPasswordView.as_view(), name='resend'),
    path('otpforFP/', VerifyotpForFP.as_view(), name='otpforforgotverify'),    
    # path('token/',CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('fpotp/', OtpForFPView.as_view(), name='fpotp'),
]