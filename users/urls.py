from django.urls import path
from .views import RegisterView, MyTokenObtainPairView, DashboardView,update_score, LeaderboardView, PasswordResetRequestView, PasswordTokenCheckView, SetNewPasswordView, get_user_profile, update_user_profile
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset/validate-token/<uidb64>/<token>/', PasswordTokenCheckView.as_view(), name='validate-token'),
    path('password-reset/confirm/', SetNewPasswordView.as_view(), name='password-reset-confirm'),
    path('user/profile/', get_user_profile),
    path('user/update/', update_user_profile),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('leaderboard/', LeaderboardView.as_view(), name='leaderboard'),
    path("api/update-score/", update_score, name="update-score")

]
