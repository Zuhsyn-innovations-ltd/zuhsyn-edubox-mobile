from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Profile
from dj_rest_auth.registration.serializers import RegisterSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


# ✅ JWT Login using Email
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = User.email  # Tells SimpleJWT to use email

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = User.objects.filter(email=email).first()

        if user and user.check_password(password):
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled.')

            refresh = RefreshToken.for_user(user)

            return {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': f"{user.first_name} {user.last_name}".strip(),
                }
            }

        raise serializers.ValidationError('Invalid login credentials.')


# ✅ Registration Serializer with full_name
class CustomRegisterSerializer(RegisterSerializer):
    full_name = serializers.CharField(required=True)

    def get_cleaned_data(self):
        return {
            'email': self.validated_data.get('email', ''),
            'password1': self.validated_data.get('password1', ''),
            'password2': self.validated_data.get('password2', ''),
            'full_name': self.validated_data.get('full_name', ''),
        }

    def save(self, request):
        user = super().save(request)
        full_name = self.cleaned_data.get('full_name', '').strip()

        # Split full_name into first_name and last_name
        names = full_name.split(' ', 1)
        user.first_name = names[0]
        user.last_name = names[1] if len(names) > 1 else ''

        user.save()
        return user


# Dashboard Serializer
class DashboardSerializer(serializers.ModelSerializer):
    level = serializers.IntegerField(source='profile.level', read_only=True)
    last_subject = serializers.CharField(source='profile.last_subject', read_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'level', 'last_subject']


# Leaderboard Serializer
class LeaderboardSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = Profile
        fields = ['email', 'points', 'level']
