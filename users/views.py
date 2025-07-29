from django.shortcuts import render
from django.contrib.auth.hashers import make_password
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from .utils.token_generator import account_activation_token
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes, force_str, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from .serializers import DashboardSerializer, LeaderboardSerializer, MyTokenObtainPairSerializer, CustomRegisterSerializer
from .models import Profile

class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = DashboardSerializer(request.user)
        return Response(serializer.data)

class LeaderboardView(APIView):
    def get(self, request):
        top_profiles = Profile.objects.select_related('user').order_by('-points')[:50]
        serializer = LeaderboardSerializer(top_profiles, many=True)
        return Response(serializer.data)


class RegisterView(APIView):
    def post(self, request):
        data = request.data
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')

        if not name or not email or not password:
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"message": "User already exists"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            email=email,
            password=password,
            first_name=name
        )
        user.save()

        # Auto-create Profile if needed:
        # Profile.objects.create(user=user)

        return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = TokenObtainPairSerializer



User = get_user_model()

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            uid = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_link = f"http://myapp.com/reset-password/{uid}/{token}/"  # or deep link

            send_mail(
                'Reset your password',
                f'Click here to reset your password: {reset_link}',
                'admin@yourapp.com',
                [email],
            )
        return Response({'message': 'If your email is registered, a reset link has been sent.'}, status=200)


class PasswordTokenCheckView(APIView):
    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if PasswordResetTokenGenerator().check_token(user, token):
                return Response({'uid': uidb64, 'token': token}, status=200)
            else:
                return Response({'error': 'Invalid or expired token'}, status=400)
        except Exception:
            return Response({'error': 'Invalid token'}, status=400)


class SetNewPasswordView(APIView):
    def post(self, request):
        uidb64 = request.data.get('uid')
        token = request.data.get('token')
        password = request.data.get('password')

        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Invalid token'}, status=400)

            user.set_password(password)
            user.save()
            return Response({'message': 'Password reset successful'}, status=200)

        except Exception:
            return Response({'error': 'Something went wrong'}, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    user = request.user
    profile = user.profile
    return Response({
        "id": user.id,
        "name": user.first_name,
        "email": user.email,
        "level": profile.level,
        "last_subject": profile.last_subject,
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_user_profile(request):
    user = request.user
    data = request.data

    user.first_name = data.get("name", user.first_name)
    user.email = data.get("email", user.email)
    user.save()

    profile = user.profile
    profile.level = data.get("level", profile.level)
    profile.last_subject = data.get("last_subject", profile.last_subject)
    profile.save()

    return Response({"message": "Profile updated successfully"})
