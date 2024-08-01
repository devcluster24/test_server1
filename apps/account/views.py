from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, authenticate
from rest_framework.views import APIView
from rest_framework import generics
from apps.account.serializers import (
                                      UserSerializers,
                                      UserRegistrationSerializers,
                                      UserLoginSerializer,
                                      UserProfileSerializer,
                                      UserUpdateSerializer,
                                      AdminUserUpdateSerializer,
                                      ChangePasswordSerializer,
                                      )
from apps.account.renderers import UserRenderer
from apps.news.models import NewsPost
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from rest_framework.authtoken.models import Token
from django.db import transaction
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    access = refresh.access_token
    access['username'] = user.username
    access['email'] = user.email
    access['role'] = user.role
    return {
        'refresh': str(refresh),
        'access': str(access),
    }


#--------------ADMIN ALL USER CRUD OPERATION-------------

class AllUserView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        queryset = User.objects.filter(role__in=['EDITOR', 'ADMIN'])
        serializer = UserSerializers(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AllUserRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = AdminUserUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        if user.role == "EDITOR" and request.data.get("role") == "ADMIN":
            user.role = "ADMIN"
            user.is_staff = True
            user.save()
        response = super().update(request, *args, **kwargs)
        return Response({"message": "User updated successfully", "user": response.data}, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        user = self.get_object()
        # print(user.is_staff)
        if user.role == "EDITOR" and request.data.get("role") == "ADMIN":
            user.role = "ADMIN"
            user.is_staff = True
            user.save()
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "user partially updated successfully", "user": response.data}, status=status.HTTP_200_OK)
    

class UserRegistrationView(APIView):
    serializer_class = UserRegistrationSerializers

    def post(self, request):
        
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            with transaction.atomic():
                validated_data = serializer.validated_data
                user = serializer.save(validated_data)
                user.save()
                print(user)
                token = default_token_generator.make_token(user)
                # print("token ", token)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                # print("uid ", uid)
                confirm_link = f"https://kalerpotro-server.onrender.com/api/auth_user/active/{uid}/{token}"
                email_subject = "Confirm Your Email"
                email_body = render_to_string('confirm_email.html', {'confirm_link' : confirm_link})
                
                email = EmailMultiAlternatives(email_subject, '', to=[user.email])
                email.attach_alternative(email_body, "text/html")
                email.send()
            return Response("Check your mail for confirmation", status=status.HTTP_200_OK)
        return Response(serializer.errors)


class ActivateAccountView(APIView):
    def get(self, *args, **kwargs):
        uid64 = kwargs.get('uid64')  
        token = kwargs.get('token')

        try:
            uid = urlsafe_base64_decode(uid64).decode()
            user = User.objects.get(pk=uid)
        except User.DoesNotExist:
            user = None
        
        print(user)
        if user is not None and default_token_generator.check_token(user, token):
            print("user valid ache ", user.role)
            if user.role == "ADMIN":
                print("user valid ache Admin er modde", user.role)
                user.is_active = True
                user.is_staff = True
                user.save()

            elif user.role == "EDITOR":
                print("user valid ache editor er modde", user.role)
                user.is_active = True
                user.save()

            
            return Response({"message": "Account Successfully Activated"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Invalid activation link or user does not exist."}, status=status.HTTP_404_NOT_FOUND)


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    # print('login views')
    def post(self, request, format=None):
        print('login post function')
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password)
        if user is not None:
            # print('user ase', user)
            token = get_tokens_for_user(user)
            # print('token hocce-----', token)
            return Response({'token': token, 'msg': 'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors': 'Email or Password is not Valid'}, status=status.HTTP_404_NOT_FOUND)

#ChangePassword

class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        return self.request.user

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)

            # Set new password
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            return Response({"detail": "Password updated successfully"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



    

# User Profile View
class UserProfileView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
   
    def get_object(self):
        queryset = User.objects.get(email=self.request.user.email)
        return queryset
    

class UserUpdateView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        queryset = User.objects.get(email=self.request.user.email)
        return queryset



# class UserLogoutView(APIView):
#     permission_classes = [IsAuthenticated]
    
#     def get(self, request):
#         print(request.data)
#         return Response({"message": "Logout successfully"}, status=status.HTTP_200_OK)


