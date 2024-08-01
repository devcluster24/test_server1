from rest_framework import serializers
from rest_framework.validators import ValidationError
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.password_validation import validate_password
from apps.account.models import DashboardStat
User = get_user_model()


class UserSerializers(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
                  'id', 'username', 'first_name', 'role', 'last_name', 
                  'email', 'profile_picture', 'phone', 
                  'address', 'bio'
                  ]


class UserRegistrationSerializers(serializers.ModelSerializer):
    password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = [
            'username', 'first_name', 'last_name', 'email', 
            'role', 'profile_picture', 'password', 'confirm_password'
            ]
        
    def validate(self, attrs):

        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        email_exists = User.objects.filter(email=attrs["email"]).exists()

        if email_exists:
            raise ValidationError("Email has already been used")

        return super().validate(attrs)

    def save(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            role=validated_data['role'],
            profile_picture=validated_data['profile_picture']
            
        )
        user.is_active = False
        user.set_password(validated_data['password'])
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    confirm_password = serializers.CharField(required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is not correct")
        return value

    def validate(self, attrs):
        if attrs['old_password'] == attrs['new_password']:
            raise serializers.ValidationError("New password cannot be the same as the old password")
        
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")

        return attrs 


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
                  'id', 'username', 'first_name', 'last_name', 
                  'email', 'profile_picture', 'phone', 
                  'address', 'bio'
                  ]
        

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
                  'id', 'username', 'first_name', 'last_name', 
                  'email', 'profile_picture', 'phone', 'bio'
                  ]
        

class AdminUserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
                  'id', 'username', 'first_name', 'last_name', 'role', 'is_staff',
                  'email', 'profile_picture', 'phone', 'bio', 'address'
                  ]

    # def update(self, instance, validated_data):
    #     instance.username = validated_data.get('username', instance.username)
    #     instance.first_name = validated_data.get('first_name', instance.first_name)
    #     instance.last_name = validated_data.get('last_name', instance.last_name)
    #     instance.email = validated_data.get('email', instance.email)
    #     instance.profile_picture = validated_data.get('profile_picture', instance.profile_picture)
    #     instance.phone = validated_data.get('phone', instance.phone)
    #     instance.bio = validated_data.get('bio', instance.bio)
    #     instance.save()
    #     return instance


class DashboardStatSerializers(serializers.ModelSerializer):
    class Meta:
        model = DashboardStat
        fields = [
                  'id', 'total_post',
                  'total_shares', 'total_editor', 
                  'todays_post', 'date'
                  ]