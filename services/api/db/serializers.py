from rest_framework import serializers
from db.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.validators import validate_email


class SignUpEndPointSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(style={'input_type': 'passowrd'}, write_only=True)
    class Meta:
        model = User
        fields= ['email', 'name', 'password', 'confirm_password']
        extra_kwargs={
            'password': {'write_only': True}
        }
    #To validate whether the entered email and password are correct.
    def validate(self, data):
        email = data.get('email')
        password, confirm_password = data.get('password'), data.get('confirm_password')
        try:
            validate_email(email)
        except:
            raise serializers.ValidationError("Please provide a valid email address.")
        if password != confirm_password:
            raise serializers.ValidationError("Password and confirm password doesn't match.")
        return data
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
class SignInEndPointSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']

class UserProfileSerialiser(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name']

class UserChangePasswordSerialiser(serializers.Serializer):
    #New password type could be customised here.
    password = serializers.CharField(max_length=255, style={'input_type' : 'password'}, write_only=True)
    confirm_password = serializers.CharField(max_length=255, style={'input_type' : 'password'}, write_only=True)
    class Meta:
        fields = ['passowrd', 'confirm_password']
    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        if password != confirm_password:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        return attrs

    
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email = email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            """
            Instead of local server, desired domain server could be added here.
            """
            link = f'http://localhost:3000/api/user/reset/{uid}/{token}'
            return attrs
        else:
            raise serializers.ValidationError('You are not a Registered User')
    
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    confirm_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        fields = ['password', 'confirm_password']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != confirm_password:
                raise serializers.ValidationError("Password and Confirm Password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            return attrs
        except:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')