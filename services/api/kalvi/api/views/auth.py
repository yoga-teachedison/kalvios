from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from db.serializers import SignUpEndPointSerializer, SignInEndPointSerializer, UserProfileSerialiser, UserChangePasswordSerialiser, SendPasswordResetEmailSerializer, UserPasswordResetSerializer
from django.contrib.auth import authenticate
from db.renderer import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from db.models import User

# Generate stateless token for User
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }

#viewset class for sign up
class SignUpEndPoint(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = SignUpEndPointSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()       
        token = get_tokens_for_user(user)
        return Response({'token' : token, 'msg': 'user registered'}, status=status.HTTP_201_CREATED)

#viewset class for sign in 
class SignInEndPoint(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = SignInEndPointSerializer(data=request.data)  
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password)
        if user:
            token = get_tokens_for_user(user)
            return Response({'token' : token,'msg' : 'Login Successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors' : {'non_field_errors' : ["Email or password is not valid"]}}, status=status.HTTP_404_NOT_FOUND)


#viewset class for changing password, only authenticated users could change password. 
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post (self, request, format=None):
        serializer = UserChangePasswordSerialiser(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        user.set_password(serializer.data.get('password'))
        user.save()
        return Response({'msg' : 'Password changed successfully'}, status=status.HTTP_200_OK)

#viewset class for profile view of a user with get method using access tokens.
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerialiser(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

#viewset class for sending email to reset password in case of forget password.
class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

#viewset class for changing password from local browser after getting email rest link.
class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
        serializer.is_valid(raise_exception=True)
        id = smart_str(urlsafe_base64_decode(uid))
        user = User.objects.get(id=id)
        password = serializer.validated_data.get('password')
        user.set_password(password)
        user.save()
        return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
