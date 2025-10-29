from django.contrib.auth import user_logged_in
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.renderers import TemplateHTMLRenderer, JSONRenderer
from rest_framework.request import Request
from rest_framework.views import APIView

from rest_framework import serializers, status
from rest_framework.decorators import api_view, permission_classes, authentication_classes, renderer_classes
from django.core.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from django.contrib.auth.password_validation import validate_password

from .authentication import JWTAuthentication
from .decorators import protected_decorator
from .models import User

from .serializers import UserSerializer, BookSerializer, LoginSerializer, UserDetailsSerializer
from .service import JWTManagerService


@api_view(['POST'])
@permission_classes(AllowAny, )
def register_user(request: Request, *args, **kwargs):
    required_args = {'email', 'password','password2', 'first_name', 'last_name'}
    misssing_fields = required_args - request.data.keys()
    if misssing_fields:
        raise serializers.ValidationError(f"The following fields are missing: {misssing_fields}")
    try:
        validate_password(request.data['password'])
    except ValidationError as password_error:
        return Response({'Error': [str(e) for e in password_error.messages]})
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(
            {'Status': True, 'Message': 'User registered successfully'},
            status=status.HTTP_201_CREATED
        )
    return Response({'Status': False, 'Errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



class LoginView(APIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request: Request, *args, **kwargs):
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            user = User.objects.get(email=email)
            if user.check_password(password) and user.is_active:
                service = JWTManagerService()
                jwt_access = service.create_token(user=user, token_type="access")
                user_logged_in.send(sender=user.__class__, request=request, user=user)
                return Response({
                    'access': str(jwt_access),
                }, status=status.HTTP_200_OK)
            else:
                res = {
                    'error': 'can not authenticate with the given credentials or the account has been deactivated'}
            return Response(res, status=status.HTTP_403_FORBIDDEN)
        except KeyError:
            res = {'error': 'please provide a email and a password'}

            return Response(res)


class AddBookView(APIView):
    serializer_class = BookSerializer
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)
    def post(self, request: Request, *args, **kwargs):
        data = request.data.copy()
        data['author'] = request.user.id
        serializer = BookSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateUserDataView(APIView):
    serializer_class = UserDetailsSerializer
    authentication_classes = (JWTAuthentication,)
    def get(self, request: Request, *args, **kwargs):
        """
          Retrieve the details of the authenticated user.

          Args:
          - request (Request): The Django request object including in Authorization header(
          'Authorization',Token 'token').

          Returns:
          - Response: The response containing the details of the authenticated user.
        """
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=403)

        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def post(self, request: Request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'Status': False, 'Error': 'Log in required'}, status=403)

        if 'password' in request.data:
            try:
                validate_password(request.data['password'])
            except ValidationError as err:
                err_array = []
                for error in err.messages:
                    err_array.append(error)
                return Response(
                    {'Status': False, 'Error': err_array},
                    status=status.HTTP_403_FORBIDDEN)
        user_serializer = UserDetailsSerializer(request.user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
            return Response(
                {'Status': True, 'Message': 'Account updated successfully'},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'Status': False, 'Errors': user_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    response = Response({'message': 'Logged out successfully'})
    response.delete_cookie('refresh')
    return response