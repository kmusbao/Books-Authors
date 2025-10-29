from functools import wraps

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from .service import JWTManagerService

def protected_decorator(func):
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        auth_headers = request.headers.get('Authorization')
        if not auth_headers or not auth_headers.startswith('Bearer'):
            return Response("No token provided")
        token = auth_headers.split(' ', 1)[1].strip()
        service = JWTManagerService()
        try:
            payload = service.verify_token(token)
        except Exception as e:
            return Response({'detail': f'Invalid token: {str(e)}'}, status=status.HTTP_401_UNAUTHORIZED)
        user_id = payload.get('user_id')
        if not user_id:
            return Response({'detail': 'user_id missing in token'}, status=status.HTTP_401_UNAUTHORIZED)

        # Подставим реального пользователя в request.user
        User = get_user_model()
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)

        request.user = user

        return func(request, *args, **kwargs)
    return wrapper

