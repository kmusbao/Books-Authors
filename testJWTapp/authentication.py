from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed

from testJWTapp.service import JWTManagerService


class JWTAuthentication(BaseAuthentication):
    keyword = 'Bearer'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_model = get_user_model()
        self.service = JWTManagerService()

    def authenticate(self, request):
        auth_header = None
        if hasattr(request, 'headers'):
            auth_header = request.headers.get('Authorization')
        if not auth_header:
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth_header:
            return None

        parts = auth_header.split(' ')
        if len(parts) == 0:
            return None

        token = parts[1]

        try:
            payload = self.service.verify_token(token)
            if payload:
                user_id = payload['user_id']
                try:
                    user = self.user_model.objects.get(pk=user_id)
                except self.user_model.DoesNotExist as exc:
                    raise exceptions.AuthenticationFailed('User not found', code='user_not_found') from exc

                if not getattr(user, 'is_active', True):
                    raise exceptions.AuthenticationFailed('User inactive', code='user_inactive')

                return user, token
        except Exception as exc:
            raise exceptions.AuthenticationFailed('Invalid token: ' + str(exc))


    def authenticate_header(self, request):
        return self.keyword