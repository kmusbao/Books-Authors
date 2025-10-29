import jwt
import datetime
from .models import User
from protectedservice.settings import SECRET_KEY

class JWTManagerService:
    def __init__(self):
        self.secret_key = SECRET_KEY
        self.algorithm = 'HS256'

    def create_token(self, user, token_type):
        payload = {
            'user_id': user.id,
            'type': token_type,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
            'iat': datetime.datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def verify_token(self, token):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            raise Exception('Signature expired. Please log in again.')
        except jwt.InvalidTokenError:
            raise Exception('Invalid token. Please log in again.')






