from django.conf import settings
from oauthlib.common import UNICODE_ASCII_CHARACTER_SET
from oauthlib.common import generate_client_id as oauthlib_generate_client_id
from oauthlib.oauth2.rfc6749.tokens import random_token_generator as oauth_random_token_generator

from .settings import oauth2_settings


class BaseHashGenerator(object):
    """
    All generators should extend this class overriding `.hash()` method.
    """

    def hash(self):
        raise NotImplementedError()


class ClientIdGenerator(BaseHashGenerator):
    def hash(self):
        """
        Generate a client_id for Basic Authentication scheme without colon char
        as in http://tools.ietf.org/html/rfc2617#section-2
        """
        return oauthlib_generate_client_id(length=40, chars=UNICODE_ASCII_CHARACTER_SET)


class ClientSecretGenerator(BaseHashGenerator):
    def hash(self):
        length = oauth2_settings.CLIENT_SECRET_GENERATOR_LENGTH
        chars = UNICODE_ASCII_CHARACTER_SET
        return oauthlib_generate_client_id(length=length, chars=chars)


def generate_client_id():
    """
    Generate a suitable client id
    """
    client_id_generator = oauth2_settings.CLIENT_ID_GENERATOR_CLASS()
    return client_id_generator.hash()


def generate_client_secret():
    """
    Generate a suitable client secret
    """
    client_secret_generator = oauth2_settings.CLIENT_SECRET_GENERATOR_CLASS()
    return client_secret_generator.hash()


def random_token_generator(request, **kwargs):
    return oauth_random_token_generator(request, kwargs)


def signed_token_generator(request, **kwargs):
    import uuid
    import datetime
    import jwt
    from oauthlib.common import to_unicode

    now = datetime.datetime.utcnow()

    claims = {
        "ref": str(uuid.uuid4()),
        'scope': request.scope,
        'exp': now + datetime.timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS),
        'iat': now
    }

    print(claims)
    print(request.user)

    claims.update(**kwargs)

    token = jwt.encode(claims, settings.SECRET_KEY, 'HS256')
    token = to_unicode(token, "UTF-8")

    return token
