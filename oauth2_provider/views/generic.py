from django.views.generic import View

from ..settings import oauth2_settings
from .mixins import (
    ProtectedResourceMixin, ReadWriteScopedResourceMixin, ScopedResourceMixin
)


class ProtectedResourceView(ProtectedResourceMixin, View):
    """
    Generic view protecting resources by providing OAuth2 authentication out of the box
    """
    server_class = oauth2_settings.OAUTH2_SERVER_CLASS
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    access_token_generator = oauth2_settings.OAUTH2_ACCESS_TOKEN_GENERATOR
    refresh_token_generator = oauth2_settings.OAUTH2_REFRESH_TOKEN_GENERATOR
    oauthlib_backend_class = oauth2_settings.OAUTH2_BACKEND_CLASS


class ScopedProtectedResourceView(ScopedResourceMixin, ProtectedResourceView):
    """
    Generic view protecting resources by providing OAuth2 authentication and Scopes handling
    out of the box
    """
    pass


class ReadWriteScopedResourceView(ReadWriteScopedResourceMixin, ProtectedResourceView):
    """
    Generic view protecting resources with OAuth2 authentication and read/write scopes.
    GET, HEAD, OPTIONS http methods require "read" scope. Otherwise "write" scope is required.
    """
    pass
