"""Vendor-specific utilities.

This module contains vendor-specific subclasses of [requests_oauth2client] classes, that make it
easier to work with specific OAuth 2.x providers and/or fix compatibility issues.

"""

from .auth0 import Auth0
from .ping import Ping

__all__ = ["Auth0", "Ping"]
