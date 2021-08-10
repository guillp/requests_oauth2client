import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple, Type, Union

import requests

from .client import OAuth2Client
from .client_authentication import ClientSecretBasic, ClientSecretPost, PublicApp
from .exceptions import (AuthorizationPending, DeviceAuthorizationError,
                         InvalidDeviceAuthorizationResponse, SlowDown, UnauthorizedClient)
from .token_response import BearerToken


class DeviceAuthorizationResponse:
    """
    A response returned by the device Authorization Endpoint (as defined in RFC8628)
    """

    def __init__(
        self,
        device_code: str,
        user_code: str,
        verification_uri: str,
        verification_uri_complete: Optional[str] = None,
        expires_in: Optional[int] = None,
        expires_at: Optional[datetime] = None,
        interval: Optional[int] = None,
        **kwargs: Any,
    ):
        self.device_code = (device_code,)
        self.user_code = user_code
        self.verification_uri = verification_uri
        self.verification_uri_complete = verification_uri_complete
        self.expires_at: Optional[datetime]
        if expires_at:
            self.expires_at = expires_at
        elif expires_in:
            self.expires_at = datetime.now() + timedelta(seconds=expires_in)
        else:
            self.expires_at = None
        self.interval = interval
        self.other = kwargs

    def is_expired(self) -> Optional[bool]:
        """
        Returns true if the access token is expired at the time of the call.
        :return:
        """
        if self.expires_at:
            return datetime.now() > self.expires_at
        return None


class DeviceAuthorizationClient:
    """
    A client for the Device Authorization Endpoint (RFC8628)
    This client can send requests to a Device Authorization Endpoint
    """

    device_authorization_response_class = DeviceAuthorizationResponse

    exception_classes: Dict[str, Type[Exception]] = {
        "unauthorized_client": UnauthorizedClient,
    }

    default_exception_class = DeviceAuthorizationError

    def __init__(
        self,
        device_authorization_endpoint: str,
        auth: Union[requests.auth.AuthBase, Tuple[str, str], str],
        session: Optional[requests.Session] = None,
        default_auth_handler: Union[
            Type[ClientSecretPost], Type[ClientSecretBasic]
        ] = ClientSecretPost,
    ):
        self.device_authorization_endpoint = device_authorization_endpoint
        self.session = session or requests.Session()
        if isinstance(auth, requests.auth.AuthBase):
            self.auth = auth
        elif isinstance(auth, tuple) and len(auth) == 2:
            client_id, client_secret = auth
            self.auth = default_auth_handler(client_id, client_secret)
        elif isinstance(auth, str):
            client_id = auth
            self.auth = PublicApp(client_id)
        else:
            raise ValueError("An Auth Handler is required")

    def authorize_device(self, **data: Any) -> DeviceAuthorizationResponse:
        """
        Sends a Device Authorization Request.
        :param data: additional data to send to the Device Authorization Endpoint
        :return: a Device Authorization Response
        """
        response = self.session.post(
            self.device_authorization_endpoint, data=data, auth=self.auth
        )

        if response.ok:
            device_authorization_response = self.device_authorization_response_class(
                **response.json()
            )
            return device_authorization_response

        # error handling
        error_json = response.json()
        error = error_json.get("error")
        error_description = error_json.get("error_description")
        error_uri = error_json.get("error_uri")
        if error:
            exception_class = self.exception_classes.get(error, self.default_exception_class)
            raise exception_class(error, error_description, error_uri)

        raise InvalidDeviceAuthorizationResponse(
            "device authorization endpoint returned an HTTP error without an error message",
            error_json,
        )


class DeviceAuthorizationPoolingJob:
    """
    A pooling job for checking if the user has finished with his authorization.

    """

    def __init__(
        self,
        client: OAuth2Client,
        device_code: str,
        interval: Optional[int] = None,
        requests_kwargs: Optional[Dict[str, Any]] = None,
        **token_kwargs: Any,
    ):
        self.client = client
        self.device_code = device_code
        self.interval = interval or 5
        self.requests_kwargs = requests_kwargs
        self.token_kwargs = token_kwargs

    def __call__(self) -> Optional[BearerToken]:
        time.sleep(self.interval)
        try:
            return self.client.device_code(
                self.device_code, requests_kwargs=self.requests_kwargs, **self.token_kwargs
            )
        except SlowDown:
            self.interval += 5
        except AuthorizationPending:
            pass
        return None
