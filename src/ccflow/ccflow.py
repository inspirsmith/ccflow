"""A module for OAuth2 token handling."""
import datetime
import logging
from typing import Final, TypedDict

import requests

logger = logging.getLogger(__name__)

LATENCY_GUARD_SECONDS: Final = 60.0


class TokenDict(TypedDict):
    """Improve type safety of token dictionary returned from authorization token end point."""

    access_token: str
    expires_at: datetime.datetime
    expires_in: str
    ext_expires_in: str
    token_type: str


class CCFlowAuth(requests.auth.AuthBase):  # type: ignore
    """Encapsulates OAuth2 protocol handling using requests authorization class hierarchy.

    The OAuth2Handler manages all aspects of OAuth2 authentication as part of a requests based
    API client workflow.  After instantiating an instance of the class all that is required is
    inserting the resulting object in the auth parameter of requests HTTP calls.

    Usage:
        my_auth = OAuth2Handler(actual_client_id, actual_client_secret, actual_token_endpoint)
        response = requests.get(actual_api_endpoint, ..., auth=my_auth)

    """

    def __init__(self, client_id: str, client_secret: str, token_endpoint: str):
        """Class handles all operations associated with client ID/Secret protocol."""
        self.client_id, self.client_secret = client_id, client_secret
        self.token_endpoint = token_endpoint
        self.token: TokenDict = self._fetch_token()

    def _fetch_token(self) -> TokenDict:
        """Get new token from issuing server.

        A token is needed at startup and when the current token expires. This helper
        function acquires a new token from endpoint when called by member functions.

        """
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        token_response = requests.post(self.token_endpoint, data=data, allow_redirects=False)
        token_response.raise_for_status()
        token: TokenDict = token_response.json()
        # Current time and token duration enables creation of an "expires at" field
        token["expires_at"] = datetime.datetime.now() + datetime.timedelta(
            seconds=float(token["expires_in"]) - LATENCY_GUARD_SECONDS
        )
        return token

    def __call__(self, prepared_request: requests.PreparedRequest) -> requests.PreparedRequest:
        """Needs to be callable to support use in auth parameter of request."""
        # Automatically handle token expiration by fetching new token as needed.
        if datetime.datetime.now() > self.token["expires_at"]:
            self.token = self._fetch_token()

        prepared_request.headers[
            "Authorization"
        ] = f'{self.token["token_type"]} {self.token["access_token"]}'

        return prepared_request
