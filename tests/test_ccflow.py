import os

from ccflow import CCFlowAuth
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
TOKEN_ENDPOINT = os.environ["TOKEN_ENDPOINT"]


def test_token_fetch():
    my_auth = CCFlowAuth(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        token_endpoint=TOKEN_ENDPOINT
    )
    assert my_auth.token is not None