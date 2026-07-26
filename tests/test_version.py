"""Package/runtime metadata remains coherent for release builds."""

from magic_auth_client import __version__
from magic_auth_client.constants import DEFAULT_USER_AGENT


def test_release_version_and_default_user_agent():
    assert __version__ == "0.3.0"
    assert DEFAULT_USER_AGENT == "magic_auth_client/0.3.0"
