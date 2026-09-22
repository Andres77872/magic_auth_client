"""Package/runtime metadata remains coherent for release builds."""

import re

from magic_auth_client import __version__
from magic_auth_client.constants import DEFAULT_USER_AGENT


def test_release_version_and_default_user_agent():
    # CI bumps the patch digit on every push (scripts/bump_version.py), so assert
    # coherence rather than a literal release number.
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)
    assert DEFAULT_USER_AGENT == f"magic_auth_client/{__version__}"
