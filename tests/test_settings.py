"""
Property-based tests for the Settings module.

Tests verify that environment variable loading works correctly
across a wide range of valid inputs.
"""

import os
import sys
from unittest.mock import patch

from hypothesis import given
from hypothesis import strategies as st


# Feature: test-database-automation, Property 1: Environment variable loading
# For any set of valid environment variables (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME),
# when the settings module initializes, it should correctly load all values into
# the corresponding settings fields.
# **Validates: Requirements 1.1**
@given(
    db_host=st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",), blacklist_characters="\x00"
        ),
        min_size=1,
        max_size=100,
    ).filter(lambda x: x.strip()),
    db_user=st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",), blacklist_characters="\x00"
        ),
        min_size=1,
        max_size=100,
    ).filter(lambda x: x.strip()),
    db_password=st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",), blacklist_characters="\x00"
        ),
        min_size=1,
        max_size=100,
    ).filter(lambda x: x.strip()),
    db_name=st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",), blacklist_characters="\x00"
        ),
        min_size=1,
        max_size=100,
    ).filter(lambda x: x.strip()),
)
def test_property_environment_variable_loading(db_host, db_user, db_password, db_name):
    """
    Property test: Environment variable loading.

    For any valid set of environment variables, the Settings module should
    correctly load all values into the corresponding fields.
    """
    # Set up environment variables
    env_vars = {
        "DB_HOST": db_host,
        "DB_USER": db_user,
        "DB_PASSWORD": db_password,
        "DB_NAME": db_name,
    }

    with patch.dict(os.environ, env_vars, clear=False):
        # Import Settings class fresh with the patched environment
        # Remove the module from cache to force reimport
        if "trackers.db.settings" in sys.modules:
            del sys.modules["trackers.db.settings"]

        from trackers.db.settings import Settings

        # Create settings instance
        settings_instance = Settings()

        # Verify all values are loaded correctly
        assert settings_instance.db_host == db_host
        assert settings_instance.db_user == db_user
        assert settings_instance.db_password == db_password
        assert settings_instance.db_name == db_name
