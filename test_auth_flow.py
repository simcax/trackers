#!/usr/bin/env python3
"""
Test script to debug the authentication flow.
"""

import os
import sys

import requests

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_auth_flow():
    """Test the authentication flow step by step."""
    print("=== Testing Authentication Flow ===")

    # Test environment API key
    env_key = "test-key-1234567890123456"
    print(f"Testing environment API key: {env_key}")

    try:
        response = requests.get(
            "http://localhost:5000/trackers",
            headers={"Authorization": f"Bearer {env_key}"},
            timeout=5,
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")

    except requests.exceptions.ConnectionError:
        print("Could not connect to server")
    except Exception as e:
        print(f"Error: {e}")

    # Test user API key
    user_key = "uk_3PvRjtRYLS67eqFD4Avm8Uhhk7OnGmrQMsQ1yFnLiss"
    print(f"\nTesting user API key: {user_key}")

    try:
        response = requests.get(
            "http://localhost:5000/trackers",
            headers={"Authorization": f"Bearer {user_key}"},
            timeout=5,
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")

    except requests.exceptions.ConnectionError:
        print("Could not connect to server")
    except Exception as e:
        print(f"Error: {e}")

    # Test invalid key
    invalid_key = "invalid-key"
    print(f"\nTesting invalid API key: {invalid_key}")

    try:
        response = requests.get(
            "http://localhost:5000/trackers",
            headers={"Authorization": f"Bearer {invalid_key}"},
            timeout=5,
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")

    except requests.exceptions.ConnectionError:
        print("Could not connect to server")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    test_auth_flow()
