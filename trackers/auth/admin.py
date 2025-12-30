"""
Admin authorization system for restricting access to administrative features.

This module provides functionality to check if a user is authorized to access
administrative features like the systems page.
"""

import os
from typing import List, Optional

from trackers.auth.context import get_current_user


def get_admin_users() -> List[str]:
    """
    Get the list of admin user emails from environment configuration.

    Returns:
        List of admin user email addresses
    """
    admin_users_env = os.getenv("ADMIN_USERS", "")
    if not admin_users_env:
        return []

    # Split by comma and strip whitespace
    admin_users = [email.strip() for email in admin_users_env.split(",")]
    # Filter out empty strings
    return [email for email in admin_users if email]


def is_admin_user(email: Optional[str] = None) -> bool:
    """
    Check if the current user or specified email is an admin user.

    Args:
        email: Optional email to check. If not provided, uses current user's email.

    Returns:
        True if the user is an admin, False otherwise
    """
    if email is None:
        current_user = get_current_user()
        if not current_user or not current_user.email:
            return False
        email = current_user.email

    admin_users = get_admin_users()
    return email.lower() in [admin_email.lower() for admin_email in admin_users]


def require_admin_user():
    """
    Check if the current user is an admin user and raise an exception if not.

    Raises:
        PermissionError: If the current user is not an admin
    """
    if not is_admin_user():
        current_user = get_current_user()
        user_email = current_user.email if current_user else "unknown"
        raise PermissionError(
            f"Admin access required. User {user_email} is not authorized."
        )


def get_admin_status_info() -> dict:
    """
    Get information about admin configuration for debugging/display purposes.

    Returns:
        Dictionary with admin configuration information
    """
    admin_users = get_admin_users()
    current_user = get_current_user()
    current_email = current_user.email if current_user else None

    return {
        "admin_users_configured": len(admin_users),
        "admin_users": admin_users,  # Only include in development
        "current_user_email": current_email,
        "current_user_is_admin": is_admin_user(),
        "admin_system_enabled": len(admin_users) > 0,
    }
