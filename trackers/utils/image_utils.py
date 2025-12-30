"""
Image utility functions for handling profile pictures and avatars.
"""

import base64
from typing import Optional


def get_proxied_image_url(original_url: Optional[str]) -> Optional[str]:
    """
    Convert a Google profile image URL to a proxied URL to avoid rate limiting.

    Args:
        original_url: The original Google profile image URL

    Returns:
        Proxied image URL or None if invalid
    """
    if not original_url:
        return None

    # Validate that it's a Google image URL
    if not original_url.startswith("https://lh3.googleusercontent.com/"):
        return None

    try:
        # Encode the URL for safe transmission
        encoded_url = base64.urlsafe_b64encode(original_url.encode()).decode()
        return f"/images/profile/{encoded_url}"
    except Exception:
        return None


def get_safe_profile_image_url(original_url: Optional[str]) -> Optional[str]:
    """
    Get a profile image URL that's safe to load (respects rate limiting).

    For now, this is a simple pass-through. In the future, this could
    integrate with rate limiting logic.

    Args:
        original_url: The original profile image URL

    Returns:
        Safe image URL or None if we should skip loading
    """
    # For now, just return the original URL
    # TODO: Integrate with rate limiting when needed
    return original_url


def should_use_proxy(original_url: Optional[str]) -> bool:
    """
    Determine if an image URL should be proxied.

    Args:
        original_url: The original image URL

    Returns:
        True if the URL should be proxied
    """
    if not original_url:
        return False

    # Proxy Google images to avoid rate limiting
    return original_url.startswith("https://lh3.googleusercontent.com/")


def get_avatar_initials(name: Optional[str]) -> str:
    """
    Generate initials for avatar fallback.

    Args:
        name: User's full name

    Returns:
        1-2 character initials
    """
    if not name:
        return "U"

    words = name.strip().split()
    if len(words) == 1:
        return words[0][0].upper()
    elif len(words) >= 2:
        return (words[0][0] + words[-1][0]).upper()
    else:
        return "U"
