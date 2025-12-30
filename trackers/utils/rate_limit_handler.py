"""
Rate limit handling utilities for external API calls.

This module provides utilities to handle rate limiting from external services
like Google's image servers, with exponential backoff and graceful degradation.
"""

import time
from typing import Optional
from urllib.parse import urlparse


class RateLimitHandler:
    """Handle rate limiting with exponential backoff."""

    def __init__(self):
        self._last_request_time = {}
        self._failure_count = {}
        self._backoff_until = {}

    def can_make_request(self, domain: str) -> bool:
        """
        Check if we can make a request to the given domain.

        Args:
            domain: The domain to check (e.g., 'lh3.googleusercontent.com')

        Returns:
            True if request can be made, False if we should wait
        """
        current_time = time.time()

        # Check if we're in a backoff period
        if domain in self._backoff_until:
            if current_time < self._backoff_until[domain]:
                return False
            else:
                # Backoff period expired, reset
                del self._backoff_until[domain]
                self._failure_count[domain] = 0

        # Check minimum time between requests (basic rate limiting)
        if domain in self._last_request_time:
            time_since_last = current_time - self._last_request_time[domain]
            min_interval = 1.0  # Minimum 1 second between requests

            if time_since_last < min_interval:
                return False

        return True

    def record_request(self, domain: str, success: bool = True):
        """
        Record the result of a request.

        Args:
            domain: The domain that was requested
            success: Whether the request was successful
        """
        current_time = time.time()
        self._last_request_time[domain] = current_time

        if success:
            # Reset failure count on success
            self._failure_count[domain] = 0
            if domain in self._backoff_until:
                del self._backoff_until[domain]
        else:
            # Increment failure count and set backoff
            failure_count = self._failure_count.get(domain, 0) + 1
            self._failure_count[domain] = failure_count

            # Exponential backoff: 2^failures seconds, max 300 seconds (5 minutes)
            backoff_seconds = min(2**failure_count, 300)
            self._backoff_until[domain] = current_time + backoff_seconds

    def get_backoff_time(self, domain: str) -> Optional[float]:
        """
        Get remaining backoff time for a domain.

        Args:
            domain: The domain to check

        Returns:
            Remaining backoff time in seconds, or None if no backoff
        """
        if domain not in self._backoff_until:
            return None

        remaining = self._backoff_until[domain] - time.time()
        return max(0, remaining)


# Global rate limit handler instance
rate_limiter = RateLimitHandler()


def should_load_image(image_url: Optional[str]) -> bool:
    """
    Determine if we should attempt to load an image URL.

    Args:
        image_url: The image URL to check

    Returns:
        True if we should attempt to load the image
    """
    if not image_url:
        return False

    try:
        parsed = urlparse(image_url)
        domain = parsed.netloc

        # Only apply rate limiting to Google images
        if "googleusercontent.com" in domain:
            return rate_limiter.can_make_request(domain)

        return True

    except Exception:
        return False


def record_image_load_result(image_url: Optional[str], success: bool):
    """
    Record the result of an image load attempt.

    Args:
        image_url: The image URL that was attempted
        success: Whether the load was successful
    """
    if not image_url:
        return

    try:
        parsed = urlparse(image_url)
        domain = parsed.netloc

        if "googleusercontent.com" in domain:
            rate_limiter.record_request(domain, success)

    except Exception:
        pass


def get_safe_image_url(image_url: Optional[str]) -> Optional[str]:
    """
    Get a safe image URL that respects rate limiting.

    Args:
        image_url: The original image URL

    Returns:
        The image URL if safe to load, None if we should skip it
    """
    if should_load_image(image_url):
        return image_url
    return None
