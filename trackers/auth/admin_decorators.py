"""
Decorators for admin authorization.

This module provides decorators to protect routes and functions that should
only be accessible to admin users.
"""

from functools import wraps

from flask import jsonify, redirect, request, url_for

from trackers.auth.admin import is_admin_user


def require_admin(redirect_to_dashboard=True):
    """
    Decorator to require admin user access for a route.

    NOTE: This decorator should be used AFTER authentication decorators like @require_auth.
    It assumes the user is already authenticated and only checks admin status.

    Args:
        redirect_to_dashboard: If True, redirect non-admin users to dashboard.
                              If False, return 403 Forbidden.

    Returns:
        Decorator function
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user is admin (assumes authentication already verified)
            if not is_admin_user():
                if redirect_to_dashboard:
                    # Redirect to dashboard with error message
                    return redirect(url_for("web.dashboard", error="admin_required"))
                else:
                    # Return 403 Forbidden for API calls
                    if request.is_json:
                        return jsonify(
                            {
                                "error": "Admin access required",
                                "message": "You do not have permission to access this resource",
                            }
                        ), 403
                    else:
                        return "Access Denied: Admin privileges required", 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def admin_required(f):
    """
    Simple admin required decorator that redirects to dashboard.

    This is a convenience decorator equivalent to @require_admin(redirect_to_dashboard=True)
    """
    return require_admin(redirect_to_dashboard=True)(f)


def admin_api_required(f):
    """
    Admin required decorator for API endpoints that returns 403 instead of redirecting.

    This is a convenience decorator equivalent to @require_admin(redirect_to_dashboard=False)
    """
    return require_admin(redirect_to_dashboard=False)(f)
