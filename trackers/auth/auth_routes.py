"""
Flask routes for Google OAuth authentication.

This module provides Flask blueprint with authentication endpoints including
login, callback, and logout routes with comprehensive error handling and
HTTPS enforcement.

Requirements: 2.1, 3.2, 6.3, 7.1, 7.2, 7.4, 8.1
"""

import os
from functools import wraps
from typing import Optional
from urllib.parse import urlparse

from flask import Blueprint, flash, jsonify, redirect, render_template, request

from .auth_service import GoogleAuthService
from .config import GoogleOAuthConfig
from .error_handling import (
    AuthError,
    RateLimitError,
    auth_logger,
    create_error_response,
    get_client_ip,
)

# Create authentication blueprint
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# Global auth service instance (will be initialized by app factory)
auth_service: Optional[GoogleAuthService] = None


# Allowlist of safe redirect paths for preventing open redirect vulnerabilities
ALLOWED_REDIRECT_PATHS = {
    "/",
    "/web/",
    "/web/dashboard",
    "/web/systems",
    "/web/learn-more",
    "/web/test",
    "/auth/login",
    "/health",
    "/health/detailed",
    "/health/ready",
    "/health/live",
}


def validate_redirect_url(url: Optional[str]) -> str:
    """
    Validate and sanitize redirect URL to prevent open redirect vulnerabilities.

    This function implements an allowlist approach to ensure redirects only go to
    safe, application-controlled endpoints.

    Args:
        url: The URL to validate (can be None)

    Returns:
        str: A safe redirect URL (defaults to "/" if invalid)

    Security:
        - Only allows relative URLs (no external redirects)
        - Uses allowlist of known safe paths
        - Prevents open redirect attacks
        - Logs suspicious redirect attempts
    """
    # Default safe redirect
    default_redirect = "/"

    if not url:
        return default_redirect

    try:
        # Parse the URL
        parsed = urlparse(url)

        # Only allow relative URLs (no scheme, no netloc)
        if parsed.scheme or parsed.netloc:
            try:
                client_ip = get_client_ip()
            except RuntimeError:
                # Outside request context (e.g., in tests)
                client_ip = "unknown"

            auth_logger.log_authentication_failure(
                client_ip,
                f"Attempted redirect to external URL: {url}",
                "suspicious_redirect_attempt",
            )
            return default_redirect

        # Extract the path component
        path = parsed.path or "/"

        # Normalize path (remove trailing slash except for root)
        # But first check if the original path with trailing slash is in allowlist
        original_path = path
        normalized_path = path.rstrip("/") if path != "/" else path

        # Check both original and normalized paths against allowlist
        if (
            original_path in ALLOWED_REDIRECT_PATHS
            or normalized_path in ALLOWED_REDIRECT_PATHS
        ):
            # Use the original path if it's in allowlist, otherwise use normalized
            final_path = (
                original_path
                if original_path in ALLOWED_REDIRECT_PATHS
                else normalized_path
            )
            # Include query parameters if they exist (they're generally safe for internal URLs)
            if parsed.query:
                return f"{final_path}?{parsed.query}"
            return final_path
        else:
            try:
                client_ip = get_client_ip()
            except RuntimeError:
                # Outside request context (e.g., in tests)
                client_ip = "unknown"

            auth_logger.log_authentication_failure(
                client_ip,
                f"Blocked redirect to non-allowlisted path: {original_path} (normalized: {normalized_path})",
                "blocked_redirect_attempt",
            )
            return default_redirect

    except Exception as e:
        try:
            client_ip = get_client_ip()
        except RuntimeError:
            # Outside request context (e.g., in tests)
            client_ip = "unknown"

        auth_logger.log_authentication_failure(
            client_ip,
            f"Error validating redirect URL '{url}': {str(e)}",
            "redirect_validation_error",
        )
        return default_redirect


def require_https(f):
    """
    Decorator to enforce HTTPS for OAuth endpoints in production.

    Requirements: 8.1 - Implement HTTPS enforcement for OAuth endpoints
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check environment and request scheme
        environment = os.getenv("FLASK_ENV", "development")
        is_production = environment == "production"
        is_secure = (
            request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
        )

        # Enforce HTTPS in production
        if is_production and not is_secure:
            auth_logger.logger.warning(
                f"HTTPS required for OAuth endpoint {request.endpoint} in production. "
                f"Request from {get_client_ip()} using {request.scheme}"
            )

            # Redirect to HTTPS version
            if request.method == "GET":
                https_url = request.url.replace("http://", "https://", 1)
                # Validate the HTTPS URL to prevent open redirects
                safe_https_url = validate_redirect_url(https_url)
                return redirect(safe_https_url, code=301)
            else:
                # For non-GET requests, return error
                error_msg = "HTTPS is required for OAuth authentication in production"
                if request.accept_mimetypes.accept_html:
                    flash(error_msg, "error")
                    return render_template("auth/error.html", error=error_msg), 400
                else:
                    return jsonify({"error": {"message": error_msg}}), 400

        # Log security warning for HTTP in development
        if not is_production and not is_secure:
            auth_logger.logger.debug(
                f"OAuth endpoint {request.endpoint} accessed over HTTP in {environment} environment"
            )

        return f(*args, **kwargs)

    return decorated_function


def init_auth_routes(config: GoogleOAuthConfig) -> Blueprint:
    """
    Initialize authentication routes with configuration.

    Args:
        config: Google OAuth configuration

    Returns:
        Blueprint: Configured authentication blueprint
    """
    global auth_service
    auth_service = GoogleAuthService(config)
    return auth_bp


@auth_bp.route("/login")
@require_https
def login():
    """
    Display main login page with both authentication options.

    Requirements: 5.2 - Display both Google OAuth and email/password login options
    """
    # Display main login page with both authentication options
    redirect_after_login = request.args.get("redirect")
    response = render_template(
        "auth/main_login.html", redirect_url=redirect_after_login
    )
    return response


@auth_bp.route("/google/login")
@require_https
def google_login():
    """
    Initiate Google OAuth login flow.

    Requirements: 2.1 - Redirect to Google's authorization endpoint
    """
    if not auth_service:
        return jsonify({"error": "Authentication service not configured"}), 500

    client_ip = get_client_ip()

    try:
        # Get redirect URL from query parameters
        redirect_after_login = request.args.get("redirect")

        # Initiate login flow
        auth_redirect = auth_service.initiate_login(redirect_after_login)

        auth_logger.log_oauth_initiation(client_ip, redirect_after_login)

        # OAuth authorization URLs are safe by design - no validation needed
        # The validate_redirect_url function is only for user-provided redirects
        return redirect(auth_redirect.url)

    except RateLimitError as e:
        auth_logger.log_rate_limit_violation(
            client_ip, 0
        )  # Count will be tracked by rate limiter
        response, status_code = create_error_response(e)

        # For web requests, show user-friendly error page
        if request.accept_mimetypes.accept_html:
            flash(e.user_message, "error")
            return render_template(
                "auth/error.html",
                error=e.user_message,
                retry_after=e.details.get("retry_after_seconds"),
            ), status_code
        else:
            return jsonify(response), status_code

    except AuthError as e:
        auth_logger.log_authentication_failure(client_ip, str(e), e.error_code)
        response, status_code = create_error_response(e)

        # For web requests, show user-friendly error page
        if request.accept_mimetypes.accept_html:
            flash(e.user_message, "error")
            return render_template("auth/error.html", error=e.user_message), status_code
        else:
            return jsonify(response), status_code

    except Exception as e:
        auth_logger.log_authentication_failure(client_ip, str(e), "unexpected_error")

        error_msg = "An unexpected error occurred. Please try again."
        if request.accept_mimetypes.accept_html:
            flash(error_msg, "error")
            return render_template("auth/error.html", error=error_msg), 500
        else:
            return jsonify({"error": {"message": error_msg}}), 500


@auth_bp.route("/google/callback")
@require_https
def callback():
    """
    Handle OAuth callback from Google.

    Requirements: 3.2 - Process OAuth callback and exchange code for tokens
    """
    if not auth_service:
        return jsonify({"error": "Authentication service not configured"}), 500

    client_ip = get_client_ip()

    try:
        # Extract OAuth parameters from callback
        code = request.args.get("code")
        state = request.args.get("state")
        error = request.args.get("error")

        # Process the callback
        auth_result = auth_service.process_callback(code, state, error)

        if auth_result.success:
            # Successful authentication
            auth_logger.log_authentication_success(
                auth_result.user_info.email, client_ip
            )

            # For web requests, show success message and redirect
            if request.accept_mimetypes.accept_html:
                flash(f"Welcome, {auth_result.user_info.name}!", "success")
                safe_redirect_url = validate_redirect_url(auth_result.redirect_url)
                return redirect(safe_redirect_url)
            else:
                return jsonify(
                    {
                        "success": True,
                        "user": {
                            "email": auth_result.user_info.email,
                            "name": auth_result.user_info.name,
                            "google_id": auth_result.user_info.google_id,
                        },
                        "redirect_url": validate_redirect_url(auth_result.redirect_url),
                    }
                )
        else:
            # Authentication failed
            auth_logger.log_authentication_failure(
                client_ip, auth_result.error_message, "callback_processing_failed"
            )

            # For web requests, show error and redirect
            if request.accept_mimetypes.accept_html:
                flash(auth_result.error_message, "error")
                safe_redirect_url = (
                    validate_redirect_url(auth_result.redirect_url)
                    if auth_result.redirect_url
                    else "/auth/login"
                )
                return redirect(safe_redirect_url)
            else:
                return jsonify(
                    {
                        "success": False,
                        "error": auth_result.error_message,
                        "redirect_url": validate_redirect_url(auth_result.redirect_url),
                    }
                ), 400

    except RateLimitError as e:
        auth_logger.log_rate_limit_violation(client_ip, 0)
        response, status_code = create_error_response(e)

        if request.accept_mimetypes.accept_html:
            flash(e.user_message, "error")
            return render_template(
                "auth/error.html",
                error=e.user_message,
                retry_after=e.details.get("retry_after_seconds"),
            ), status_code
        else:
            return jsonify(response), status_code

    except AuthError as e:
        auth_logger.log_authentication_failure(client_ip, str(e), e.error_code)
        response, status_code = create_error_response(e)

        if request.accept_mimetypes.accept_html:
            flash(e.user_message, "error")
            return render_template("auth/error.html", error=e.user_message), status_code
        else:
            return jsonify(response), status_code

    except Exception as e:
        auth_logger.log_authentication_failure(
            client_ip, str(e), "unexpected_callback_error"
        )

        error_msg = (
            "An unexpected error occurred during authentication. Please try again."
        )
        if request.accept_mimetypes.accept_html:
            flash(error_msg, "error")
            return render_template("auth/error.html", error=error_msg), 500
        else:
            return jsonify({"error": {"message": error_msg}}), 500


@auth_bp.route("/logout")
@require_https
def logout():
    """
    Log out the current user.

    Requirements: 6.3 - Implement logout functionality with session cleanup
    """
    if not auth_service:
        return jsonify({"error": "Authentication service not configured"}), 500

    client_ip = get_client_ip()

    try:
        # Get current user for logging
        current_user = auth_service.get_current_user()
        user_email = current_user.email if current_user else "unknown"

        # Check if we should redirect to Google logout
        redirect_to_google = request.args.get("google_logout", "").lower() == "true"

        # Perform logout
        logout_redirect_url = auth_service.logout(redirect_to_google)

        auth_logger.log_logout(user_email, client_ip)

        # For web requests, show logout message and redirect
        if request.accept_mimetypes.accept_html:
            if not redirect_to_google:
                flash("You have been logged out successfully.", "info")
            safe_logout_url = validate_redirect_url(logout_redirect_url)
            return redirect(safe_logout_url)
        else:
            return jsonify(
                {
                    "success": True,
                    "message": "Logged out successfully",
                    "redirect_url": validate_redirect_url(logout_redirect_url),
                }
            )

    except Exception as e:
        auth_logger.logger.error(f"Error during logout: {str(e)}")

        # Even if logout fails, try to clear session and redirect
        try:
            auth_service.session_manager.clear_session()
        except Exception:
            pass

        error_msg = "Logout completed, but there may have been an issue clearing all session data."
        if request.accept_mimetypes.accept_html:
            flash(error_msg, "warning")
            return redirect("/")
        else:
            return jsonify({"success": True, "message": error_msg, "redirect_url": "/"})


@auth_bp.route("/status")
def status():
    """
    Get current authentication status.

    Returns:
        JSON response with authentication status and user information
    """
    if not auth_service:
        return jsonify({"error": "Authentication service not configured"}), 500

    try:
        is_authenticated = auth_service.is_authenticated()
        current_user = auth_service.get_current_user()
        session_info = auth_service.get_session_info()

        response = {"authenticated": is_authenticated, "session_info": session_info}

        if is_authenticated and current_user:
            response["user"] = {
                "email": current_user.email,
                "name": current_user.name,
                "google_id": current_user.google_id,
                "picture_url": current_user.picture_url,
                "verified_email": current_user.verified_email,
            }

        return jsonify(response)

    except Exception as e:
        auth_logger.logger.error(f"Error getting auth status: {str(e)}")
        return jsonify({"error": "Unable to get authentication status"}), 500


@auth_bp.route("/refresh")
def refresh():
    """
    Refresh the current authentication session.

    Returns:
        JSON response indicating whether session was refreshed
    """
    if not auth_service:
        return jsonify({"error": "Authentication service not configured"}), 500

    try:
        refreshed = auth_service.refresh_authentication()

        return jsonify(
            {
                "success": refreshed,
                "message": "Session refreshed"
                if refreshed
                else "Session could not be refreshed",
            }
        )

    except Exception as e:
        auth_logger.logger.error(f"Error refreshing session: {str(e)}")
        return jsonify({"error": "Unable to refresh session"}), 500


@auth_bp.errorhandler(AuthError)
def handle_auth_error(error: AuthError):
    """Handle authentication errors in the blueprint."""
    client_ip = get_client_ip()
    auth_logger.log_authentication_failure(client_ip, str(error), error.error_code)

    response, status_code = create_error_response(error)

    if request.accept_mimetypes.accept_html:
        flash(error.user_message, "error")
        return render_template("auth/error.html", error=error.user_message), status_code
    else:
        return jsonify(response), status_code


@auth_bp.errorhandler(RateLimitError)
def handle_rate_limit_error(error: RateLimitError):
    """Handle rate limiting errors in the blueprint."""
    client_ip = get_client_ip()
    auth_logger.log_rate_limit_violation(client_ip, 0)

    response, status_code = create_error_response(error)

    if request.accept_mimetypes.accept_html:
        flash(error.user_message, "error")
        return render_template(
            "auth/error.html",
            error=error.user_message,
            retry_after=error.details.get("retry_after_seconds"),
        ), status_code
    else:
        return jsonify(response), status_code
