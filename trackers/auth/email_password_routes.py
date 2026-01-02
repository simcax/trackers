"""
Flask routes for email/password authentication.

This module provides Flask blueprint with email/password authentication endpoints
including registration, login, and password change routes with comprehensive
error handling and HTTPS enforcement.

Requirements: 5.2, 5.3, 5.4, 5.5
"""

import os
from functools import wraps
from typing import Optional
from urllib.parse import urlparse

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session

from .email_password_auth_service import (
    EmailPasswordAuthService,
)
from .error_handling import (
    AccountLockedError,
    AuthError,
    DuplicateEmailError,
    EmailPasswordAuthError,
    EmailPasswordRateLimitError,
    InvalidCredentialsError,
    PasswordValidationError,
    auth_logger,
    create_error_response,
    create_secure_email_password_error_response,
    get_client_ip,
)

# Create email/password authentication blueprint
email_password_bp = Blueprint("email_password", __name__, url_prefix="/auth")

# Global auth service instance (will be initialized by app factory)
email_password_service: Optional[EmailPasswordAuthService] = None


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
    Decorator to enforce HTTPS for authentication endpoints in production.

    Requirements: 5.5 - Add HTTPS enforcement and security headers
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
                f"HTTPS required for authentication endpoint {request.endpoint} in production. "
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
                error_msg = "HTTPS is required for authentication in production"
                if request.accept_mimetypes.accept_html:
                    flash(error_msg, "error")
                    return render_template("auth/error.html", error=error_msg), 400
                else:
                    return jsonify({"error": {"message": error_msg}}), 400

        # Log security warning for HTTP in development
        if not is_production and not is_secure:
            auth_logger.logger.debug(
                f"Authentication endpoint {request.endpoint} accessed over HTTP in {environment} environment"
            )

        return f(*args, **kwargs)

    return decorated_function


def add_security_headers(response):
    """
    Add security headers to authentication responses.

    Requirements: 5.5 - Add HTTPS enforcement and security headers
    """
    from flask import make_response

    # If response is a string (from render_template), convert to Response object
    if isinstance(response, str):
        response = make_response(response)

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Enable XSS protection
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Referrer policy for privacy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Content Security Policy for forms
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "form-action 'self';"
    )

    return response


def init_email_password_routes(service: EmailPasswordAuthService) -> Blueprint:
    """
    Initialize email/password authentication routes with service.

    Args:
        service: EmailPasswordAuthService instance

    Returns:
        Blueprint: Configured authentication blueprint
    """
    global email_password_service
    email_password_service = service
    return email_password_bp


@email_password_bp.route("/register", methods=["GET", "POST"])
@require_https
def register():
    """
    User registration with email/password.

    GET: Display registration form
    POST: Process registration form submission

    Requirements: 5.2 - Create email/password registration route and form handling
    """
    if not email_password_service:
        return jsonify({"error": "Authentication service not configured"}), 500

    client_ip = get_client_ip()

    if request.method == "GET":
        # Display registration form
        redirect_after_login = request.args.get("redirect")
        response = render_template(
            "auth/register.html", redirect_url=redirect_after_login
        )
        return add_security_headers(response)

    # POST: Process registration
    try:
        # Extract form data
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        name = request.form.get("name", "").strip()
        redirect_url = request.form.get("redirect_url", "")

        # Basic validation
        if not email:
            raise EmailPasswordAuthError(
                "Email is required",
                error_code="missing_email",
                user_message="Please enter your email address.",
            )

        if not password:
            raise EmailPasswordAuthError(
                "Password is required",
                error_code="missing_password",
                user_message="Please enter a password.",
            )

        if not name:
            raise EmailPasswordAuthError(
                "Name is required",
                error_code="missing_name",
                user_message="Please enter your name.",
            )

        if password != confirm_password:
            raise EmailPasswordAuthError(
                "Passwords do not match",
                error_code="password_mismatch",
                user_message="Passwords do not match. Please try again.",
            )

        # Attempt registration
        auth_result = email_password_service.register_user(email, password, name)

        if auth_result.success:
            # Successful registration
            auth_logger.log_authentication_success(
                auth_result.user_info.email, client_ip
            )

            # For web requests, show success message and redirect
            if request.accept_mimetypes.accept_html:
                flash(
                    f"Welcome, {auth_result.user_info.name}! Your account has been created.",
                    "success",
                )
                safe_redirect_url = validate_redirect_url(
                    redirect_url or auth_result.redirect_url
                )
                response = redirect(safe_redirect_url)
                return add_security_headers(response)
            else:
                return jsonify(
                    {
                        "success": True,
                        "user": {
                            "email": auth_result.user_info.email,
                            "name": auth_result.user_info.name,
                        },
                        "redirect_url": validate_redirect_url(
                            redirect_url or auth_result.redirect_url
                        ),
                    }
                )
        else:
            # Registration failed
            error_msg = auth_result.error_message or "Registration failed"
            if request.accept_mimetypes.accept_html:
                flash(error_msg, "error")
                response = render_template(
                    "auth/register.html",
                    email=email,
                    name=name,
                    redirect_url=redirect_url,
                )
                return add_security_headers(response), 400
            else:
                return jsonify(
                    {
                        "success": False,
                        "error": error_msg,
                    }
                ), 400

    except EmailPasswordRateLimitError as e:
        auth_logger.log_email_password_rate_limit(
            client_ip,
            e.details.get("attempt_type", "registration"),
            0,
            e.details.get("retry_after_seconds", 0),
        )
        response_data, status_code = create_secure_email_password_error_response(e)

        if request.accept_mimetypes.accept_html:
            flash(e.user_message, "error")
            response = render_template(
                "auth/error.html",
                error=e.user_message,
                retry_after=e.details.get("retry_after_seconds"),
            )
            return add_security_headers(response), status_code
        else:
            return jsonify(response_data), status_code

    except (
        PasswordValidationError,
        DuplicateEmailError,
        EmailPasswordAuthError,
    ) as e:
        # Use secure error response that doesn't reveal user existence
        response_data, status_code = create_secure_email_password_error_response(e)

        if request.accept_mimetypes.accept_html:
            # For HTML responses, show the secure user message
            flash(response_data["error"]["message"], "error")
            response = render_template(
                "auth/register.html", email=email, name=name, redirect_url=redirect_url
            )
            return add_security_headers(response), status_code
        else:
            return jsonify(response_data), status_code

    except Exception as e:
        auth_logger.log_authentication_failure(client_ip, str(e), "unexpected_error")

        error_msg = (
            "An unexpected error occurred during registration. Please try again."
        )
        if request.accept_mimetypes.accept_html:
            flash(error_msg, "error")
            response = render_template("auth/error.html", error=error_msg)
            return add_security_headers(response), 500
        else:
            return jsonify({"error": {"message": error_msg}}), 500


@email_password_bp.route("/login/email", methods=["GET", "POST"])
@require_https
def email_login():
    """
    Email/password login.

    GET: Display login form
    POST: Process login form submission

    Requirements: 5.3 - Create email/password login route with credential validation
    """
    if not email_password_service:
        return jsonify({"error": "Authentication service not configured"}), 500

    client_ip = get_client_ip()

    if request.method == "GET":
        # Display login form
        redirect_after_login = request.args.get("redirect")
        response = render_template("auth/login.html", redirect_url=redirect_after_login)
        return add_security_headers(response)

    # POST: Process login
    try:
        # Extract form data
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        redirect_url = request.form.get("redirect_url", "")

        # Basic validation
        if not email:
            raise InvalidCredentialsError("Please enter your email address.")

        if not password:
            raise InvalidCredentialsError("Please enter your password.")

        # Attempt authentication
        auth_result = email_password_service.authenticate_user(email, password)

        if auth_result.success:
            # Successful authentication
            auth_logger.log_authentication_success(
                auth_result.user_info.email, client_ip
            )

            # For web requests, show success message and redirect
            if request.accept_mimetypes.accept_html:
                flash(f"Welcome back, {auth_result.user_info.name}!", "success")
                safe_redirect_url = validate_redirect_url(
                    redirect_url or auth_result.redirect_url
                )
                response = redirect(safe_redirect_url)
                return add_security_headers(response)
            else:
                return jsonify(
                    {
                        "success": True,
                        "user": {
                            "email": auth_result.user_info.email,
                            "name": auth_result.user_info.name,
                        },
                        "redirect_url": validate_redirect_url(
                            redirect_url or auth_result.redirect_url
                        ),
                    }
                )
        else:
            # Authentication failed
            error_msg = auth_result.error_message or "Authentication failed"
            if request.accept_mimetypes.accept_html:
                flash(error_msg, "error")
                response = render_template(
                    "auth/login.html", email=email, redirect_url=redirect_url
                )
                return add_security_headers(response), 400
            else:
                return jsonify(
                    {
                        "success": False,
                        "error": error_msg,
                    }
                ), 400

    except EmailPasswordRateLimitError as e:
        auth_logger.log_email_password_rate_limit(
            client_ip,
            e.details.get("attempt_type", "login"),
            0,
            e.details.get("retry_after_seconds", 0),
        )
        response_data, status_code = create_secure_email_password_error_response(e)

        if request.accept_mimetypes.accept_html:
            flash(e.user_message, "error")
            response = render_template(
                "auth/error.html",
                error=e.user_message,
                retry_after=e.details.get("retry_after_seconds"),
            )
            return add_security_headers(response), status_code
        else:
            return jsonify(response_data), status_code

    except (
        InvalidCredentialsError,
        AccountLockedError,
        EmailPasswordAuthError,
    ) as e:
        # Use secure error response that doesn't reveal user existence
        response_data, status_code = create_secure_email_password_error_response(e)

        if request.accept_mimetypes.accept_html:
            # For HTML responses, show the secure user message
            flash(response_data["error"]["message"], "error")
            response = render_template(
                "auth/login.html", email=email, redirect_url=redirect_url
            )
            return add_security_headers(response), status_code
        else:
            return jsonify(response_data), status_code

    except Exception as e:
        auth_logger.log_authentication_failure(client_ip, str(e), "unexpected_error")

        error_msg = "An unexpected error occurred during login. Please try again."
        if request.accept_mimetypes.accept_html:
            flash(error_msg, "error")
            response = render_template("auth/error.html", error=error_msg)
            return add_security_headers(response), 500
        else:
            return jsonify({"error": {"message": error_msg}}), 500


@email_password_bp.route("/password/change", methods=["GET", "POST"])
@require_https
def change_password():
    """
    Change password for authenticated users.

    GET: Display password change form
    POST: Process password change form submission

    Requirements: 5.4 - Create password change route for authenticated users
    """
    if not email_password_service:
        return jsonify({"error": "Authentication service not configured"}), 500

    # Check if user is authenticated
    if not email_password_service.is_authenticated():
        # Store current URL for post-login redirect
        session["post_login_redirect"] = request.url

        if request.accept_mimetypes.accept_html:
            flash("Please log in to change your password.", "info")
            return redirect("/auth/login/email")
        else:
            return jsonify({"error": "Authentication required"}), 401

    client_ip = get_client_ip()
    current_user = email_password_service.get_current_user()

    if request.method == "GET":
        # Display password change form
        response = render_template("auth/change_password.html")
        return add_security_headers(response)

    # POST: Process password change
    try:
        # Extract form data
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Basic validation
        if not current_password:
            raise EmailPasswordAuthError(
                "Current password is required",
                error_code="missing_current_password",
                user_message="Please enter your current password.",
            )

        if not new_password:
            raise EmailPasswordAuthError(
                "New password is required",
                error_code="missing_new_password",
                user_message="Please enter a new password.",
            )

        if new_password != confirm_password:
            raise EmailPasswordAuthError(
                "Passwords do not match",
                error_code="password_mismatch",
                user_message="New passwords do not match. Please try again.",
            )

        # Get user ID from session/database
        # We need to get the user ID from the database using the email
        from trackers.db.database import get_db_session
        from trackers.services.user_service import UserService

        with get_db_session() as db:
            user_service = UserService(db)
            user = user_service.get_user_by_email(current_user.email)

            if not user:
                raise EmailPasswordAuthError(
                    "User not found",
                    error_code="user_not_found",
                    user_message="Unable to find your account. Please log in again.",
                )

            # Attempt password change
            success = email_password_service.change_password(
                user.id, current_password, new_password
            )

            if success:
                # Password changed successfully
                auth_logger.log_security_event(
                    "password_change",
                    f"Password changed for user {current_user.email}",
                    client_ip,
                )

                if request.accept_mimetypes.accept_html:
                    flash("Your password has been changed successfully.", "success")
                    response = redirect("/profile/")
                    return add_security_headers(response)
                else:
                    return jsonify(
                        {
                            "success": True,
                            "message": "Password changed successfully",
                        }
                    )
            else:
                # Password change failed
                error_msg = "Failed to change password. Please try again."
                if request.accept_mimetypes.accept_html:
                    flash(error_msg, "error")
                    response = render_template("auth/change_password.html")
                    return add_security_headers(response), 400
                else:
                    return jsonify(
                        {
                            "success": False,
                            "error": error_msg,
                        }
                    ), 400

    except EmailPasswordRateLimitError as e:
        auth_logger.log_email_password_rate_limit(
            client_ip,
            e.details.get("attempt_type", "password_change"),
            0,
            e.details.get("retry_after_seconds", 0),
        )
        response_data, status_code = create_secure_email_password_error_response(e)

        if request.accept_mimetypes.accept_html:
            flash(e.user_message, "error")
            response = render_template("auth/change_password.html")
            return add_security_headers(response), status_code
        else:
            return jsonify(response_data), status_code

    except (
        InvalidCredentialsError,
        PasswordValidationError,
        EmailPasswordAuthError,
    ) as e:
        # Use secure error response
        response_data, status_code = create_secure_email_password_error_response(e)

        if request.accept_mimetypes.accept_html:
            flash(response_data["error"]["message"], "error")
            response = render_template("auth/change_password.html")
            return add_security_headers(response), status_code
        else:
            return jsonify(response_data), status_code

    except Exception as e:
        auth_logger.log_authentication_failure(client_ip, str(e), "unexpected_error")

        error_msg = "An unexpected error occurred while changing your password. Please try again."
        if request.accept_mimetypes.accept_html:
            flash(error_msg, "error")
            response = render_template("auth/error.html", error=error_msg)
            return add_security_headers(response), 500
        else:
            return jsonify({"error": {"message": error_msg}}), 500


@email_password_bp.errorhandler(EmailPasswordAuthError)
def handle_email_password_auth_error(error: EmailPasswordAuthError):
    """Handle email/password authentication errors in the blueprint with secure responses."""
    client_ip = get_client_ip()

    # Use secure error response that doesn't reveal user existence
    response_data, status_code = create_secure_email_password_error_response(error)

    if request.accept_mimetypes.accept_html:
        flash(response_data["error"]["message"], "error")
        response = render_template(
            "auth/error.html", error=response_data["error"]["message"]
        )
        return add_security_headers(response), status_code
    else:
        return jsonify(response_data), status_code


@email_password_bp.errorhandler(EmailPasswordRateLimitError)
def handle_email_password_rate_limit_error(error: EmailPasswordRateLimitError):
    """Handle email/password rate limiting errors in the blueprint."""
    client_ip = get_client_ip()
    auth_logger.log_email_password_rate_limit(
        client_ip,
        error.details.get("attempt_type", "unknown"),
        0,
        error.details.get("retry_after_seconds", 0),
    )

    response_data, status_code = create_secure_email_password_error_response(error)

    if request.accept_mimetypes.accept_html:
        flash(error.user_message, "error")
        response = render_template(
            "auth/error.html",
            error=error.user_message,
            retry_after=error.details.get("retry_after_seconds"),
        )
        return add_security_headers(response), status_code
    else:
        return jsonify(response_data), status_code


@email_password_bp.errorhandler(AuthError)
def handle_auth_error(error: AuthError):
    """Handle general authentication errors in the blueprint."""
    client_ip = get_client_ip()
    auth_logger.log_authentication_failure(client_ip, str(error), error.error_code)

    response_data, status_code = create_error_response(error)

    if request.accept_mimetypes.accept_html:
        flash(error.user_message, "error")
        response = render_template("auth/error.html", error=error.user_message)
        return add_security_headers(response), status_code
    else:
        return jsonify(response_data), status_code
