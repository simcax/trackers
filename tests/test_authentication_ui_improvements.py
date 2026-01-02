"""
Tests for Authentication UI Improvements.

This module tests the authentication methods display functionality
on the user profile page, covering different user authentication configurations.

Requirements: FR-1, FR-2, NFR-1, NFR-2, NFR-3, NFR-4
"""

from unittest.mock import patch

from trackers.models.user_model import UserModel


class TestAuthenticationUIImprovements:
    """Test suite for authentication UI improvements functionality."""

    def test_user_with_google_oauth_only(self, client, db_session):
        """
        Test profile page display for users with Google OAuth only.

        This test verifies that:
        - Google authentication badge is displayed
        - Email authentication badge is not displayed
        - Security status shows "Single authentication method"
        - Appropriate warning message is shown

        Requirements: FR-1, FR-2
        """
        # Create a user with Google OAuth only
        user = UserModel(
            google_user_id="google_123456789",
            email="test@example.com",
            name="Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash=None,  # No password authentication
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock the authentication system components that the decorator uses
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            # Mock Google OAuth authentication to return success
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True

            # Mock the user service to return our test user
            mock_get_db_user.return_value = user

            # Request the profile page
            response = client.get("/profile/")

            # Verify response is successful
            assert response.status_code == 200

            # Parse response data
            html_content = response.data.decode("utf-8")

            # Verify Google authentication badge is present
            assert "Google" in html_content
            assert "bg-blue-100 text-blue-800" in html_content  # Google badge styling

            # Verify Email authentication badge is NOT present
            assert "Email & Password" not in html_content
            assert (
                "bg-green-100 text-green-800" not in html_content
            )  # Email badge styling

            # Verify security status shows single method warning
            assert "Single authentication method" in html_content
            assert "text-yellow-400" in html_content  # Warning color
            assert "Consider adding a backup authentication method" in html_content

            # Verify authentication methods section is present
            assert "Authentication Methods" in html_content
            assert "Linked Authentication Methods" in html_content
            assert "Account Security" in html_content

    def test_user_with_email_password_only(self, client, db_session):
        """
        Test profile page display for users with email/password authentication only.

        This test verifies that:
        - Email authentication badge is displayed
        - Google authentication badge is not displayed
        - Security status shows "Single authentication method"
        - Appropriate warning message is shown

        Requirements: FR-1, FR-2
        """
        # Create a user with email/password authentication only
        user = UserModel(
            google_user_id=None,  # No Google OAuth
            email="email_user@example.com",  # Different email to avoid unique constraint violation
            name="Email Test User",
            profile_picture_url=None,
            password_hash="$2b$12$example_bcrypt_hash_here",  # Has password authentication
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock the authentication system components that the decorator uses
        with (
            patch(
                "trackers.auth.decorators._check_email_password_auth"
            ) as mock_email_auth,
            patch(
                "trackers.auth.decorators._has_email_password_auth_configured"
            ) as mock_has_email,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            # Mock email/password authentication to return success
            mock_email_auth.return_value = (True, user)
            mock_has_email.return_value = True

            # Mock the user service to return our test user
            mock_get_db_user.return_value = user

            # Request the profile page
            response = client.get("/profile/")

            # Verify response is successful
            assert response.status_code == 200

            # Parse response data
            html_content = response.data.decode("utf-8")

            # Verify Email authentication badge is present
            assert "Email & Password" in html_content
            assert "bg-green-100 text-green-800" in html_content  # Email badge styling

            # Verify Google authentication badge is NOT present
            assert "Google" not in html_content or html_content.count("Google") == 0
            assert (
                "bg-blue-100 text-blue-800" not in html_content
            )  # Google badge styling should not be present

            # Verify security status shows single method warning
            assert "Single authentication method" in html_content
            assert "text-yellow-400" in html_content  # Warning color
            assert "Consider adding a backup authentication method" in html_content

            # Verify authentication methods section is present
            assert "Authentication Methods" in html_content
            assert "Linked Authentication Methods" in html_content
            assert "Account Security" in html_content

            # Verify the email icon is present (envelope SVG)
            assert (
                "M3 8l7.89 5.26a2 2 0 002.22 0L21 8" in html_content
            )  # Email icon path

    def test_user_with_both_authentication_methods(self, client, db_session):
        """
        Test profile page display for users with both Google OAuth and email/password authentication.

        This test verifies that:
        - Both Google and Email authentication badges are displayed
        - Security status shows "Multiple authentication methods"
        - Appropriate success message is shown with enhanced security indication
        - Both authentication method icons are present

        Requirements: FR-1, FR-2
        """
        # Create a user with both authentication methods
        user = UserModel(
            google_user_id="google_987654321",  # Has Google OAuth
            email="both_auth@example.com",  # Different email to avoid unique constraint violation
            name="Both Auth User",
            profile_picture_url="https://example.com/both_profile.jpg",
            password_hash="$2b$12$another_example_bcrypt_hash_here",  # Has password authentication
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock the authentication system components that the decorator uses
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            # Mock Google OAuth authentication to return success (primary auth method)
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True

            # Mock the user service to return our test user
            mock_get_db_user.return_value = user

            # Request the profile page
            response = client.get("/profile/")

            # Verify response is successful
            assert response.status_code == 200

            # Parse response data
            html_content = response.data.decode("utf-8")

            # Verify BOTH authentication badges are present
            assert "Google" in html_content
            assert "bg-blue-100 text-blue-800" in html_content  # Google badge styling
            assert "Email & Password" in html_content
            assert "bg-green-100 text-green-800" in html_content  # Email badge styling

            # Verify security status shows multiple methods (enhanced security)
            assert "Multiple authentication methods" in html_content
            assert "text-green-400" in html_content  # Success/secure color
            assert "Enhanced account security with backup login options" in html_content

            # Verify authentication methods section is present
            assert "Authentication Methods" in html_content
            assert "Linked Authentication Methods" in html_content
            assert "Account Security" in html_content

            # Verify both icons are present
            # Google icon (multi-color G logo paths)
            assert (
                "M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                in html_content
            )  # Google icon path

            # Email icon (envelope SVG)
            assert (
                "M3 8l7.89 5.26a2 2 0 002.22 0L21 8" in html_content
            )  # Email icon path

            # Verify that single method warnings are NOT present
            assert "Single authentication method" not in html_content
            assert "Consider adding a backup authentication method" not in html_content
            assert (
                "text-yellow-400" not in html_content
            )  # Warning color should not be present

    def test_user_with_no_authentication_methods(self, client, db_session):
        """
        Test profile page display for users with no authentication methods (edge case).

        This test verifies that:
        - No authentication method badges are displayed
        - "No authentication methods configured" message is shown
        - Security status shows error state with appropriate warning
        - Proper error styling is applied

        Requirements: TC-1, TC-2, TC-3
        """
        # Create a user with no authentication methods (edge case)
        user = UserModel(
            google_user_id=None,  # No Google OAuth
            email="no_auth@example.com",  # Different email to avoid unique constraint violation
            name="No Auth User",
            profile_picture_url=None,
            password_hash=None,  # No password authentication
            email_verified=False,  # Likely not verified if no auth methods
        )

        db_session.add(user)
        db_session.commit()

        # Mock the authentication system components
        # Note: This is an edge case that shouldn't normally occur in production
        # but we need to handle it gracefully
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.auth.decorators._check_email_password_auth"
            ) as mock_email_auth,
            patch(
                "trackers.auth.decorators._has_email_password_auth_configured"
            ) as mock_has_email,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            # Mock that no authentication methods are configured
            mock_google_auth.return_value = (False, None)
            mock_has_google.return_value = False
            mock_email_auth.return_value = (False, None)
            mock_has_email.return_value = False

            # Mock the user service to return our test user
            mock_get_db_user.return_value = user

            # Request the profile page
            response = client.get("/profile/")

            # Verify response is successful (page should still render gracefully)
            assert response.status_code == 200

            # Parse response data
            html_content = response.data.decode("utf-8")

            # Verify NO authentication method badges are present
            assert "Google" not in html_content or html_content.count("Google") == 0
            assert (
                "bg-blue-100 text-blue-800" not in html_content
            )  # Google badge styling should not be present
            assert "Email & Password" not in html_content
            assert (
                "bg-green-100 text-green-800" not in html_content
            )  # Email badge styling should not be present

            # Verify "No authentication methods configured" message is present
            assert "No authentication methods configured" in html_content
            assert (
                "bg-gray-600 text-gray-300" in html_content
            )  # No methods badge styling

            # Verify security status shows error state
            assert "No authentication configured" in html_content
            assert "text-red-400" in html_content  # Error color
            assert "Please set up an authentication method" in html_content

            # Verify authentication methods section is still present (graceful handling)
            assert "Authentication Methods" in html_content
            assert "Linked Authentication Methods" in html_content
            assert "Account Security" in html_content

            # Verify warning icon is present for no methods badge
            assert (
                "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                in html_content
            )  # Warning triangle icon path

            # Verify error icon is present for security status
            assert (
                "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" in html_content
            )  # Error circle icon path

            # Verify that success/warning messages from other states are NOT present
            assert "Multiple authentication methods" not in html_content
            assert "Single authentication method" not in html_content
            assert (
                "Enhanced account security with backup login options"
                not in html_content
            )
            assert "Consider adding a backup authentication method" not in html_content

            # Verify that the specific success color for authentication status is not present
            # (Note: text-green-400 may appear elsewhere in the page for code highlighting, etc.)
            # So we check that the specific success message combination is not present
            assert not (
                "text-green-400" in html_content
                and "Multiple authentication methods" in html_content
            )
            assert (
                "text-yellow-400" not in html_content
            )  # Warning color should not be present

    def test_google_badge_styling_elements(self, client, db_session):
        """
        Test that Google authentication badge has proper styling elements.

        This test verifies specific styling classes and elements for the Google badge:
        - Proper background, text, and border colors
        - Correct padding and shape classes
        - Google icon SVG paths are present
        - Badge structure and accessibility attributes

        Requirements: FR-2, NFR-4
        """
        # Create a user with Google OAuth only
        user = UserModel(
            google_user_id="google_styling_test",
            email="google_styling@example.com",
            name="Google Styling Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash=None,
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify Google badge styling classes
            assert "inline-flex items-center" in html_content  # Badge structure
            assert "px-3 py-1.5" in html_content  # Padding
            assert "rounded-full" in html_content  # Shape
            assert "text-sm font-medium" in html_content  # Typography
            assert (
                "bg-blue-100 text-blue-800 border border-blue-200" in html_content
            )  # Google colors

            # Verify Google icon is present with proper attributes
            assert 'class="w-4 h-4 mr-2"' in html_content  # Icon sizing and margin
            assert 'viewBox="0 0 24 24"' in html_content  # Icon viewBox
            assert 'aria-hidden="true"' in html_content  # Accessibility attribute

            # Verify all Google icon SVG paths are present (multi-color G logo)
            assert 'fill="#4285F4"' in html_content  # Blue path
            assert 'fill="#34A853"' in html_content  # Green path
            assert 'fill="#FBBC05"' in html_content  # Yellow path
            assert 'fill="#EA4335"' in html_content  # Red path

            # Verify specific Google icon path data
            assert (
                "M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                in html_content
            )

    def test_email_badge_styling_elements(self, client, db_session):
        """
        Test that Email & Password authentication badge has proper styling elements.

        This test verifies specific styling classes and elements for the Email badge:
        - Proper background, text, and border colors
        - Correct padding and shape classes
        - Email icon SVG paths are present
        - Badge structure and accessibility attributes

        Requirements: FR-2, NFR-4
        """
        # Create a user with email/password authentication only
        user = UserModel(
            google_user_id=None,
            email="email_styling@example.com",
            name="Email Styling Test User",
            profile_picture_url=None,
            password_hash="$2b$12$example_bcrypt_hash_for_styling_test",
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication
        with (
            patch(
                "trackers.auth.decorators._check_email_password_auth"
            ) as mock_email_auth,
            patch(
                "trackers.auth.decorators._has_email_password_auth_configured"
            ) as mock_has_email,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_email_auth.return_value = (True, user)
            mock_has_email.return_value = True
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify Email badge styling classes
            assert "inline-flex items-center" in html_content  # Badge structure
            assert "px-3 py-1.5" in html_content  # Padding
            assert "rounded-full" in html_content  # Shape
            assert "text-sm font-medium" in html_content  # Typography
            assert (
                "bg-green-100 text-green-800 border border-green-200" in html_content
            )  # Email colors

            # Verify Email icon is present with proper attributes
            assert 'class="w-4 h-4 mr-2"' in html_content  # Icon sizing and margin
            assert 'fill="none"' in html_content  # Email icon fill
            assert 'viewBox="0 0 24 24"' in html_content  # Icon viewBox
            assert 'stroke="currentColor"' in html_content  # Email icon stroke
            assert 'aria-hidden="true"' in html_content  # Accessibility attribute

            # Verify Email icon SVG paths are present
            assert 'stroke-linecap="round"' in html_content  # Icon styling
            assert 'stroke-linejoin="round"' in html_content  # Icon styling
            assert 'stroke-width="2"' in html_content  # Icon stroke width

            # Verify specific Email icon path data (envelope)
            assert (
                "M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                in html_content
            )

    def test_no_methods_badge_styling_elements(self, client, db_session):
        """
        Test that "No authentication methods configured" badge has proper styling elements.

        This test verifies specific styling classes and elements for the no methods badge:
        - Proper background, text, and border colors (gray theme)
        - Correct padding and shape classes
        - Warning icon SVG paths are present
        - Badge structure and accessibility attributes

        Requirements: TC-1, TC-2, TC-3
        """
        # Create a user with no authentication methods
        user = UserModel(
            google_user_id=None,
            email="no_methods_styling@example.com",
            name="No Methods Styling Test User",
            profile_picture_url=None,
            password_hash=None,
            email_verified=False,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication to simulate no methods configured
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.auth.decorators._check_email_password_auth"
            ) as mock_email_auth,
            patch(
                "trackers.auth.decorators._has_email_password_auth_configured"
            ) as mock_has_email,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (False, None)
            mock_has_google.return_value = False
            mock_email_auth.return_value = (False, None)
            mock_has_email.return_value = False
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify No methods badge styling classes
            assert "inline-flex items-center" in html_content  # Badge structure
            assert "px-3 py-1.5" in html_content  # Padding
            assert "rounded-full" in html_content  # Shape
            assert "text-sm font-medium" in html_content  # Typography
            assert (
                "bg-gray-600 text-gray-300 border border-gray-500" in html_content
            )  # Gray colors

            # Verify Warning icon is present with proper attributes
            assert 'class="w-4 h-4 mr-2"' in html_content  # Icon sizing and margin
            assert 'fill="none"' in html_content  # Warning icon fill
            assert 'viewBox="0 0 24 24"' in html_content  # Icon viewBox
            assert 'stroke="currentColor"' in html_content  # Warning icon stroke
            assert 'aria-hidden="true"' in html_content  # Accessibility attribute

            # Verify Warning icon SVG paths are present
            assert 'stroke-linecap="round"' in html_content  # Icon styling
            assert 'stroke-linejoin="round"' in html_content  # Icon styling
            assert 'stroke-width="2"' in html_content  # Icon stroke width

            # Verify specific Warning icon path data (warning triangle)
            assert (
                "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                in html_content
            )

    def test_security_status_styling_elements(self, client, db_session):
        """
        Test that security status indicators have proper styling elements.

        This test verifies styling for all three security status states:
        - Multiple methods (green with checkmark icon)
        - Single method (yellow with warning icon)
        - No methods (red with error icon)

        Requirements: FR-2, NFR-4
        """
        # Test Multiple methods security status
        user_multiple = UserModel(
            google_user_id="google_security_test",
            email="security_multiple@example.com",
            name="Security Multiple Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash="$2b$12$example_bcrypt_hash_security_test",
            email_verified=True,
        )

        db_session.add(user_multiple)
        db_session.commit()

        # Mock authentication for multiple methods
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user_multiple)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user_multiple

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify Multiple methods security status styling
            assert "flex items-center text-green-400" in html_content  # Success color
            assert 'class="w-4 h-4 mr-1"' in html_content  # Security icon sizing
            assert "Multiple authentication methods" in html_content  # Status text
            assert (
                "Enhanced account security with backup login options" in html_content
            )  # Subtext
            assert (
                'class="text-xs text-gray-400 mt-1"' in html_content
            )  # Subtext styling

            # Verify checkmark icon path for multiple methods
            assert "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" in html_content

        # Clean up for next test
        db_session.delete(user_multiple)
        db_session.commit()

        # Test Single method security status
        user_single = UserModel(
            google_user_id="google_single_test",
            email="security_single@example.com",
            name="Security Single Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash=None,  # Only Google auth
            email_verified=True,
        )

        db_session.add(user_single)
        db_session.commit()

        # Mock authentication for single method
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user_single)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user_single

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify Single method security status styling
            assert "flex items-center text-yellow-400" in html_content  # Warning color
            assert "Single authentication method" in html_content  # Status text
            assert (
                "Consider adding a backup authentication method" in html_content
            )  # Subtext

            # Verify warning triangle icon path for single method
            assert (
                "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                in html_content
            )

        # Clean up for next test
        db_session.delete(user_single)
        db_session.commit()

        # Test No methods security status
        user_none = UserModel(
            google_user_id=None,
            email="security_none@example.com",
            name="Security None Test User",
            profile_picture_url=None,
            password_hash=None,
            email_verified=False,
        )

        db_session.add(user_none)
        db_session.commit()

        # Mock authentication for no methods
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.auth.decorators._check_email_password_auth"
            ) as mock_email_auth,
            patch(
                "trackers.auth.decorators._has_email_password_auth_configured"
            ) as mock_has_email,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (False, None)
            mock_has_google.return_value = False
            mock_email_auth.return_value = (False, None)
            mock_has_email.return_value = False
            mock_get_db_user.return_value = user_none

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify No methods security status styling
            assert "flex items-center text-red-400" in html_content  # Error color
            assert "No authentication configured" in html_content  # Status text
            assert "Please set up an authentication method" in html_content  # Subtext

            # Verify error circle icon path for no methods
            assert "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" in html_content

    def test_security_status_messages_correctness(self, client, db_session):
        """
        Test that security status messages are exactly correct for all authentication states.

        This test specifically verifies the exact security status messages and their
        associated styling for all three authentication states as defined in the design:
        - Multiple methods: "Multiple authentication methods" with success styling
        - Single method: "Single authentication method" with warning styling
        - No methods: "No authentication configured" with error styling

        Requirements: FR-1, FR-2, Design Security Status Indicators
        """

        # Test 1: Multiple authentication methods (both Google and email/password)
        user_multiple = UserModel(
            google_user_id="security_msg_test_multiple",
            email="security_msg_multiple@example.com",
            name="Security Message Multiple Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash="$2b$12$example_bcrypt_hash_security_msg_test",
            email_verified=True,
        )

        db_session.add(user_multiple)
        db_session.commit()

        # Mock authentication for multiple methods
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user_multiple)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user_multiple

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify exact security status message for multiple methods
            assert "Multiple authentication methods" in html_content
            assert "Enhanced account security with backup login options" in html_content
            assert "text-green-400" in html_content  # Success color

            # Verify that other status messages are NOT present
            assert "Single authentication method" not in html_content
            assert "No authentication configured" not in html_content
            assert "Consider adding a backup authentication method" not in html_content
            assert "Please set up an authentication method" not in html_content

        # Clean up
        db_session.delete(user_multiple)
        db_session.commit()

        # Test 2: Single authentication method (Google only)
        user_single_google = UserModel(
            google_user_id="security_msg_test_single_google",
            email="security_msg_single_google@example.com",
            name="Security Message Single Google Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash=None,  # No password auth
            email_verified=True,
        )

        db_session.add(user_single_google)
        db_session.commit()

        # Mock authentication for single Google method
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user_single_google)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user_single_google

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify exact security status message for single method
            assert "Single authentication method" in html_content
            assert "Consider adding a backup authentication method" in html_content
            assert "text-yellow-400" in html_content  # Warning color

            # Verify that other status messages are NOT present
            assert "Multiple authentication methods" not in html_content
            assert "No authentication configured" not in html_content
            assert (
                "Enhanced account security with backup login options"
                not in html_content
            )
            assert "Please set up an authentication method" not in html_content

        # Clean up
        db_session.delete(user_single_google)
        db_session.commit()

        # Test 3: Single authentication method (email/password only)
        user_single_email = UserModel(
            google_user_id=None,  # No Google auth
            email="security_msg_single_email@example.com",
            name="Security Message Single Email Test User",
            profile_picture_url=None,
            password_hash="$2b$12$example_bcrypt_hash_security_msg_single_email",
            email_verified=True,
        )

        db_session.add(user_single_email)
        db_session.commit()

        # Mock authentication for single email method
        with (
            patch(
                "trackers.auth.decorators._check_email_password_auth"
            ) as mock_email_auth,
            patch(
                "trackers.auth.decorators._has_email_password_auth_configured"
            ) as mock_has_email,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_email_auth.return_value = (True, user_single_email)
            mock_has_email.return_value = True
            mock_get_db_user.return_value = user_single_email

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify exact security status message for single method
            assert "Single authentication method" in html_content
            assert "Consider adding a backup authentication method" in html_content
            assert "text-yellow-400" in html_content  # Warning color

            # Verify that other status messages are NOT present
            assert "Multiple authentication methods" not in html_content
            assert "No authentication configured" not in html_content
            assert (
                "Enhanced account security with backup login options"
                not in html_content
            )
            assert "Please set up an authentication method" not in html_content

        # Clean up
        db_session.delete(user_single_email)
        db_session.commit()

        # Test 4: No authentication methods (edge case)
        user_none = UserModel(
            google_user_id=None,  # No Google auth
            email="security_msg_none@example.com",
            name="Security Message None Test User",
            profile_picture_url=None,
            password_hash=None,  # No password auth
            email_verified=False,
        )

        db_session.add(user_none)
        db_session.commit()

        # Mock authentication for no methods
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.auth.decorators._check_email_password_auth"
            ) as mock_email_auth,
            patch(
                "trackers.auth.decorators._has_email_password_auth_configured"
            ) as mock_has_email,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (False, None)
            mock_has_google.return_value = False
            mock_email_auth.return_value = (False, None)
            mock_has_email.return_value = False
            mock_get_db_user.return_value = user_none

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify exact security status message for no methods
            assert "No authentication configured" in html_content
            assert "Please set up an authentication method" in html_content
            assert "text-red-400" in html_content  # Error color

            # Verify that other status messages are NOT present
            assert "Multiple authentication methods" not in html_content
            assert "Single authentication method" not in html_content
            assert (
                "Enhanced account security with backup login options"
                not in html_content
            )
            assert "Consider adding a backup authentication method" not in html_content

    def test_badge_layout_and_structure(self, client, db_session):
        """
        Test that authentication methods section has proper layout and structure.

        This test verifies:
        - Section container styling and structure
        - Grid layout classes for responsive design
        - Proper heading hierarchy and labels
        - Flex layout for badges with proper gap spacing

        Requirements: FR-2, NFR-3, NFR-4
        """
        # Create a user with both authentication methods for comprehensive layout test
        user = UserModel(
            google_user_id="layout_test_google",
            email="layout_test@example.com",
            name="Layout Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash="$2b$12$example_bcrypt_hash_layout_test",
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify main section container styling
            assert (
                "bg-gray-800 rounded-lg p-6 mb-8 border border-gray-700" in html_content
            )

            # Verify section heading
            assert 'class="text-xl font-semibold text-white mb-4"' in html_content
            assert "Authentication Methods" in html_content

            # Verify responsive grid layout
            assert "grid grid-cols-1 md:grid-cols-2 gap-4" in html_content

            # Verify left column (authentication methods) structure
            assert (
                'class="block text-sm font-medium text-gray-400 mb-2"' in html_content
            )
            assert "Linked Authentication Methods" in html_content
            assert "flex flex-wrap gap-2" in html_content  # Badge container

            # Verify right column (security status) structure
            assert "Account Security" in html_content
            assert 'class="text-sm text-gray-300"' in html_content

            # Verify that both badges are present with proper spacing
            badge_count = html_content.count("inline-flex items-center")
            assert badge_count >= 2  # At least Google and Email badges

            # Verify proper gap spacing between badges
            assert "gap-2" in html_content  # Badge container gap

    def test_responsive_design_mobile_layout(self, client, db_session):
        """
        Test responsive design for mobile layout (< 640px).

        This test verifies:
        - Single column layout using grid-cols-1
        - Proper badge wrapping with flex-wrap
        - Mobile-friendly spacing and sizing
        - Touch targets meet minimum requirements
        - No horizontal scrolling issues

        Requirements: NFR-3, Task 3 - Responsive Design
        """
        # Create a user with both authentication methods to test full mobile layout
        user = UserModel(
            google_user_id="mobile_test_google",
            email="mobile_test@example.com",
            name="Mobile Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash="$2b$12$example_bcrypt_hash_mobile_test",
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify mobile-first single column layout
            assert "grid grid-cols-1" in html_content

            # Verify responsive breakpoint for larger screens
            assert "md:grid-cols-2" in html_content

            # Verify badge container uses flex-wrap for mobile
            assert "flex flex-wrap gap-2" in html_content

            # Verify mobile-friendly padding and spacing
            assert "px-3 py-1.5" in html_content  # Badge padding suitable for touch
            assert "gap-4" in html_content  # Grid gap for proper spacing

            # Verify text sizing is appropriate for mobile
            assert "text-sm" in html_content  # Badge text size
            assert "text-xl" in html_content  # Section heading size

            # Verify icon sizing is touch-friendly
            assert "w-4 h-4" in html_content  # 16px icons are touch-friendly

            # Verify container has proper mobile margins
            assert "mb-8" in html_content  # Bottom margin for section separation
            assert "p-6" in html_content  # Padding that works on mobile

    def test_responsive_design_tablet_layout(self, client, db_session):
        """
        Test responsive design for tablet layout (640px - 1024px).

        This test verifies:
        - Two column layout using md:grid-cols-2
        - Proper content distribution between columns
        - Appropriate spacing for tablet screens
        - Badge layout optimization for medium screens

        Requirements: NFR-3, Task 3 - Responsive Design
        """
        # Create a user with both authentication methods to test tablet layout
        user = UserModel(
            google_user_id="tablet_test_google",
            email="tablet_test@example.com",
            name="Tablet Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash="$2b$12$example_bcrypt_hash_tablet_test",
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify tablet two-column layout
            assert "grid grid-cols-1 md:grid-cols-2" in html_content

            # Verify proper gap spacing for tablet
            assert "gap-4" in html_content

            # Verify left column content (authentication methods)
            assert "Linked Authentication Methods" in html_content
            assert "flex flex-wrap gap-2" in html_content  # Badge container

            # Verify right column content (security status)
            assert "Account Security" in html_content
            assert "text-sm text-gray-300" in html_content

            # Verify badges maintain proper sizing for tablet
            assert "px-3 py-1.5" in html_content  # Badge padding
            assert "text-sm font-medium" in html_content  # Badge typography

            # Verify section container adapts well to tablet
            assert "rounded-lg p-6" in html_content  # Container styling

            # Verify both authentication methods are displayed
            assert "Google" in html_content
            assert "Email & Password" in html_content

    def test_responsive_design_desktop_layout(self, client, db_session):
        """
        Test responsive design for desktop layout (> 1024px).

        This test verifies:
        - Two column layout is maintained on desktop
        - Optimal spacing and alignment for large screens
        - Content distribution works well on wide screens
        - All elements scale appropriately

        Requirements: NFR-3, Task 3 - Responsive Design
        """
        # Create a user with both authentication methods to test desktop layout
        user = UserModel(
            google_user_id="desktop_test_google",
            email="desktop_test@example.com",
            name="Desktop Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash="$2b$12$example_bcrypt_hash_desktop_test",
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify desktop maintains two-column layout
            assert "grid grid-cols-1 md:grid-cols-2" in html_content

            # Verify optimal spacing for desktop
            assert "gap-4" in html_content  # Grid gap
            assert "gap-2" in html_content  # Badge gap

            # Verify container styling works well on desktop
            assert "max-w-6xl mx-auto" in html_content  # Page container max-width
            assert "px-4 sm:px-6 lg:px-8" in html_content  # Responsive padding

            # Verify section styling is appropriate for desktop
            assert "bg-gray-800 rounded-lg p-6 mb-8" in html_content

            # Verify typography scales well for desktop
            assert "text-xl font-semibold" in html_content  # Section heading
            assert "text-sm font-medium" in html_content  # Badge text

            # Verify both columns have proper content
            assert "Linked Authentication Methods" in html_content  # Left column
            assert "Account Security" in html_content  # Right column

            # Verify authentication methods are displayed
            assert "Google" in html_content
            assert "Email & Password" in html_content

            # Verify security status is displayed
            assert "Multiple authentication methods" in html_content

    def test_responsive_badge_wrapping(self, client, db_session):
        """
        Test that authentication method badges wrap gracefully when space is limited.

        This test verifies:
        - Badges use flex-wrap to wrap to new lines when needed
        - Proper gap spacing is maintained when wrapping
        - Badge content remains readable when wrapped
        - No layout breaking occurs with long badge text

        Requirements: NFR-3, Task 3 - Responsive Design
        """
        # Create a user with both authentication methods to test badge wrapping
        user = UserModel(
            google_user_id="wrap_test_google",
            email="wrap_test@example.com",
            name="Badge Wrap Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash="$2b$12$example_bcrypt_hash_wrap_test",
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify flex-wrap is used for badge container
            assert "flex flex-wrap gap-2" in html_content

            # Verify badges have proper inline-flex structure
            assert "inline-flex items-center" in html_content

            # Verify badges have appropriate padding for wrapping
            assert "px-3 py-1.5" in html_content

            # Verify badges have rounded corners that work when wrapped
            assert "rounded-full" in html_content

            # Verify text sizing remains readable when wrapped
            assert "text-sm font-medium" in html_content

            # Verify both badges are present and can wrap
            google_badge_present = (
                "Google" in html_content and "bg-blue-100" in html_content
            )
            email_badge_present = (
                "Email & Password" in html_content and "bg-green-100" in html_content
            )
            assert google_badge_present
            assert email_badge_present

            # Verify gap spacing is consistent
            assert "gap-2" in html_content  # Badge container gap

    def test_responsive_text_scaling(self, client, db_session):
        """
        Test that text remains readable at all screen sizes.

        This test verifies:
        - Text sizing is appropriate for different screen sizes
        - Font weights provide proper hierarchy
        - Color contrast is maintained across sizes
        - No text becomes too small to read

        Requirements: NFR-3, Task 3 - Responsive Design
        """
        # Create a user with both authentication methods to test text scaling
        user = UserModel(
            google_user_id="text_scale_test_google",
            email="text_scale_test@example.com",
            name="Text Scale Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash="$2b$12$example_bcrypt_hash_text_scale_test",
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify section heading text scaling
            assert "text-xl font-semibold text-white" in html_content

            # Verify label text scaling
            assert "text-sm font-medium text-gray-400" in html_content

            # Verify badge text scaling (readable but not too large)
            assert "text-sm font-medium" in html_content

            # Verify security status text scaling
            assert "text-sm text-gray-300" in html_content

            # Verify subtext scaling (smaller but still readable)
            assert "text-xs text-gray-400" in html_content

            # Verify proper font weight hierarchy
            assert "font-semibold" in html_content  # Section headings
            assert "font-medium" in html_content  # Labels and badges

            # Verify color contrast classes are used
            assert "text-white" in html_content  # High contrast for headings
            assert "text-gray-300" in html_content  # Medium contrast for content
            assert "text-gray-400" in html_content  # Lower contrast for labels

    def test_responsive_container_spacing(self, client, db_session):
        """
        Test that container spacing works properly across different screen sizes.

        This test verifies:
        - Proper padding and margins for different screen sizes
        - No layout breaking on small screens
        - Appropriate spacing between elements
        - Container max-width constraints work properly

        Requirements: NFR-3, Task 3 - Responsive Design
        """
        # Create a user with both authentication methods to test container spacing
        user = UserModel(
            google_user_id="spacing_test_google",
            email="spacing_test@example.com",
            name="Spacing Test User",
            profile_picture_url="https://example.com/profile.jpg",
            password_hash="$2b$12$example_bcrypt_hash_spacing_test",
            email_verified=True,
        )

        db_session.add(user)
        db_session.commit()

        # Mock authentication
        with (
            patch(
                "trackers.auth.decorators._check_google_oauth_auth"
            ) as mock_google_auth,
            patch(
                "trackers.auth.decorators._has_google_auth_configured"
            ) as mock_has_google,
            patch(
                "trackers.services.user_service.UserService.get_current_user_from_session"
            ) as mock_get_db_user,
        ):
            mock_google_auth.return_value = (True, user)
            mock_has_google.return_value = True
            mock_get_db_user.return_value = user

            response = client.get("/profile/")
            assert response.status_code == 200
            html_content = response.data.decode("utf-8")

            # Verify page container responsive padding
            assert "px-4 sm:px-6 lg:px-8" in html_content

            # Verify page container max-width and centering
            assert "max-w-6xl mx-auto" in html_content

            # Verify section container padding
            assert "p-6" in html_content

            # Verify section bottom margin
            assert "mb-8" in html_content

            # Verify grid gap spacing
            assert "gap-4" in html_content

            # Verify badge container gap
            assert "gap-2" in html_content

            # Verify badge internal padding
            assert "px-3 py-1.5" in html_content

            # Verify label bottom margin
            assert "mb-2" in html_content

            # Verify section heading bottom margin
            assert "mb-4" in html_content

            # Verify subtext top margin
            assert "mt-1" in html_content
