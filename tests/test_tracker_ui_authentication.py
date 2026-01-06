"""
Playwright test to verify tracker UI authentication flow.

This test verifies that the authentication system correctly handles
browser requests vs API requests and redirects unauthenticated users.
"""

from playwright.sync_api import Page


class TestTrackerUIAuthentication:
    """Test tracker UI authentication and data loading."""

    def test_unauthenticated_user_redirected_to_login(self, page: Page, live_server):
        """
        Test that unauthenticated users are correctly redirected to login.

        This test verifies that:
        1. Browser requests without authentication are redirected to login
        2. The system no longer incorrectly treats browser requests as API key auth
        3. Authentication is working as expected
        """
        # Set up network monitoring
        network_requests = []

        def handle_request(request):
            network_requests.append(
                {
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                }
            )

        def handle_response(response):
            for req in network_requests:
                if req["url"] == response.url:
                    req["status"] = response.status
                    req["response_headers"] = dict(response.headers)
                    break

        page.on("request", handle_request)
        page.on("response", handle_response)

        # Navigate to dashboard without authentication
        print(f"Navigating to dashboard: {live_server.url}")
        page.goto(live_server.url)

        # Wait for page to load
        page.wait_for_load_state("networkidle")

        # Check current URL - should be redirected to login since not authenticated
        current_url = page.url
        print(f"Current URL after navigation: {current_url}")

        # Take a screenshot for debugging
        page.screenshot(path="debug_unauthenticated_redirect.png")

        # Verify we're redirected to login (this proves authentication is working)
        if "login" in current_url.lower() or "auth" in current_url.lower():
            print("✓ Correctly redirected to login page (authentication working)")
        else:
            print("✗ Not redirected to login - authentication may not be working")

        # Check network requests to understand the flow
        print("\n=== NETWORK REQUESTS ===")
        for req in network_requests:
            print(f"{req['method']} {req['url']} -> {req.get('status', 'pending')}")

        # Verify that we see the expected redirect flow:
        # 1. GET / -> 302 (redirect to /web/)
        # 2. GET /web/ -> 302 (redirect to /auth/login)
        # 3. GET /auth/login -> 200 (login page)
        redirect_count = sum(1 for req in network_requests if req.get("status") == 302)
        login_request = any("/auth/login" in req["url"] for req in network_requests)

        print(f"Redirect count: {redirect_count}")
        print(f"Login request found: {login_request}")

        # This test verifies that:
        # 1. Unauthenticated users are redirected to login (authentication working)
        # 2. The system no longer incorrectly treats browser requests as API key auth
        assert "login" in current_url.lower() or "auth" in current_url.lower(), (
            "Expected unauthenticated user to be redirected to login page"
        )
        assert redirect_count >= 1, (
            "Expected at least one redirect in the authentication flow"
        )
        assert login_request, "Expected to see a request to the login page"

    def test_direct_trackers_data_endpoint(self, page: Page, live_server):
        """
        Test the /web/trackers/data endpoint directly to see what it returns.

        This test checks if the endpoint correctly requires authentication
        and doesn't return data for unauthenticated requests.
        """
        # Navigate to establish a session first
        page.goto(live_server.url)

        # Now make a direct request to the trackers data endpoint
        trackers_data_url = f"{live_server.url}/web/trackers/data"
        print(f"Making direct request to: {trackers_data_url}")

        # Use page.request to make the API call
        response = page.request.get(trackers_data_url)

        print(f"Response status: {response.status}")
        print(f"Response headers: {dict(response.headers)}")

        # For unauthenticated requests, we should get a 401 or redirect
        if response.status == 401:
            print("✓ Correctly returns 401 for unauthenticated request")
            response_text = response.text()
            print(f"Response body: {response_text}")
        elif response.status in [302, 303]:
            print("✓ Correctly redirects unauthenticated request")
            location = response.headers.get("location", "")
            print(f"Redirect location: {location}")
        else:
            print(f"✗ Unexpected status code: {response.status}")
            response_text = response.text()
            print(f"Response body: {response_text}")

        # The endpoint should require authentication
        assert response.status in [401, 302, 303], (
            f"Expected 401 or redirect for unauthenticated request, got {response.status}"
        )

    def test_authentication_context_in_browser(self, page: Page, live_server):
        """
        Test that the authentication context is properly set up in browser requests.

        This test verifies that browser requests are handled differently from API requests.
        """
        # Navigate to the site
        page.goto(live_server.url)
        page.wait_for_load_state("networkidle")

        # Check if we can access any debug information about authentication
        # This would be available if the system is working correctly
        current_url = page.url

        # If we're on the login page, that's expected for unauthenticated users
        if "login" in current_url.lower():
            print("✓ Unauthenticated user correctly shown login page")

            # Check if the login page has the expected authentication options
            google_login = page.locator("text=Sign in with Google")
            email_login = page.locator("text=Email")

            if google_login.count() > 0:
                print("✓ Google OAuth login option available")
            if email_login.count() > 0:
                print("✓ Email/password login option available")

            # Take a screenshot of the login page
            page.screenshot(path="debug_login_page.png")

        else:
            print(f"✗ Unexpected page: {current_url}")

        # This test passes if we reach the login page (expected behavior)
        assert "login" in current_url.lower(), (
            "Expected to be on login page for unauthenticated user"
        )
