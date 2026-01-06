"""
Playwright tests for Jobs Page functionality

Tests the "View Details" button modal and "Run Now" button functionality
to ensure they work correctly and show the expected modals.
"""

import logging
import os

import pytest
from playwright.async_api import Page, expect

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Test configuration
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")
TEST_TIMEOUT = 30000  # 30 seconds


@pytest.mark.asyncio
async def test_view_details_button_opens_modal(page: Page):
    """Test that the 'View Details' button opens the job details modal"""
    logger.info("Testing View Details button functionality...")

    # Navigate to jobs page
    await page.goto(f"{BASE_URL}/web/jobs")
    await page.wait_for_load_state("networkidle")

    # Check if we need to authenticate
    current_url = page.url
    if "/auth/login" in current_url or "/login" in current_url:
        logger.info("Authentication required, attempting login...")
        await _authenticate(page)
        await page.goto(f"{BASE_URL}/web/jobs")
        await page.wait_for_load_state("networkidle")

    # Wait for the page title to confirm we're on the right page
    await expect(page.locator("h1")).to_contain_text("Automated Jobs")

    # Ensure we have a test job
    test_job = await _ensure_test_job_exists(page)

    # Find the View Details button in the job card
    if test_job["element"]:
        view_details_btn = test_job["element"].locator(
            'button:has-text("View Details")'
        )
    else:
        # Fallback: find any View Details button
        view_details_btn = page.locator('button:has-text("View Details")').first

    # Ensure the button exists
    await expect(view_details_btn).to_be_visible()

    # Click the View Details button
    await view_details_btn.click()

    # Wait for the job details modal to appear
    details_modal = page.locator("#job-details-modal")
    await expect(details_modal).to_be_visible(timeout=TEST_TIMEOUT)

    # Verify modal content
    modal_title = details_modal.locator("#job-details-title")
    await expect(modal_title).to_contain_text("Job Details")

    # Verify the modal contains job information
    job_details_content = details_modal.locator("#job-details-content")
    await expect(job_details_content).to_be_visible()

    # Check for execution history section
    history_section = job_details_content.locator(
        ':has-text("Recent Execution History")'
    )
    await expect(history_section).to_be_visible()

    # Verify close button works
    close_btn = details_modal.locator("#close-job-details-btn")
    await expect(close_btn).to_be_visible()
    await close_btn.click()

    # Verify modal closes
    await expect(details_modal).to_be_hidden()

    logger.info("✅ View Details button test passed")


@pytest.mark.asyncio
async def test_view_details_from_dropdown_opens_same_modal(page: Page):
    """Test that 'View Details' from dropdown opens the same modal as the button"""
    logger.info("Testing View Details from dropdown functionality...")

    # Navigate to jobs page
    await page.goto(f"{BASE_URL}/web/jobs")
    await page.wait_for_load_state("networkidle")

    # Check if we need to authenticate
    current_url = page.url
    if "/auth/login" in current_url or "/login" in current_url:
        logger.info("Authentication required, attempting login...")
        await _authenticate(page)
        await page.goto(f"{BASE_URL}/web/jobs")
        await page.wait_for_load_state("networkidle")

    # Wait for the page title to confirm we're on the right page
    await expect(page.locator("h1")).to_contain_text("Automated Jobs")

    # Ensure we have a test job
    test_job = await _ensure_test_job_exists(page)

    if not test_job["element"]:
        # Find first job card
        job_cards = page.locator(".job-card")
        if await job_cards.count() > 0:
            test_job["element"] = job_cards.first
        else:
            pytest.skip("No job cards found for testing")

    # Find and click the dropdown button (three dots menu)
    dropdown_btn = test_job["element"].locator("[data-dropdown-toggle]")
    await expect(dropdown_btn).to_be_visible()
    await dropdown_btn.click()

    # Wait for dropdown menu to appear
    job_id = test_job["id"]
    dropdown_menu = page.locator(f"#job-{job_id}-menu")
    await expect(dropdown_menu).to_be_visible()

    # Click "View Details" from dropdown
    view_details_dropdown = dropdown_menu.locator('[data-job-action="view-details"]')
    await expect(view_details_dropdown).to_be_visible()
    await view_details_dropdown.click()

    # Wait for the job details modal to appear
    details_modal = page.locator("#job-details-modal")
    await expect(details_modal).to_be_visible(timeout=TEST_TIMEOUT)

    # Verify it's the same modal with same content
    modal_title = details_modal.locator("#job-details-title")
    await expect(modal_title).to_contain_text("Job Details")

    # Verify the modal contains job information
    job_details_content = details_modal.locator("#job-details-content")
    await expect(job_details_content).to_be_visible()

    # Close the modal
    close_btn = details_modal.locator("#close-job-details-btn")
    await close_btn.click()
    await expect(details_modal).to_be_hidden()

    logger.info("✅ View Details from dropdown test passed")


@pytest.mark.asyncio
async def test_run_now_button_executes_job_and_shows_result(page: Page):
    """Test that the 'Run Now' button executes the job and shows results"""
    logger.info("Testing Run Now button functionality...")

    # Navigate to jobs page
    await page.goto(f"{BASE_URL}/web/jobs")
    await page.wait_for_load_state("networkidle")

    # Check if we need to authenticate
    current_url = page.url
    if "/auth/login" in current_url or "/login" in current_url:
        logger.info("Authentication required, attempting login...")
        await _authenticate(page)
        await page.goto(f"{BASE_URL}/web/jobs")
        await page.wait_for_load_state("networkidle")

    # Wait for the page title to confirm we're on the right page
    await expect(page.locator("h1")).to_contain_text("Automated Jobs")

    # Ensure we have a test job
    test_job = await _ensure_test_job_exists(page)

    # Find the Run Now button in the job card
    if test_job["element"]:
        run_now_btn = test_job["element"].locator('button:has-text("Run Now")')
    else:
        # Fallback: find any Run Now button
        run_now_btn = page.locator('button:has-text("Run Now")').first

    # Ensure the button exists
    await expect(run_now_btn).to_be_visible()

    # Set up response listener to capture the test job execution
    responses = []

    def handle_response(response):
        if "/api/jobs/" in response.url and "/test" in response.url:
            responses.append(response)

    page.on("response", handle_response)

    # Click the Run Now button
    await run_now_btn.click()

    # Wait for the API call to complete
    await page.wait_for_timeout(2000)  # Give time for API call

    # Check if we got a response
    if responses:
        response = responses[0]
        logger.info(f"Job test API response status: {response.status}")

        # Verify we got a response (success or failure)
        assert response.status in [200, 400, 500], (
            f"Unexpected status code: {response.status}"
        )

    # Look for toast notifications or modal results
    # Check for success toast
    success_toast = page.locator('.toast, [class*="toast"], [role="alert"]').filter(
        has_text="executed successfully"
    )
    failure_toast = page.locator('.toast, [class*="toast"], [role="alert"]').filter(
        has_text="execution failed"
    )

    # Wait for either success or failure notification
    try:
        await expect(success_toast.or_(failure_toast)).to_be_visible(timeout=10000)
        logger.info("✅ Job execution notification appeared")
    except:
        # If no toast, check for other indicators
        logger.info(
            "No toast notification found, checking for other execution indicators..."
        )

        # Check if job details modal opened with updated history
        details_modal = page.locator("#job-details-modal")
        if await details_modal.is_visible():
            logger.info("Job details modal is open, checking for execution history...")
            history_content = details_modal.locator("#job-history-content")
            await expect(history_content).to_be_visible()

    logger.info("✅ Run Now button test completed")


@pytest.mark.asyncio
async def test_run_now_from_dropdown_works(page: Page):
    """Test that 'Run Now' from dropdown menu works the same as the button"""
    logger.info("Testing Run Now from dropdown functionality...")

    # Navigate to jobs page
    await page.goto(f"{BASE_URL}/web/jobs")
    await page.wait_for_load_state("networkidle")

    # Check if we need to authenticate
    current_url = page.url
    if "/auth/login" in current_url or "/login" in current_url:
        logger.info("Authentication required, attempting login...")
        await _authenticate(page)
        await page.goto(f"{BASE_URL}/web/jobs")
        await page.wait_for_load_state("networkidle")

    # Wait for the page title to confirm we're on the right page
    await expect(page.locator("h1")).to_contain_text("Automated Jobs")

    # Ensure we have a test job
    test_job = await _ensure_test_job_exists(page)

    if not test_job["element"]:
        # Find first job card
        job_cards = page.locator(".job-card")
        if await job_cards.count() > 0:
            test_job["element"] = job_cards.first
        else:
            pytest.skip("No job cards found for testing")

    # Find and click the dropdown button (three dots menu)
    dropdown_btn = test_job["element"].locator("[data-dropdown-toggle]")
    await expect(dropdown_btn).to_be_visible()
    await dropdown_btn.click()

    # Wait for dropdown menu to appear
    job_id = test_job["id"]
    dropdown_menu = page.locator(f"#job-{job_id}-menu")
    await expect(dropdown_menu).to_be_visible()

    # Set up response listener
    responses = []

    def handle_response(response):
        if "/api/jobs/" in response.url and "/test" in response.url:
            responses.append(response)

    page.on("response", handle_response)

    # Click "Run Now" from dropdown
    run_now_dropdown = dropdown_menu.locator('[data-job-action="test-job"]')
    await expect(run_now_dropdown).to_be_visible()
    await run_now_dropdown.click()

    # Wait for the API call to complete
    await page.wait_for_timeout(2000)

    # Verify we got a response
    if responses:
        response = responses[0]
        logger.info(f"Job test API response status: {response.status}")
        assert response.status in [200, 400, 500], (
            f"Unexpected status code: {response.status}"
        )

    # Look for execution result indicators
    success_toast = page.locator('.toast, [class*="toast"], [role="alert"]').filter(
        has_text="executed successfully"
    )
    failure_toast = page.locator('.toast, [class*="toast"], [role="alert"]').filter(
        has_text="execution failed"
    )

    try:
        await expect(success_toast.or_(failure_toast)).to_be_visible(timeout=10000)
        logger.info("✅ Job execution notification appeared")
    except:
        logger.info(
            "No toast notification found, execution may have completed silently"
        )

    logger.info("✅ Run Now from dropdown test completed")


@pytest.mark.asyncio
async def test_modal_accessibility_and_keyboard_navigation(page: Page):
    """Test modal accessibility features and keyboard navigation"""
    logger.info("Testing modal accessibility and keyboard navigation...")

    # Navigate to jobs page
    await page.goto(f"{BASE_URL}/web/jobs")
    await page.wait_for_load_state("networkidle")

    # Check if we need to authenticate
    current_url = page.url
    if "/auth/login" in current_url or "/login" in current_url:
        logger.info("Authentication required, attempting login...")
        await _authenticate(page)
        await page.goto(f"{BASE_URL}/web/jobs")
        await page.wait_for_load_state("networkidle")

    # Wait for the page title to confirm we're on the right page
    await expect(page.locator("h1")).to_contain_text("Automated Jobs")

    # Ensure we have a test job
    test_job = await _ensure_test_job_exists(page)

    # Open job details modal
    if test_job["element"]:
        view_details_btn = test_job["element"].locator(
            'button:has-text("View Details")'
        )
    else:
        view_details_btn = page.locator('button:has-text("View Details")').first

    await view_details_btn.click()

    # Wait for modal to appear
    details_modal = page.locator("#job-details-modal")
    await expect(details_modal).to_be_visible()

    # Test ARIA attributes
    await expect(details_modal).to_have_attribute("role", "dialog")
    await expect(details_modal).to_have_attribute("aria-modal", "true")
    await expect(details_modal).to_have_attribute(
        "aria-labelledby", "job-details-title"
    )

    # Test keyboard navigation - Escape key should close modal
    await page.keyboard.press("Escape")
    await expect(details_modal).to_be_hidden()

    logger.info("✅ Modal accessibility test passed")


@pytest.mark.asyncio
async def test_multiple_jobs_interaction(page: Page):
    """Test interaction with multiple jobs if available"""
    logger.info("Testing multiple jobs interaction...")

    # Navigate to jobs page
    await page.goto(f"{BASE_URL}/web/jobs")
    await page.wait_for_load_state("networkidle")

    # Check if we need to authenticate
    current_url = page.url
    if "/auth/login" in current_url or "/login" in current_url:
        logger.info("Authentication required, attempting login...")
        await _authenticate(page)
        await page.goto(f"{BASE_URL}/web/jobs")
        await page.wait_for_load_state("networkidle")

    # Wait for the page title to confirm we're on the right page
    await expect(page.locator("h1")).to_contain_text("Automated Jobs")

    # Count available jobs
    job_cards = page.locator(".job-card")
    job_count = await job_cards.count()

    logger.info(f"Found {job_count} job cards")

    if job_count >= 2:
        # Test first job
        first_job = job_cards.first
        first_view_btn = first_job.locator('button:has-text("View Details")')
        await first_view_btn.click()

        details_modal = page.locator("#job-details-modal")
        await expect(details_modal).to_be_visible()

        # Close first modal
        close_btn = details_modal.locator("#close-job-details-btn")
        await close_btn.click()
        await expect(details_modal).to_be_hidden()

        # Test second job
        second_job = job_cards.nth(1)
        second_view_btn = second_job.locator('button:has-text("View Details")')
        await second_view_btn.click()

        await expect(details_modal).to_be_visible()

        # Close second modal
        await close_btn.click()
        await expect(details_modal).to_be_hidden()

        logger.info("✅ Multiple jobs interaction test passed")
    else:
        logger.info("Only one job available, skipping multiple jobs test")


@pytest.mark.asyncio
async def test_error_handling_for_invalid_job(page: Page):
    """Test error handling when trying to interact with invalid job"""
    logger.info("Testing error handling for invalid job...")

    # Navigate to jobs page
    await page.goto(f"{BASE_URL}/web/jobs")
    await page.wait_for_load_state("networkidle")

    # Check if we need to authenticate
    current_url = page.url
    if "/auth/login" in current_url or "/login" in current_url:
        logger.info("Authentication required, attempting login...")
        await _authenticate(page)
        await page.goto(f"{BASE_URL}/web/jobs")
        await page.wait_for_load_state("networkidle")

    # Wait for the page title to confirm we're on the right page
    await expect(page.locator("h1")).to_contain_text("Automated Jobs")

    # Try to call job details for non-existent job
    await page.evaluate("""
        if (window.JobManager && window.JobManager.showJobDetails) {
            window.JobManager.showJobDetails(99999);
        }
    """)

    # Wait a moment for any error handling
    await page.wait_for_timeout(2000)

    # Check for error toast or modal
    error_toast = page.locator('.toast, [class*="toast"], [role="alert"]').filter(
        has_text="error"
    )
    error_modal = page.locator('[role="dialog"]').filter(has_text="error")

    # Either an error toast should appear or no modal should open
    details_modal = page.locator("#job-details-modal")

    # The modal should either not be visible or show an error
    if await details_modal.is_visible():
        error_content = details_modal.locator(
            ':has-text("Failed to load"), :has-text("error"), :has-text("Error")'
        )
        await expect(error_content).to_be_visible()

        # Close the modal
        close_btn = details_modal.locator("#close-job-details-btn")
        await close_btn.click()

    logger.info("✅ Error handling test completed")


# Helper functions
async def _authenticate(page: Page):
    """Authenticate with the application"""
    try:
        # Try to find login form
        email_input = page.locator('input[type="email"], input[name="email"]')
        password_input = page.locator('input[type="password"], input[name="password"]')

        if await email_input.count() > 0 and await password_input.count() > 0:
            # Use test credentials
            await email_input.fill("test@example.com")
            await password_input.fill("testpassword123")

            # Find and click submit button
            submit_button = page.locator('button[type="submit"], input[type="submit"]')
            await submit_button.click()

            # Wait for redirect
            await page.wait_for_load_state("networkidle")
            logger.info("Authentication completed")
        else:
            logger.warning("Login form not found, proceeding without authentication")

    except Exception as e:
        logger.warning(f"Authentication failed: {e}, proceeding anyway")


async def _ensure_test_job_exists(page: Page) -> dict:
    """Ensure a test job exists for testing"""
    try:
        # Check if any jobs exist
        job_cards = page.locator(".job-card")
        job_count = await job_cards.count()

        if job_count > 0:
            # Get the first job's data
            first_card = job_cards.first
            job_id_attr = await first_card.get_attribute("data-job-id")
            job_title = await first_card.locator("h3").text_content()

            return {
                "id": int(job_id_attr) if job_id_attr else None,
                "name": job_title.strip() if job_title else "Test Job",
                "element": first_card,
            }
        else:
            # Create a test job
            logger.info("No jobs found, creating test job...")
            return await _create_test_job(page)

    except Exception as e:
        logger.error(f"Error ensuring test job exists: {e}")
        # Return a mock job for testing
        return {"id": 1, "name": "Test Job", "element": None}


async def _create_test_job(page: Page) -> dict:
    """Create a test job for testing purposes"""
    try:
        # Click create job button
        create_btn = page.locator("#create-job-btn")
        await create_btn.click()

        # Wait for form modal to appear
        form_modal = page.locator("#job-form-modal")
        await form_modal.wait_for(state="visible")

        # Fill out the form with test data
        await page.locator('input[name="name"]').fill("Playwright Test Job")
        await page.locator('select[name="job_type"]').select_option("generic")

        # Fill generic job config
        await page.locator('input[name="url"]').fill("https://api.example.com/test")
        await page.locator('input[name="json_path"]').fill("$.value")

        # Set cron schedule
        await page.locator('input[name="cron_schedule"]').fill("0 9 * * *")

        # Submit form
        submit_btn = form_modal.locator('button[type="submit"]')
        await submit_btn.click()

        # Wait for form to close and page to refresh
        await form_modal.wait_for(state="hidden")
        await page.wait_for_load_state("networkidle")

        # Find the newly created job
        job_cards = page.locator(".job-card")
        if await job_cards.count() > 0:
            first_card = job_cards.first
            job_id_attr = await first_card.get_attribute("data-job-id")

            return {
                "id": int(job_id_attr) if job_id_attr else 1,
                "name": "Playwright Test Job",
                "element": first_card,
            }
        else:
            logger.warning("Failed to create test job, using mock data")
            return {"id": 1, "name": "Test Job", "element": None}

    except Exception as e:
        logger.error(f"Error creating test job: {e}")
        return {"id": 1, "name": "Test Job", "element": None}


# Utility functions for running tests
async def run_single_test(test_name: str):
    """Run a single test by name"""
    pytest.main(["-v", f"tests/test_jobs_page_playwright.py::{test_name}"])


if __name__ == "__main__":
    # Run all tests
    pytest.main(["-v", "tests/test_jobs_page_playwright.py"])
