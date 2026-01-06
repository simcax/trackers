"""
Playwright UI tests for Jobs functionality

Tests the complete jobs workflow including:
1. Creating a new job for a newly created tracker
2. Verifying UI correctly counts the number of jobs for a user
3. Testing UI correctly lists the jobs

Requirements: 1.1, 1.2, 1.3, 1.4, 5.1, 5.3, 7.1, 7.2, 10.1, 10.2
"""

import pytest
from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from trackers import create_app
from trackers.db import database as db_module
from trackers.models.job_model import JobModel
from trackers.models.tracker_model import TrackerModel
from trackers.models.user_model import UserModel
from trackers.services.job_service import JobService
from trackers.services.user_service import UserService


class TestJobsUI:
    """Test Jobs UI functionality with Playwright"""

    @pytest.fixture(scope="class")
    async def browser(self):
        """Create browser instance"""
        playwright = await async_playwright().start()
        browser = await playwright.chromium.launch(headless=False, slow_mo=500)
        yield browser
        await browser.close()
        await playwright.stop()

    @pytest.fixture(scope="class")
    async def context(self, browser: Browser):
        """Create browser context"""
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        yield context
        await context.close()

    @pytest.fixture
    async def page(self, context: BrowserContext):
        """Create new page for each test"""
        page = await context.new_page()
        yield page
        await page.close()

    @pytest.fixture
    def app(self):
        """Create Flask app instance"""
        app = create_app()
        app.config["TESTING"] = True
        return app

    @pytest.fixture
    def test_user_data(self):
        """Test user data"""
        return {
            "email": "playwright-test@example.com",
            "name": "Playwright Test User",
            "password": "test-password-123",
        }

    @pytest.fixture
    def test_tracker_data(self):
        """Test tracker data"""
        return {
            "name": "Test Tracker for Jobs",
            "description": "A test tracker for job creation tests",
        }

    @pytest.fixture
    def test_job_data(self):
        """Test job data"""
        return {
            "name": "Test Stock Job",
            "job_type": "stock",
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test-api-key",
            },
            "cron_schedule": "0 9 * * *",
        }

    async def setup_test_user(self, app, test_user_data):
        """Create a test user and return user info"""
        with app.app_context():
            db = db_module.SessionLocal()
            try:
                user_service = UserService(db)

                # Create user
                user = UserModel(
                    email=test_user_data["email"],
                    name=test_user_data["name"],
                    google_id=f"test-google-id-{test_user_data['email']}",
                )
                db.add(user)
                db.commit()
                db.refresh(user)

                return user
            finally:
                db.close()

    async def setup_test_tracker(self, app, user_id, test_tracker_data):
        """Create a test tracker and return tracker info"""
        with app.app_context():
            db = db_module.SessionLocal()
            try:
                tracker = TrackerModel(
                    name=test_tracker_data["name"],
                    description=test_tracker_data["description"],
                    user_id=user_id,
                )
                db.add(tracker)
                db.commit()
                db.refresh(tracker)

                return tracker
            finally:
                db.close()

    async def login_user(self, page: Page, test_user_data):
        """Login user via email/password authentication"""
        # Navigate to login page
        await page.goto("http://localhost:5000/auth/login")
        await page.wait_for_load_state("networkidle")

        # Fill login form
        await page.fill('input[name="email"]', test_user_data["email"])
        await page.fill('input[name="password"]', test_user_data["password"])

        # Submit form
        await page.click('button[type="submit"]')
        await page.wait_for_load_state("networkidle")

        # Verify login success
        await page.wait_for_selector('text="Dashboard"', timeout=10000)

    async def navigate_to_jobs_page(self, page: Page):
        """Navigate to the jobs page"""
        # Click on Jobs link in navigation
        await page.click('a[href="/web/jobs"]')
        await page.wait_for_load_state("networkidle")

        # Wait for jobs page to load
        await page.wait_for_selector('h1:has-text("Automated Jobs")', timeout=10000)

    @pytest.mark.asyncio
    async def test_jobs_page_loads_correctly(self, page: Page, app, test_user_data):
        """Test that the jobs page loads correctly for authenticated users"""
        # Setup test user
        user = await self.setup_test_user(app, test_user_data)

        try:
            # Login user
            await self.login_user(page, test_user_data)

            # Navigate to jobs page
            await self.navigate_to_jobs_page(page)

            # Verify page elements are present
            await page.wait_for_selector('h1:has-text("Automated Jobs")')
            await page.wait_for_selector(
                'text="Schedule and manage automated data collection jobs"'
            )
            await page.wait_for_selector('button:has-text("Create New Job")')

            # Verify statistics cards are present
            await page.wait_for_selector('text="Total Jobs"')
            await page.wait_for_selector('text="Active Jobs"')
            await page.wait_for_selector('text="Need Attention"')
            await page.wait_for_selector('text="Last 24h Runs"')

            # Verify empty state is shown initially
            await page.wait_for_selector('text="No Automated Jobs Yet"')

        finally:
            # Cleanup
            with app.app_context():
                db = db_module.SessionLocal()
                try:
                    db.delete(user)
                    db.commit()
                finally:
                    db.close()

    @pytest.mark.asyncio
    async def test_create_job_for_new_tracker(
        self, page: Page, app, test_user_data, test_tracker_data, test_job_data
    ):
        """Test creating a new job for a newly created tracker"""
        # Setup test user and tracker
        user = await self.setup_test_user(app, test_user_data)
        tracker = await self.setup_test_tracker(app, user.id, test_tracker_data)

        try:
            # Login user
            await self.login_user(page, test_user_data)

            # Navigate to jobs page
            await self.navigate_to_jobs_page(page)

            # Click Create New Job button
            await page.click('button:has-text("Create New Job")')

            # Wait for job creation modal
            await page.wait_for_selector("#job-form-modal:not(.hidden)", timeout=5000)
            await page.wait_for_selector('h2:has-text("Create New Job")')

            # Fill job form
            await page.fill('input[name="name"]', test_job_data["name"])
            await page.select_option(
                'select[name="job_type"]', test_job_data["job_type"]
            )
            await page.select_option('select[name="tracker_id"]', str(tracker.id))
            await page.fill(
                'input[name="cron_schedule"]', test_job_data["cron_schedule"]
            )

            # Fill job-specific config based on type
            if test_job_data["job_type"] == "stock":
                await page.fill(
                    'input[name="config.symbol"]', test_job_data["config"]["symbol"]
                )
                await page.select_option(
                    'select[name="config.provider"]',
                    test_job_data["config"]["provider"],
                )
                await page.fill(
                    'input[name="config.api_key"]', test_job_data["config"]["api_key"]
                )

            # Submit form
            await page.click('button[type="submit"]:has-text("Create Job")')

            # Wait for success message
            await page.wait_for_selector(".toast.success", timeout=10000)

            # Verify modal closes
            await page.wait_for_selector("#job-form-modal.hidden", timeout=5000)

            # Verify job appears in the list
            await page.wait_for_selector(
                f'text="{test_job_data["name"]}"', timeout=10000
            )

            # Verify statistics are updated
            await page.wait_for_selector('#total-jobs-stat:has-text("1")', timeout=5000)
            await page.wait_for_selector(
                '#active-jobs-stat:has-text("1")', timeout=5000
            )

        finally:
            # Cleanup
            with app.app_context():
                db = db_module.SessionLocal()
                try:
                    # Delete jobs first (foreign key constraint)
                    jobs = db.query(JobModel).filter_by(user_id=user.id).all()
                    for job in jobs:
                        db.delete(job)

                    # Delete tracker
                    db.delete(tracker)

                    # Delete user
                    db.delete(user)

                    db.commit()
                finally:
                    db.close()

    @pytest.mark.asyncio
    async def test_job_count_accuracy(
        self, page: Page, app, test_user_data, test_tracker_data, test_job_data
    ):
        """Test that UI correctly counts the number of jobs for a user"""
        # Setup test user and tracker
        user = await self.setup_test_user(app, test_user_data)
        tracker = await self.setup_test_tracker(app, user.id, test_tracker_data)

        # Create multiple jobs directly in database
        jobs_created = []
        with app.app_context():
            db = db_module.SessionLocal()
            try:
                job_service = JobService(db, None)

                # Create 3 jobs
                for i in range(3):
                    job_data = {
                        "name": f"Test Job {i + 1}",
                        "job_type": "stock",
                        "tracker_id": tracker.id,
                        "config": {
                            "symbol": f"TEST{i + 1}",
                            "provider": "alpha_vantage",
                            "api_key": "test-key",
                        },
                        "cron_schedule": "0 9 * * *",
                        "is_active": i < 2,  # First 2 jobs active, last one inactive
                    }

                    job = job_service.create_job(user.id, job_data)
                    jobs_created.append(job)

                db.commit()
            finally:
                db.close()

        try:
            # Login user
            await self.login_user(page, test_user_data)

            # Navigate to jobs page
            await self.navigate_to_jobs_page(page)

            # Verify job counts in statistics
            await page.wait_for_selector(
                '#total-jobs-stat:has-text("3")', timeout=10000
            )
            await page.wait_for_selector(
                '#active-jobs-stat:has-text("2")', timeout=5000
            )

            # Verify job counts in header
            await page.wait_for_selector('#job-count:has-text("3")', timeout=5000)
            await page.wait_for_selector('#active-count:has-text("2")', timeout=5000)

            # Count actual job cards displayed
            job_cards = await page.query_selector_all(".job-card")
            assert len(job_cards) == 3, f"Expected 3 job cards, found {len(job_cards)}"

            # Verify each job is displayed
            for i in range(3):
                await page.wait_for_selector(f'text="Test Job {i + 1}"', timeout=5000)

        finally:
            # Cleanup
            with app.app_context():
                db = db_module.SessionLocal()
                try:
                    # Delete jobs
                    for job in jobs_created:
                        db.delete(job)

                    # Delete tracker
                    db.delete(tracker)

                    # Delete user
                    db.delete(user)

                    db.commit()
                finally:
                    db.close()

    @pytest.mark.asyncio
    async def test_job_list_display(
        self, page: Page, app, test_user_data, test_tracker_data, test_job_data
    ):
        """Test that UI correctly lists the jobs with proper information"""
        # Setup test user and tracker
        user = await self.setup_test_user(app, test_user_data)
        tracker = await self.setup_test_tracker(app, user.id, test_tracker_data)

        # Create a job directly in database
        job_created = None
        with app.app_context():
            db = db_module.SessionLocal()
            try:
                job_service = JobService(db, None)

                job_data = {
                    "name": test_job_data["name"],
                    "job_type": test_job_data["job_type"],
                    "tracker_id": tracker.id,
                    "config": test_job_data["config"],
                    "cron_schedule": test_job_data["cron_schedule"],
                    "is_active": True,
                }

                job_created = job_service.create_job(user.id, job_data)
                db.commit()
            finally:
                db.close()

        try:
            # Login user
            await self.login_user(page, test_user_data)

            # Navigate to jobs page
            await self.navigate_to_jobs_page(page)

            # Verify job card is displayed
            job_card = await page.wait_for_selector(".job-card", timeout=10000)
            assert job_card is not None, "Job card should be displayed"

            # Verify job information is displayed correctly
            await page.wait_for_selector(
                f'h3:has-text("{test_job_data["name"]}")', timeout=5000
            )
            await page.wait_for_selector(
                'text="📈 Stock"', timeout=5000
            )  # Job type badge
            await page.wait_for_selector(
                'text="● Active"', timeout=5000
            )  # Status badge
            await page.wait_for_selector(
                f'text="{test_job_data["cron_schedule"]}"', timeout=5000
            )  # Schedule
            await page.wait_for_selector(
                f'text="Tracker ID: {tracker.id}"', timeout=5000
            )  # Tracker ID

            # Verify action buttons are present
            await page.wait_for_selector(
                'button:has-text("View Details")', timeout=5000
            )
            await page.wait_for_selector('button:has-text("Run Now")', timeout=5000)

            # Test dropdown menu
            dropdown_button = await page.wait_for_selector(
                "[data-dropdown-toggle]", timeout=5000
            )
            await dropdown_button.click()

            # Verify dropdown menu items
            await page.wait_for_selector(
                'button:has-text("View Details")', timeout=5000
            )
            await page.wait_for_selector('button:has-text("Run Now")', timeout=5000)
            await page.wait_for_selector('button:has-text("Edit Job")', timeout=5000)
            await page.wait_for_selector('button:has-text("Disable Job")', timeout=5000)
            await page.wait_for_selector('button:has-text("Delete Job")', timeout=5000)

        finally:
            # Cleanup
            with app.app_context():
                db = db_module.SessionLocal()
                try:
                    if job_created:
                        db.delete(job_created)
                    db.delete(tracker)
                    db.delete(user)
                    db.commit()
                finally:
                    db.close()

    @pytest.mark.asyncio
    async def test_run_now_functionality(
        self, page: Page, app, test_user_data, test_tracker_data, test_job_data
    ):
        """Test the 'Run Now' functionality works correctly"""
        # Setup test user and tracker
        user = await self.setup_test_user(app, test_user_data)
        tracker = await self.setup_test_tracker(app, user.id, test_tracker_data)

        # Create a job directly in database
        job_created = None
        with app.app_context():
            db = db_module.SessionLocal()
            try:
                job_service = JobService(db, None)

                job_data = {
                    "name": test_job_data["name"],
                    "job_type": test_job_data["job_type"],
                    "tracker_id": tracker.id,
                    "config": test_job_data["config"],
                    "cron_schedule": test_job_data["cron_schedule"],
                    "is_active": True,
                }

                job_created = job_service.create_job(user.id, job_data)
                db.commit()
            finally:
                db.close()

        try:
            # Login user
            await self.login_user(page, test_user_data)

            # Navigate to jobs page
            await self.navigate_to_jobs_page(page)

            # Wait for job card
            await page.wait_for_selector(".job-card", timeout=10000)

            # Click "Run Now" button
            await page.click('button:has-text("Run Now")')

            # Wait for loading indicator
            await page.wait_for_selector("#loading-overlay:not(.hidden)", timeout=5000)

            # Wait for execution to complete (loading overlay to disappear)
            await page.wait_for_selector("#loading-overlay.hidden", timeout=15000)

            # Wait for success or error toast
            toast = await page.wait_for_selector(".toast", timeout=10000)
            toast_text = await toast.text_content()

            # Verify execution feedback
            assert any(
                keyword in toast_text.lower()
                for keyword in ["executed", "failed", "starting"]
            ), f"Expected execution feedback, got: {toast_text}"

        finally:
            # Cleanup
            with app.app_context():
                db = db_module.SessionLocal()
                try:
                    if job_created:
                        db.delete(job_created)
                    db.delete(tracker)
                    db.delete(user)
                    db.commit()
                finally:
                    db.close()

    @pytest.mark.asyncio
    async def test_empty_state_display(self, page: Page, app, test_user_data):
        """Test that empty state is displayed correctly when user has no jobs"""
        # Setup test user (no jobs)
        user = await self.setup_test_user(app, test_user_data)

        try:
            # Login user
            await self.login_user(page, test_user_data)

            # Navigate to jobs page
            await self.navigate_to_jobs_page(page)

            # Verify empty state is displayed
            await page.wait_for_selector('text="No Automated Jobs Yet"', timeout=10000)
            await page.wait_for_selector(
                'text="Create your first automated job"', timeout=5000
            )

            # Verify statistics show zero
            await page.wait_for_selector('#total-jobs-stat:has-text("0")', timeout=5000)
            await page.wait_for_selector(
                '#active-jobs-stat:has-text("0")', timeout=5000
            )

            # Verify no job cards are displayed
            job_cards = await page.query_selector_all(".job-card")
            assert len(job_cards) == 0, f"Expected 0 job cards, found {len(job_cards)}"

        finally:
            # Cleanup
            with app.app_context():
                db = db_module.SessionLocal()
                try:
                    db.delete(user)
                    db.commit()
                finally:
                    db.close()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
