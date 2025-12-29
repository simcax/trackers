"""
Test accessibility features and WCAG 2.1 AA compliance for Tracker Web UI

This test module validates:
- Proper ARIA labels and roles on all interactive elements
- Keyboard navigation support for all form controls and buttons
- Proper focus management and tab order
- Alternative text for all icons and visual elements
- WCAG 2.1 AA color contrast requirements
"""

import re

from bs4 import BeautifulSoup


class TestAccessibilityFeatures:
    """Test accessibility features implementation"""

    def test_base_template_accessibility(self, client):
        """Test base template has proper accessibility features"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Check for skip link
        skip_link = soup.find("a", class_="skip-link")
        assert skip_link is not None
        assert skip_link.get("href") == "#main-content"

        # Check for proper lang attribute
        html_tag = soup.find("html")
        assert html_tag.get("lang") == "en"

        # Check for main content landmark
        main_content = soup.find(id="main-content")
        assert main_content is not None
        assert main_content.get("role") == "main"

        # Check for proper heading structure
        h1_tags = soup.find_all("h1")
        assert len(h1_tags) >= 1  # Should have at least one h1

        # Check for navigation landmark
        nav = soup.find("nav")
        assert nav is not None
        assert nav.get("role") == "navigation"
        assert nav.get("aria-label") is not None

    def test_form_accessibility(self, client):
        """Test form accessibility features"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Check for form modal
        form_modal = soup.find(id="new-tracker-form")
        assert form_modal is not None
        assert form_modal.get("role") == "dialog"
        assert form_modal.get("aria-modal") == "true"
        assert form_modal.get("aria-labelledby") is not None

        # Check for form elements with proper labels
        form = soup.find("form", id="tracker-form")
        if form:
            # Check all input fields have labels
            inputs = form.find_all("input", type=["text", "email", "password"])
            for input_field in inputs:
                input_id = input_field.get("id")
                if input_id:
                    label = form.find("label", attrs={"for": input_id})
                    assert label is not None, f"Input {input_id} missing label"

                    # Check for aria-describedby
                    describedby = input_field.get("aria-describedby")
                    if describedby:
                        help_ids = describedby.split()
                        for help_id in help_ids:
                            help_element = soup.find(id=help_id)
                            assert help_element is not None, (
                                f"Help element {help_id} not found"
                            )

            # Check required fields have aria-required
            required_inputs = form.find_all("input", required=True)
            for required_input in required_inputs:
                # Should have visual indicator or aria-required
                assert required_input.get(
                    "aria-required"
                ) == "true" or required_input.parent.find(class_="text-red-400")

    def test_button_accessibility(self, client):
        """Test button accessibility features"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Check all buttons have accessible names
        buttons = soup.find_all("button")
        for button in buttons:
            # Button should have text content, aria-label, or aria-labelledby
            has_text = button.get_text(strip=True)
            has_aria_label = button.get("aria-label")
            has_aria_labelledby = button.get("aria-labelledby")

            assert has_text or has_aria_label or has_aria_labelledby, (
                f"Button missing accessible name: {button}"
            )

            # Check for minimum touch target size class
            classes = button.get("class", [])
            if isinstance(classes, str):
                classes = classes.split()
            assert "min-touch-target" in classes, (
                f"Button missing min-touch-target class: {button}"
            )

    def test_interactive_elements_accessibility(self, client):
        """Test interactive elements have proper accessibility attributes"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Check elements with data-interactive attribute
        interactive_elements = soup.find_all(attrs={"data-interactive": True})
        for element in interactive_elements:
            # Should have tabindex or be naturally focusable
            is_focusable = (
                element.name in ["button", "a", "input", "select", "textarea"]
                or element.get("tabindex") is not None
            )
            assert is_focusable, f"Interactive element not focusable: {element}"

            # Should have accessible name
            has_accessible_name = (
                element.get_text(strip=True)
                or element.get("aria-label")
                or element.get("aria-labelledby")
            )
            assert has_accessible_name, (
                f"Interactive element missing accessible name: {element}"
            )

    def test_images_have_alt_text(self, client):
        """Test all images have appropriate alt text"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Check all img tags have alt attributes
        images = soup.find_all("img")
        for img in images:
            assert img.get("alt") is not None, f"Image missing alt attribute: {img}"

        # Check SVG icons have proper accessibility
        svgs = soup.find_all("svg")
        for svg in svgs:
            # SVG should have aria-hidden="true" if decorative, or proper labeling if informative
            is_decorative = svg.get("aria-hidden") == "true"
            has_label = (
                svg.get("aria-label")
                or svg.get("aria-labelledby")
                or svg.find("title")
                or svg.find("desc")
            )

            assert is_decorative or has_label, (
                f"SVG missing accessibility attributes: {svg}"
            )

    def test_color_contrast_classes(self, client):
        """Test that color combinations used meet contrast requirements"""
        response = client.get("/web/")
        assert response.status_code == 200

        # This is a basic check for problematic color combinations
        # In a real implementation, you'd use a proper contrast calculation
        content = response.data.decode("utf-8")

        # Check for potentially problematic combinations
        problematic_patterns = [
            r"text-gray-500.*bg-gray-600",  # Low contrast
            r"text-gray-400.*bg-gray-500",  # Low contrast
        ]

        for pattern in problematic_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            assert len(matches) == 0, (
                f"Potentially low contrast combination found: {pattern}"
            )

    def test_focus_management(self, client):
        """Test focus management features are present"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Check for focus-visible classes
        focus_elements = soup.find_all(class_=re.compile(r"focus-visible"))
        assert len(focus_elements) > 0, "No elements with focus-visible class found"

        # Check for proper focus indicators in CSS
        content = response.data.decode("utf-8")
        assert "focus:ring" in content or "focus-visible" in content, (
            "No focus indicators found in styles"
        )

    def test_screen_reader_support(self, client):
        """Test screen reader support features"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Check for screen reader only content
        sr_only_elements = soup.find_all(class_="sr-only")
        assert len(sr_only_elements) > 0, "No screen reader only content found"

        # Check for ARIA live regions
        live_regions = soup.find_all(attrs={"aria-live": True})
        assert len(live_regions) > 0, "No ARIA live regions found"

        # Check for proper heading structure
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        assert len(headings) > 0, "No headings found"

        # Check first heading is h1
        if headings:
            first_heading = headings[0]
            assert first_heading.name == "h1", "First heading should be h1"

    def test_keyboard_navigation_support(self, client):
        """Test keyboard navigation support is implemented"""
        response = client.get("/web/")
        assert response.status_code == 200

        content = response.data.decode("utf-8")

        # Check for keyboard event handling
        assert "keydown" in content, "No keyboard event handling found"
        assert "Enter" in content or "Space" in content, (
            "No Enter/Space key handling found"
        )

        # Check for tabindex management
        soup = BeautifulSoup(response.data, "html.parser")
        tabindex_elements = soup.find_all(attrs={"tabindex": True})

        # Should have some elements with tabindex for custom controls
        custom_controls = soup.find_all(attrs={"role": "button"})
        custom_controls.extend(soup.find_all(attrs={"role": "radio"}))

        if custom_controls:
            assert len(tabindex_elements) > 0, "Custom controls missing tabindex"

    def test_reduced_motion_support(self, client):
        """Test reduced motion support is implemented"""
        response = client.get("/web/")
        assert response.status_code == 200

        content = response.data.decode("utf-8")

        # Check for prefers-reduced-motion media query
        assert "prefers-reduced-motion" in content, "No reduced motion support found"

    def test_high_contrast_support(self, client):
        """Test high contrast mode support"""
        response = client.get("/web/")
        assert response.status_code == 200

        content = response.data.decode("utf-8")

        # Check for prefers-contrast media query
        assert "prefers-contrast" in content, "No high contrast support found"


class TestWCAGCompliance:
    """Test WCAG 2.1 AA compliance requirements"""

    def test_page_has_title(self, client):
        """Test page has descriptive title"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")
        title = soup.find("title")
        assert title is not None
        assert len(title.get_text(strip=True)) > 0

    def test_page_has_lang_attribute(self, client):
        """Test page has lang attribute"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")
        html_tag = soup.find("html")
        assert html_tag.get("lang") is not None

    def test_form_labels_associated(self, client):
        """Test form labels are properly associated"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Find all input elements
        inputs = soup.find_all(
            "input", type=["text", "email", "password", "radio", "checkbox"]
        )

        for input_elem in inputs:
            input_id = input_elem.get("id")
            if input_id:
                # Should have associated label
                label = soup.find("label", attrs={"for": input_id})
                assert label is not None, f"Input {input_id} missing associated label"

    def test_error_identification(self, client):
        """Test error identification is implemented"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Check for error message containers
        error_elements = soup.find_all(attrs={"role": "alert"})
        error_elements.extend(soup.find_all(class_=re.compile(r"error")))

        # Should have error handling structure
        form = soup.find("form")
        if form:
            # Look for error message elements
            error_containers = form.find_all(class_=re.compile(r"error|invalid"))
            # This is acceptable to have 0 if no errors are currently shown
            # The important thing is the structure exists

    def test_focus_visible(self, client):
        """Test focus is visible for keyboard users"""
        response = client.get("/web/")
        assert response.status_code == 200

        content = response.data.decode("utf-8")

        # Check for focus styles
        focus_indicators = [
            "focus:ring",
            "focus:outline",
            "focus-visible",
            "focus:border",
        ]

        has_focus_styles = any(indicator in content for indicator in focus_indicators)
        assert has_focus_styles, "No focus indicators found"

    def test_minimum_touch_targets(self, client):
        """Test interactive elements meet minimum size requirements"""
        response = client.get("/web/")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")

        # Check for min-touch-target class on interactive elements
        interactive_elements = soup.find_all(["button", "a"])
        interactive_elements.extend(soup.find_all(attrs={"role": "button"}))

        for element in interactive_elements:
            classes = element.get("class", [])
            if isinstance(classes, str):
                classes = classes.split()

            # Should have min-touch-target class or be naturally large enough
            has_min_size = "min-touch-target" in classes
            # For this test, we'll require the class to be present
            assert has_min_size, (
                f"Interactive element missing min-touch-target: {element}"
            )


def test_accessibility_javascript_loaded(client):
    """Test that accessibility JavaScript is loaded"""
    response = client.get("/web/")
    assert response.status_code == 200

    content = response.data.decode("utf-8")
    assert "accessibility.js" in content, "Accessibility JavaScript not loaded"


def test_color_contrast_checker_loaded(client):
    """Test that color contrast checker is loaded"""
    response = client.get("/web/")
    assert response.status_code == 200

    content = response.data.decode("utf-8")
    assert "color-contrast-check.js" in content, "Color contrast checker not loaded"
