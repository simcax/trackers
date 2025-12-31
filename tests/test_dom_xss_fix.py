"""
Tests for DOM XSS vulnerability fix in dashboard.js.

This module tests that the DOM XSS vulnerability in the toast notification
system has been properly fixed by using textContent instead of innerHTML.
"""

import re

import pytest


class TestDOMXSSFix:
    """Test DOM XSS vulnerability fix."""

    def test_dashboard_js_uses_textcontent(self):
        """Test that dashboard.js uses textContent instead of innerHTML for user input."""

        # Read the dashboard.js file
        with open("static/js/dashboard.js", "r") as f:
            dashboard_content = f.read()

        # Check that the vulnerable innerHTML usage has been replaced
        # Look for the specific line that was vulnerable

        # The fix should create elements and use textContent
        assert "messageSpan.textContent = message;" in dashboard_content

        # Should not have the vulnerable innerHTML pattern for user messages
        vulnerable_pattern = r"innerHTML\s*=\s*`[^`]*\$\{message\}"
        assert not re.search(vulnerable_pattern, dashboard_content)

        # Should create elements safely
        assert "document.createElement(" in dashboard_content
        assert "appendChild(" in dashboard_content

    def test_xss_prevention_principle(self):
        """Test that demonstrates the XSS prevention principle."""

        # Simulate the vulnerable approach (what we fixed)
        malicious_message = "<script>alert('XSS')</script>Hello"

        # Vulnerable approach (what we had before):
        # element.innerHTML = `<span>${message}</span>`
        # This would execute the script

        # Safe approach (what we implemented):
        # span = document.createElement('span')
        # span.textContent = message
        # This treats everything as text

        # Test the principle: textContent escapes HTML automatically
        import html

        # When using textContent, HTML is automatically escaped
        safe_content = html.escape(malicious_message)

        # Verify dangerous content is neutralized
        assert "&lt;script&gt;" in safe_content
        assert "alert" in safe_content  # Still there but as text
        assert "<script>" not in safe_content  # Not executable HTML

    def test_toast_creation_safety(self):
        """Test that the toast creation method is safe."""

        # Read the dashboard.js file to verify the implementation
        with open("static/js/dashboard.js", "r") as f:
            content = f.read()

        # Find the showTemporaryToast method
        toast_method_start = content.find("showTemporaryToast(message, type)")
        assert toast_method_start != -1, "showTemporaryToast method not found"

        # Extract the method (rough approximation)
        method_end = content.find("\n    }", toast_method_start + 1000)  # Look ahead
        if method_end == -1:
            method_end = len(content)

        toast_method = content[toast_method_start:method_end]

        # Verify safe practices in the method
        assert "createElement(" in toast_method
        assert "textContent = message" in toast_method
        assert "appendChild(" in toast_method

        # Should not have direct innerHTML assignment with user content
        # (innerHTML is OK for controlled content like icons)
        lines = toast_method.split("\n")
        for line in lines:
            if "innerHTML" in line and "message" in line:
                # This would be vulnerable
                assert False, f"Found vulnerable innerHTML usage: {line.strip()}"

    def test_controlled_content_vs_user_content(self):
        """Test that controlled content (icons) vs user content (messages) are handled differently."""

        with open("static/js/dashboard.js", "r") as f:
            content = f.read()

        # Find the toast creation section
        toast_section_start = content.find("showTemporaryToast(message, type)")
        toast_section_end = content.find("\n    }", toast_section_start + 2000)
        toast_section = content[toast_section_start:toast_section_end]

        # Controlled content (icons) can use innerHTML safely
        assert "iconSvg.innerHTML = icon" in toast_section

        # User content (messages) should use textContent
        assert "textContent = message" in toast_section

        # Verify the structure is safe
        assert "appendChild(iconSvg)" in toast_section
        assert "appendChild(messageSpan)" in toast_section


if __name__ == "__main__":
    pytest.main([__file__])
