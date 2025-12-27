"""
Validation functions for tracker values.

This module provides validation and sanitization functions for tracker value operations,
ensuring data integrity and proper error handling.

Validates: Requirements 6.1, 6.2, 6.3, 7.1
"""

import re
from datetime import datetime
from typing import Dict, List

from sqlalchemy.orm import Session

from trackers.models.tracker_model import TrackerModel


def validate_date_format(date_str: str) -> bool:
    """
    Validate ISO 8601 date format (YYYY-MM-DD).

    Args:
        date_str: Date string to validate

    Returns:
        True if date format is valid, False otherwise

    Validates: Requirements 6.2
    """
    if not date_str or not isinstance(date_str, str):
        return False

    # Check basic format with regex
    date_pattern = r"^\d{4}-\d{2}-\d{2}$"
    if not re.match(date_pattern, date_str):
        return False

    # Validate actual date values
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def validate_value_data(data: Dict) -> List[str]:
    """
    Validate required fields and data types for tracker value data.

    Args:
        data: Dictionary containing tracker value data

    Returns:
        List of error messages (empty if validation passes)

    Validates: Requirements 2.4, 6.3
    """
    errors = []

    if not isinstance(data, dict):
        errors.append("Request data must be a JSON object")
        return errors

    # Check required fields
    required_fields = ["date", "value"]
    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")
        elif data[field] is None:
            errors.append(f"Field '{field}' cannot be null")

    # Validate date format if present
    if "date" in data and data["date"] is not None:
        if not validate_date_format(data["date"]):
            errors.append("Date must be in ISO 8601 format (YYYY-MM-DD)")

    # Validate value content if present
    if "value" in data and data["value"] is not None:
        if not isinstance(data["value"], str):
            errors.append("Value must be a string")
        elif not data["value"].strip():
            errors.append("Value cannot be empty or whitespace only")

    return errors


def validate_tracker_exists(db: Session, tracker_id: int) -> bool:
    """
    Check if tracker exists before creating values.

    Args:
        db: Database session
        tracker_id: ID of the tracker to validate

    Returns:
        True if tracker exists, False otherwise

    Validates: Requirements 6.1
    """
    if not isinstance(tracker_id, int) or tracker_id <= 0:
        return False

    tracker = db.query(TrackerModel).filter(TrackerModel.id == tracker_id).first()
    return tracker is not None


def sanitize_value_input(value: str) -> str:
    """
    Clean and sanitize value input to prevent XSS and other security issues.

    Args:
        value: Raw value input string

    Returns:
        Sanitized value string

    Validates: Requirements 7.1
    """
    if not isinstance(value, str):
        return ""

    # Strip leading/trailing whitespace
    sanitized = value.strip()

    # Basic XSS prevention - remove potentially dangerous characters
    # This is a simple approach; for production, consider using a proper sanitization library
    dangerous_chars = ["<", ">", '"', "'", "&"]
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")

    # Remove null bytes and control characters
    sanitized = "".join(
        char for char in sanitized if ord(char) >= 32 or char in ["\n", "\r", "\t"]
    )

    return sanitized


def validate_update_data(data: Dict) -> List[str]:
    """
    Validate data for tracker value updates (only value field required).

    Args:
        data: Dictionary containing update data

    Returns:
        List of error messages (empty if validation passes)

    Validates: Requirements 4.3
    """
    errors = []

    if not isinstance(data, dict):
        errors.append("Request data must be a JSON object")
        return errors

    # For updates, only value is required
    if "value" not in data:
        errors.append("Missing required field: value")
    elif data["value"] is None:
        errors.append("Field 'value' cannot be null")
    elif not isinstance(data["value"], str):
        errors.append("Value must be a string")
    elif not data["value"].strip():
        errors.append("Value cannot be empty or whitespace only")

    return errors
