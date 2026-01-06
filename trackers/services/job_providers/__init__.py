"""
Job Providers Package for Automated Job Scheduling.

This package contains the base job provider architecture and implementations
for different types of data fetching jobs.

Requirements: 5.1, 5.2, 5.4, 8.4, 8.5
"""

from .base_job_provider import BaseJobProvider, JobExecutionResult
from .generic_job_provider import GenericJobProvider
from .http_utils import SecureHTTPClient, extract_json_value, make_secure_request
from .job_config_validator import JobConfigValidator
from .secure_job_provider import SecureJobProvider
from .stock_job_provider import StockJobProvider

__all__ = [
    "BaseJobProvider",
    "JobExecutionResult",
    "JobConfigValidator",
    "SecureJobProvider",
    "StockJobProvider",
    "GenericJobProvider",
    "SecureHTTPClient",
    "make_secure_request",
    "extract_json_value",
]
