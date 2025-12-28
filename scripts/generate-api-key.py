#!/usr/bin/env python3
"""
API Key Generation Utility

This script generates cryptographically secure API keys for the trackers application.
It supports various output formats and validates keys against security requirements.

Usage:
    python scripts/generate-api-key.py [options]

Examples:
    # Generate a single API key
    python scripts/generate-api-key.py

    # Generate multiple keys
    python scripts/generate-api-key.py --count 3

    # Generate keys with custom length
    python scripts/generate-api-key.py --length 32

    # Generate keys in environment variable format
    python scripts/generate-api-key.py --format env --count 2

    # Generate keys for specific environment
    python scripts/generate-api-key.py --format env --environment production
"""

import argparse
import secrets
import string
import sys
from typing import List


class APIKeyGenerator:
    """Generates cryptographically secure API keys with validation."""

    # Character sets for key generation
    ALPHANUMERIC = string.ascii_letters + string.digits
    ALPHANUMERIC_SYMBOLS = ALPHANUMERIC + "-_"

    def __init__(self, min_length: int = 16, max_length: int = 64):
        """
        Initialize the API key generator.

        Args:
            min_length: Minimum allowed key length
            max_length: Maximum allowed key length
        """
        self.min_length = min_length
        self.max_length = max_length

    def generate_key(self, length: int = 32, use_symbols: bool = True) -> str:
        """
        Generate a single cryptographically secure API key.

        Args:
            length: Length of the key to generate
            use_symbols: Whether to include symbols (-_) in the key

        Returns:
            Generated API key string

        Raises:
            ValueError: If length is outside allowed range
        """
        if length < self.min_length:
            raise ValueError(
                f"Key length must be at least {self.min_length} characters"
            )

        if length > self.max_length:
            raise ValueError(f"Key length must be at most {self.max_length} characters")

        # Choose character set
        charset = self.ALPHANUMERIC_SYMBOLS if use_symbols else self.ALPHANUMERIC

        # Generate cryptographically secure random key
        key = "".join(secrets.choice(charset) for _ in range(length))

        # Validate the generated key
        if not self.validate_key_security(key):
            # This should be extremely rare with proper random generation
            # but we'll retry once to be safe
            key = "".join(secrets.choice(charset) for _ in range(length))

        return key

    def generate_keys(
        self, count: int, length: int = 32, use_symbols: bool = True
    ) -> List[str]:
        """
        Generate multiple API keys.

        Args:
            count: Number of keys to generate
            length: Length of each key
            use_symbols: Whether to include symbols in keys

        Returns:
            List of generated API keys
        """
        if count < 1:
            raise ValueError("Count must be at least 1")

        if count > 100:
            raise ValueError("Count must be at most 100 for safety")

        keys = []
        for _ in range(count):
            key = self.generate_key(length, use_symbols)
            # Ensure uniqueness (extremely unlikely to have duplicates with secure random)
            while key in keys:
                key = self.generate_key(length, use_symbols)
            keys.append(key)

        return keys

    def validate_key_security(self, key: str) -> bool:
        """
        Validate that an API key meets security requirements.

        Args:
            key: API key to validate

        Returns:
            True if key meets security requirements
        """
        # Minimum length requirement
        if len(key) < self.min_length:
            return False

        # No whitespace-only keys
        if not key.strip():
            return False

        # Must contain at least one letter and one number for complexity
        has_letter = any(c.isalpha() for c in key)
        has_digit = any(c.isdigit() for c in key)

        return has_letter and has_digit


class APIKeyFormatter:
    """Formats API keys for different output formats."""

    @staticmethod
    def format_single(key: str) -> str:
        """Format a single API key."""
        return key

    @staticmethod
    def format_list(keys: List[str]) -> str:
        """Format multiple keys as a list."""
        return "\n".join(keys)

    @staticmethod
    def format_comma_separated(keys: List[str]) -> str:
        """Format keys as comma-separated values."""
        return ",".join(keys)

    @staticmethod
    def format_environment_variable(keys: List[str], environment: str = None) -> str:
        """
        Format keys as environment variable assignment.

        Args:
            keys: List of API keys
            environment: Optional environment name (e.g., 'production')

        Returns:
            Environment variable assignment string
        """
        comma_separated = APIKeyFormatter.format_comma_separated(keys)

        if environment:
            var_name = f"API_KEYS_{environment.upper()}"
        else:
            var_name = "API_KEYS"

        return f'{var_name}="{comma_separated}"'

    @staticmethod
    def format_json(keys: List[str]) -> str:
        """Format keys as JSON array."""
        import json

        return json.dumps(keys, indent=2)


def main():
    """Main entry point for the API key generator."""
    parser = argparse.ArgumentParser(
        description="Generate cryptographically secure API keys for the trackers application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Generate one 32-character key
  %(prog)s --count 3                         # Generate 3 keys
  %(prog)s --length 24                       # Generate 24-character key
  %(prog)s --format env                      # Output as environment variable
  %(prog)s --format env --environment prod   # Output as PROD_API_KEYS
  %(prog)s --format json --count 5           # Output as JSON array
  %(prog)s --no-symbols                      # Generate without symbols (-_)
        """,
    )

    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=1,
        help="Number of API keys to generate (default: 1, max: 100)",
    )

    parser.add_argument(
        "--length",
        "-l",
        type=int,
        default=32,
        help="Length of each API key (default: 32, min: 16, max: 64)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["single", "list", "comma", "env", "json"],
        default="single",
        help="Output format (default: single)",
    )

    parser.add_argument(
        "--environment",
        "-e",
        type=str,
        help="Environment name for env format (e.g., production, staging)",
    )

    parser.add_argument(
        "--no-symbols",
        action="store_true",
        help="Generate keys without symbols (only letters and numbers)",
    )

    parser.add_argument(
        "--validate",
        type=str,
        help="Validate an existing API key instead of generating new ones",
    )

    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress informational messages"
    )

    args = parser.parse_args()

    try:
        generator = APIKeyGenerator()
        formatter = APIKeyFormatter()

        # Handle validation mode
        if args.validate:
            is_valid = generator.validate_key_security(args.validate)
            if not args.quiet:
                status = "VALID" if is_valid else "INVALID"
                print(f"API key validation: {status}", file=sys.stderr)
                if not is_valid:
                    print(
                        f"Key must be at least {generator.min_length} characters and contain letters and numbers",
                        file=sys.stderr,
                    )
            sys.exit(0 if is_valid else 1)

        # Validate arguments
        if args.count < 1 or args.count > 100:
            print("Error: Count must be between 1 and 100", file=sys.stderr)
            sys.exit(1)

        if args.length < generator.min_length or args.length > generator.max_length:
            print(
                f"Error: Length must be between {generator.min_length} and {generator.max_length}",
                file=sys.stderr,
            )
            sys.exit(1)

        if args.environment and args.format != "env":
            print(
                "Error: --environment can only be used with --format env",
                file=sys.stderr,
            )
            sys.exit(1)

        # Generate API keys
        if not args.quiet:
            print(
                f"Generating {args.count} API key(s) of length {args.length}...",
                file=sys.stderr,
            )

        use_symbols = not args.no_symbols

        if args.count == 1:
            keys = [generator.generate_key(args.length, use_symbols)]
        else:
            keys = generator.generate_keys(args.count, args.length, use_symbols)

        # Format output
        if args.format == "single":
            if args.count == 1:
                output = formatter.format_single(keys[0])
            else:
                output = formatter.format_list(keys)
        elif args.format == "list":
            output = formatter.format_list(keys)
        elif args.format == "comma":
            output = formatter.format_comma_separated(keys)
        elif args.format == "env":
            output = formatter.format_environment_variable(keys, args.environment)
        elif args.format == "json":
            output = formatter.format_json(keys)
        else:
            output = formatter.format_list(keys)

        # Output the result
        print(output)

        # Print usage instructions if not quiet
        if not args.quiet and args.format != "env":
            print("\nUsage instructions:", file=sys.stderr)
            if args.count == 1:
                print(
                    f'Set environment variable: API_KEYS="{keys[0]}"', file=sys.stderr
                )
            else:
                comma_separated = formatter.format_comma_separated(keys)
                print(
                    f'Set environment variable: API_KEYS="{comma_separated}"',
                    file=sys.stderr,
                )
            print(
                f"Or add to .env file: API_KEYS={formatter.format_comma_separated(keys)}",
                file=sys.stderr,
            )

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
