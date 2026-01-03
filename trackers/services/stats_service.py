"""
Statistics Service for system metrics and counts.

This module provides the StatsService class for gathering system statistics
including user counts, tracker counts, and authentication method breakdowns.
"""

import logging
from typing import Any, Dict

from sqlalchemy import func
from sqlalchemy.orm import Session

from trackers.models.tracker_model import TrackerModel
from trackers.models.user_model import UserModel

logger = logging.getLogger(__name__)


class StatsService:
    """
    Service class for gathering system statistics.

    This class provides methods to collect various system metrics including
    user counts, tracker counts, and authentication method breakdowns.
    """

    def __init__(self, db_session: Session):
        """
        Initialize Stats Service with database session.

        Args:
            db_session: SQLAlchemy database session
        """
        self.db = db_session

    def get_system_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive system statistics.

        Returns:
            Dict containing system statistics including:
            - total_users: Total number of users
            - google_users: Number of users with Google OAuth
            - email_users: Number of users with email/password auth
            - total_trackers: Total number of trackers
            - active_users: Users with at least one tracker
        """
        try:
            stats = {}

            # Total user count
            stats["total_users"] = self.db.query(UserModel).count()

            # Google OAuth users (have google_user_id)
            stats["google_users"] = (
                self.db.query(UserModel)
                .filter(UserModel.google_user_id.isnot(None))
                .count()
            )

            # Email/password users (have password_hash)
            stats["email_users"] = (
                self.db.query(UserModel)
                .filter(UserModel.password_hash.isnot(None))
                .count()
            )

            # Users with both authentication methods
            stats["dual_auth_users"] = (
                self.db.query(UserModel)
                .filter(
                    UserModel.google_user_id.isnot(None),
                    UserModel.password_hash.isnot(None),
                )
                .count()
            )

            # Total tracker count
            stats["total_trackers"] = self.db.query(TrackerModel).count()

            # Active users (users who have created at least one tracker)
            stats["active_users"] = (
                self.db.query(UserModel).join(TrackerModel).distinct().count()
            )

            # Users by authentication method (more detailed breakdown)
            stats["auth_breakdown"] = self._get_auth_method_breakdown()

            logger.debug(f"System stats collected: {stats}")
            return stats

        except Exception as e:
            logger.error(f"Error collecting system stats: {str(e)}")
            return {
                "total_users": 0,
                "google_users": 0,
                "email_users": 0,
                "dual_auth_users": 0,
                "total_trackers": 0,
                "active_users": 0,
                "auth_breakdown": {},
                "error": str(e),
            }

    def _get_auth_method_breakdown(self) -> Dict[str, int]:
        """
        Get detailed breakdown of authentication methods.

        Returns:
            Dict with authentication method counts
        """
        try:
            breakdown = {}

            # Google OAuth only (has google_user_id but no password_hash)
            breakdown["google_only"] = (
                self.db.query(UserModel)
                .filter(
                    UserModel.google_user_id.isnot(None),
                    UserModel.password_hash.is_(None),
                )
                .count()
            )

            # Email/password only (has password_hash but no google_user_id)
            breakdown["email_only"] = (
                self.db.query(UserModel)
                .filter(
                    UserModel.password_hash.isnot(None),
                    UserModel.google_user_id.is_(None),
                )
                .count()
            )

            # Both methods (has both google_user_id and password_hash)
            breakdown["both_methods"] = (
                self.db.query(UserModel)
                .filter(
                    UserModel.google_user_id.isnot(None),
                    UserModel.password_hash.isnot(None),
                )
                .count()
            )

            # Neither method (edge case - shouldn't normally exist)
            breakdown["no_auth"] = (
                self.db.query(UserModel)
                .filter(
                    UserModel.google_user_id.is_(None),
                    UserModel.password_hash.is_(None),
                )
                .count()
            )

            return breakdown

        except Exception as e:
            logger.error(f"Error getting auth method breakdown: {str(e)}")
            return {}

    def get_user_stats(self) -> Dict[str, Any]:
        """
        Get user-specific statistics.

        Returns:
            Dict containing user statistics
        """
        try:
            stats = {}

            # Total users
            stats["total"] = self.db.query(UserModel).count()

            # Users by verification status
            stats["verified_users"] = (
                self.db.query(UserModel)
                .filter(UserModel.email_verified == True)
                .count()
            )

            stats["unverified_users"] = (
                self.db.query(UserModel)
                .filter(UserModel.email_verified == False)
                .count()
            )

            # Users with profile pictures
            stats["users_with_pictures"] = (
                self.db.query(UserModel)
                .filter(UserModel.profile_picture_url.isnot(None))
                .count()
            )

            return stats

        except Exception as e:
            logger.error(f"Error collecting user stats: {str(e)}")
            return {"error": str(e)}

    def get_tracker_stats(self) -> Dict[str, Any]:
        """
        Get tracker-specific statistics.

        Returns:
            Dict containing tracker statistics
        """
        try:
            stats = {}

            # Total trackers
            stats["total"] = self.db.query(TrackerModel).count()

            # Trackers by user (top 5 most active users)
            top_users = (
                self.db.query(
                    UserModel.email, func.count(TrackerModel.id).label("tracker_count")
                )
                .join(TrackerModel)
                .group_by(UserModel.id, UserModel.email)
                .order_by(func.count(TrackerModel.id).desc())
                .limit(5)
                .all()
            )

            stats["top_users"] = [
                {"email": user.email, "tracker_count": user.tracker_count}
                for user in top_users
            ]

            # Average trackers per user
            if stats["total"] > 0:
                active_user_count = (
                    self.db.query(UserModel).join(TrackerModel).distinct().count()
                )
                stats["avg_trackers_per_user"] = (
                    round(stats["total"] / active_user_count, 2)
                    if active_user_count > 0
                    else 0
                )
            else:
                stats["avg_trackers_per_user"] = 0

            return stats

        except Exception as e:
            logger.error(f"Error collecting tracker stats: {str(e)}")
            return {"error": str(e)}

    def get_quick_stats(self) -> Dict[str, int]:
        """
        Get quick statistics for dashboard display.

        Returns:
            Dict with basic counts for display in stats boxes
        """
        try:
            return {
                "total_users": self.db.query(UserModel).count(),
                "google_users": self.db.query(UserModel)
                .filter(UserModel.google_user_id.isnot(None))
                .count(),
                "email_users": self.db.query(UserModel)
                .filter(UserModel.password_hash.isnot(None))
                .count(),
                "total_trackers": self.db.query(TrackerModel).count(),
            }
        except Exception as e:
            logger.error(f"Error collecting quick stats: {str(e)}")
            return {
                "total_users": 0,
                "google_users": 0,
                "email_users": 0,
                "total_trackers": 0,
            }
