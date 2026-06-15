"""Python view fixtures for i18n testing."""
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# I18N-1: hardcoded string in raise — should be flagged (medium confidence)
def validate_age(age: int) -> None:
    if age < 0:
        raise ValueError("Age must be a positive number")
    if age > 150:
        raise ValueError("Please enter a valid age")


# I18N-1: hardcoded string in exception with keyword — should be flagged
class UserNotFound(Exception):
    pass


def get_user(user_id: int):
    raise UserNotFound("The requested user was not found")


# I18N-2: non-locale date formatting — should be flagged
def format_date_bad(dt: datetime) -> str:
    return str(dt)


# I18N-2: non-locale date via f-string — should be flagged
def format_date_bad2(date) -> str:  # noqa: ANN001
    return f"Created: {date}"


# I18N-2: strftime without locale — should be flagged
def format_date_bad3(dt: datetime) -> str:
    return dt.strftime("%B %d, %Y")


# Should NOT be flagged — logging calls
def log_something():
    logger.debug("Debug: processing started")
    logger.info("Processing complete")
