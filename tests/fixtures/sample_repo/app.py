# PLANTED VIOLATION: hardcoded secrets (security domain)
# These are fake test credentials — do not use.
API_KEY = "sk-1234567890abcdef1234567890abcdef"  # noqa: S105
DATABASE_URL = "postgresql://admin:password123@localhost/mydb"  # noqa: S105
SECRET_TOKEN = "ghp_abcdef1234567890abcdef1234567890ab"  # noqa: S105


def get_user(user_id: str) -> tuple | None:
    # PLANTED VIOLATION: SQL injection (security domain)
    import sqlite3  # noqa: PLC0415

    conn = sqlite3.connect("app.db")
    # Unsanitised interpolation — injectable
    cursor = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")  # noqa: S608
    return cursor.fetchone()


def render_greeting(name: str) -> str:
    # Normal code — no violation
    return f"Hello, {name}!"
