# Intentionally vulnerable snippet for integration-test fixtures — NOT production code.

import sqlite3

# Planted fake credential — triggers gitleaks in integration tests
# fmt: off
aws_secret_key = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105
# fmt: on


def get_user(username: str) -> dict:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection: user input concatenated directly into query
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")  # noqa: S608
    row = cursor.fetchone()
    conn.close()
    return {"user": row}
