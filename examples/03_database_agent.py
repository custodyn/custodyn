"""
Demo: Database Agent with Custodyn Protection
----------------------------------------------
An AI agent that queries and manages a database.
The nightmare: agent runs DROP TABLE or DELETE without
WHERE clause on a live production database.

Real incident: Replit's AI agent deleted an entire company's
production database during a code freeze — then tried to cover
it up and rated its own failure 95/100 on the catastrophe scale.
(2025)

Without Custodyn: one bad query, everything is gone.
With Custodyn: destructive SQL is blocked until a human approves.

Install: pip install custodyn
Docs:    https://custodyn.app/docs
"""

import sqlite3
from custodyn import Custodyn, PRESETS

agent = Custodyn(
    agent_id="db-agent-001",
    api_key="as_live_your_key_here",
    server_url="https://custodyn.app",
    policies=PRESETS["balanced"],
    fail_closed=True
)

DB_PATH = "production.db"


def _run_sql(sql: str, params: tuple = ()) -> list:
    """Execute SQL directly against the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.commit()
    conn.close()
    return rows


def _classify(sql: str) -> str:
    """Detect SQL intent from the statement."""
    verb = sql.strip().upper().split()[0]
    if verb == "SELECT":
        return "read"
    if verb in ("INSERT", "UPDATE"):
        return "write"
    if verb in ("DELETE", "DROP", "TRUNCATE", "ALTER"):
        return "delete"
    return "execute"


def query(sql: str, params: tuple = ()) -> list:
    """
    Run a SQL query — Custodyn checks it before execution.
    SELECT runs freely. Anything destructive requires approval.
    """
    category = _classify(sql)

    if category == "read":
        # Safe — run directly, no check needed
        return _run_sql(sql, params)

    result = agent.check(
        action=f"sql_{category}",
        category=category,           # maps to Custodyn risk levels automatically
        target=DB_PATH,
        parameters={"sql": sql, "params": list(params)}
    )

    if not result["allowed"]:
        print(f"  [CUSTODYN] SQL blocked — {result['reason']}")
        print(f"  [CUSTODYN] Approve at: https://custodyn.app/dashboard")
        return []

    return _run_sql(sql, params)


if __name__ == "__main__":
    print("=== Database Agent Demo ===\n")

    print("Task 1: SELECT — fetch users (safe, runs immediately)")
    rows = query("SELECT id, name FROM users LIMIT 5")
    print(f"  Rows returned: {len(rows)}")

    print("\nTask 2: INSERT — add new user (write, logged)")
    query(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        ("Atul Sharma", "atul@custodyn.app")
    )

    print("\nTask 3: DELETE — remove inactive users (blocked, approval required)")
    query("DELETE FROM users WHERE last_login < '2024-01-01'")

    print("\nTask 4: DROP TABLE — destroy sessions table (blocked, approval required)")
    query("DROP TABLE sessions")

    print("\n--- Session Summary ---")
    stats = agent.stats()
    print(f"Total actions: {stats['total']}")
    print(f"Allowed: {stats['allowed']} | Blocked: {stats['blocked']}")
    print(f"Risk breakdown: {stats['risk_breakdown']}")
    print(f"Full audit log: https://custodyn.app/dashboard")
