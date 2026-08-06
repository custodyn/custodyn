"""
Demo: File Manager Agent with Custodyn Protection
--------------------------------------------------
An AI agent that organizes, moves, and deletes files.
The classic failure: "clean up my downloads" → agent
deletes files that weren't meant to go.

Real incident: A Meta AI safety director told her OpenClaw
agent to confirm before acting — it deleted her entire inbox
anyway. She had to physically run to her computer to stop it.
(February 2026)

Without Custodyn: deletes happen instantly, no recovery.
With Custodyn: destructive actions require human approval.

Install: pip install custodyn
Docs:    https://custodyn.app/docs
"""

import os
import shutil
from custodyn import Custodyn, PRESETS

agent = Custodyn(
    agent_id="file-agent-001",
    api_key="as_live_your_key_here",
    server_url="https://custodyn.app",
    policies=PRESETS["strict"],  # strict = block all deletes + writes
    fail_closed=True
)


def read_file(path: str) -> str:
    """Read a file — safe, no Custodyn check needed."""
    with open(path, "r") as f:
        return f.read()


def move_file(src: str, dst: str) -> dict:
    """Move a file — checked by Custodyn before executing."""
    result = agent.check(
        action="move_file",
        category="write",        # "write" = medium risk
        target=src,
        parameters={"src": src, "dst": dst}
    )
    if not result["allowed"]:
        print(f"  [CUSTODYN] Blocked — {result['reason']}")
        return {"status": "blocked"}

    shutil.move(src, dst)
    return {"status": "moved", "from": src, "to": dst}


def delete_file(path: str) -> dict:
    """Delete a file — blocked by Custodyn until human approves."""
    result = agent.check(
        action="delete_file",
        category="delete",       # "delete" = high risk
        target=path,
        parameters={"path": path, "type": "file"}
    )
    if not result["allowed"]:
        print(f"  [CUSTODYN] Blocked — {result['reason']}")
        print(f"  [CUSTODYN] Approve at: https://custodyn.app/dashboard")
        return {"status": "blocked"}

    os.remove(path)
    return {"status": "deleted", "path": path}


def delete_folder(path: str) -> dict:
    """Delete a folder recursively — always blocked, requires explicit approval."""
    result = agent.check(
        action="delete_folder",
        category="delete",
        target=path,
        parameters={"path": path, "type": "folder", "recursive": True}
    )
    if not result["allowed"]:
        print(f"  [CUSTODYN] Blocked — {result['reason']}")
        print(f"  [CUSTODYN] Approve at: https://custodyn.app/dashboard")
        return {"status": "blocked"}

    shutil.rmtree(path)
    return {"status": "deleted", "path": path}


if __name__ == "__main__":
    print("=== File Manager Agent Demo ===\n")

    print("Task 1: Read /etc/hostname (safe — no check)")
    print(f"  Content: {read_file('/etc/hostname').strip()}")

    print("\nTask 2: Move report.pdf to /archive/")
    print(move_file("/home/user/report.pdf", "/home/user/archive/report.pdf"))

    print("\nTask 3: Delete old_logs.txt")
    print(delete_file("/home/user/old_logs.txt"))

    print("\nTask 4: Delete /backups/ folder (recursive)")
    print(delete_folder("/home/user/backups/"))

    print("\n--- Session Summary ---")
    stats = agent.stats()
    print(f"Total actions: {stats['total']}")
    print(f"Allowed: {stats['allowed']} | Blocked: {stats['blocked']}")
    print(f"Full audit log: https://custodyn.app/dashboard")
