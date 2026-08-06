"""
Demo: Code Deployment Agent with Custodyn Protection
-----------------------------------------------------
An AI agent that manages code deployments — pushes to GitHub,
deploys to production, and manages branches.

Real incident: An AI agent's code was rejected by an open source
maintainer. The agent published a hit piece attacking the developer.
(Early 2026)

Without Custodyn: agent can force-push to main, delete branches,
or deploy broken code to production without any human review.
With Custodyn: production deployments and destructive git operations
require explicit human approval before any action is taken.

Install: pip install custodyn
Docs:    https://custodyn.app/docs
"""

import subprocess
import requests
from custodyn import Custodyn, PRESETS

agent = Custodyn(
    agent_id="deploy-agent-001",
    api_key="as_live_your_key_here",
    server_url="https://custodyn.app",
    policies=PRESETS["strict"],
    fail_closed=True   # if dashboard unreachable, never auto-deploy to production
)

GITHUB_TOKEN = "your_github_token"
REPO = "your-org/your-repo"


def _git(args: list[str]) -> str:
    result = subprocess.run(
        ["git"] + args, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _github(method: str, endpoint: str, data: dict = None) -> dict:
    url = f"https://api.github.com/repos/{REPO}/{endpoint}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    return requests.request(method, url, headers=headers, json=data).json()


def run_tests() -> bool:
    """Run test suite — safe, always allowed, no Custodyn check."""
    print("  [CI] Running test suite...")
    result = subprocess.run(["pytest", "-q", "--tb=short"], capture_output=True)
    return result.returncode == 0


def push_branch(branch: str) -> dict:
    """Push to a feature branch — safe, no approval needed."""
    output = _git(["push", "origin", branch])
    return {"pushed": branch, "output": output}


def create_pull_request(branch: str, title: str, body: str) -> dict:
    """Open a PR — safe, a human will review it anyway."""
    return _github("POST", "pulls", {
        "title": title, "body": body,
        "head": branch, "base": "main"
    })


def delete_branch(branch: str) -> dict:
    """Delete a branch — checked by Custodyn before execution."""
    result = agent.check(
        action="delete_branch",
        category="delete",
        target=branch,
        parameters={"branch": branch, "repo": REPO}
    )
    if not result["allowed"]:
        print(f"  [CUSTODYN] Blocked — {result['reason']}")
        return {"status": "blocked"}

    return _github("DELETE", f"git/refs/heads/{branch}")


def deploy_production(version: str) -> dict:
    """Deploy to production — always blocked until a human approves."""
    result = agent.check(
        action="deploy_production",
        category="execute",
        target="production",
        parameters={"version": version, "repo": REPO, "environment": "production"}
    )
    if not result["allowed"]:
        print(f"  [CUSTODYN] Blocked — {result['reason']}")
        print(f"  [CUSTODYN] Approve at: https://custodyn.app/dashboard")
        return {"status": "blocked"}

    print(f"  [DEPLOY] Deploying {version} to production...")
    return _github("POST", "deployments", {
        "ref": version,
        "environment": "production",
        "auto_merge": False
    })


def force_push_main() -> dict:
    """Force push to main — blocked, rewrites history for all collaborators."""
    result = agent.check(
        action="force_push_main",
        category="delete",      # treated as destructive
        target="main",
        parameters={"branch": "main", "force": True, "repo": REPO}
    )
    if not result["allowed"]:
        print(f"  [CUSTODYN] Blocked — {result['reason']}")
        print(f"  [CUSTODYN] Approve at: https://custodyn.app/dashboard")
        return {"status": "blocked"}

    output = _git(["push", "--force", "origin", "main"])
    return {"status": "pushed", "output": output}


if __name__ == "__main__":
    print("=== Deployment Agent Demo ===\n")

    print("Task 1: Run tests (safe — no check)")
    print(f"  Tests passed: {run_tests()}")

    print("\nTask 2: Push feature branch (safe — no check)")
    print(push_branch("feature/new-dashboard"))

    print("\nTask 3: Open pull request (safe — no check)")
    pr = create_pull_request(
        branch="feature/new-dashboard",
        title="Add new dashboard",
        body="Automated PR from deployment agent."
    )
    print(f"  PR #{pr.get('number')}: {pr.get('title')}")

    print("\nTask 4: Delete merged branch (blocked)")
    print(delete_branch("feature/old-experiment"))

    print("\nTask 5: Deploy v2.1.0 to production (blocked)")
    print(deploy_production("v2.1.0"))

    print("\nTask 6: Force push to main (blocked)")
    print(force_push_main())

    print("\n--- Session Summary ---")
    stats = agent.stats()
    print(f"Total actions: {stats['total']}")
    print(f"Allowed: {stats['allowed']} | Blocked: {stats['blocked']}")
    print(f"Full audit log: https://custodyn.app/dashboard")
