"""
Demo: Financial Agent with Custodyn Protection
-----------------------------------------------
An AI agent that processes payments and transfers.
Without Custodyn: money moves instantly, no questions asked.
With Custodyn: every payment is checked against policy —
high-value transactions are blocked until a human approves.

Install: pip install custodyn
Docs:    https://custodyn.app/docs
"""

from custodyn import Custodyn, PRESETS

# Initialize Custodyn — point to your live dashboard
agent = Custodyn(
    agent_id="fin-agent-001",
    api_key="as_live_your_key_here",
    server_url="https://custodyn.app",
    policies=PRESETS["balanced"],  # blocks payments + bulk deletes by default
    fail_closed=True               # if dashboard unreachable, block all critical actions
)


def _send_payment(to: str, amount: float, currency: str = "USD") -> dict:
    """Raw payment — calls your payment gateway (Stripe, Razorpay, etc.)"""
    print(f"  [PAYMENT GATEWAY] Sending {currency} {amount:.2f} to {to}")
    # Real code: stripe.PaymentIntent.create(...) or razorpay_client.order.create(...)
    return {"status": "success", "tx_id": "txn_abc123", "amount": amount}


def _transfer_funds(from_account: str, to_account: str, amount: float) -> dict:
    """Raw transfer — calls your bank API"""
    print(f"  [BANK API] Transferring ${amount:.2f}: {from_account} → {to_account}")
    # Real code: bank_client.transfer(from_account, to_account, amount)
    return {"status": "success", "reference": "REF-789XYZ"}


def send_payment(to: str, amount: float, currency: str = "USD") -> dict:
    """Send a payment — intercepted by Custodyn before execution."""
    result = agent.check(
        action="send_payment",
        category="pay",          # "pay" category = critical risk by default
        target=to,
        parameters={"amount": amount, "currency": currency}
    )
    if not result["allowed"]:
        print(f"  [CUSTODYN] Blocked — {result['reason']}")
        print(f"  [CUSTODYN] Approve at: https://custodyn.app/dashboard")
        return {"status": "blocked", "reason": result["reason"]}

    return _send_payment(to, amount, currency)


def transfer_funds(from_account: str, to_account: str, amount: float) -> dict:
    """Transfer funds between accounts — intercepted by Custodyn."""
    result = agent.check(
        action="transfer_funds",
        category="pay",
        target=to_account,
        parameters={"from": from_account, "to": to_account, "amount": amount}
    )
    if not result["allowed"]:
        print(f"  [CUSTODYN] Blocked — {result['reason']}")
        print(f"  [CUSTODYN] Approve at: https://custodyn.app/dashboard")
        return {"status": "blocked", "reason": result["reason"]}

    return _transfer_funds(from_account, to_account, amount)


if __name__ == "__main__":
    print("=== Financial Agent Demo ===\n")

    print("Task 1: Pay $49 vendor invoice")
    print(send_payment("vendor@acme.com", 49.00))

    print("\nTask 2: Pay $12,000 contractor invoice")
    print(send_payment("contractor@freelance.io", 12000.00))

    print("\nTask 3: Transfer $500 between accounts")
    print(transfer_funds("ops-account", "reserve-account", 500.00))

    print("\n--- Session Summary ---")
    stats = agent.stats()
    print(f"Total actions: {stats['total']}")
    print(f"Allowed: {stats['allowed']} | Blocked: {stats['blocked']}")
    print(f"Full audit log: https://custodyn.app/dashboard")
