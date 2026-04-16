"""
Lab 11 - Part 4: Human-in-the-Loop Design
  TODO 12: Confidence Router
  TODO 13: Design 3 HITL decision points
"""
from dataclasses import dataclass


HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""

    action: str
    confidence: float
    reason: str
    priority: str
    requires_human: bool


class ConfidenceRouter:
    """Route responses based on confidence and business risk.

    This router is needed because guardrails reduce harm, but they do not
    remove uncertainty. HITL provides a final escalation path for high-stakes
    or low-confidence situations.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float, action_type: str = "general") -> RoutingDecision:
        """Return the appropriate routing decision for the current response."""
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )

        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence - needs review",
                priority="normal",
                requires_human=True,
            )

        return RoutingDecision(
            action="escalate",
            confidence=confidence,
            reason="Low confidence - escalating",
            priority="high",
            requires_human=True,
        )


hitl_decision_points = [
    {
        "id": 1,
        "name": "Large transfer authorization",
        "trigger": "Transfer amount is greater than 50,000,000 VND or the beneficiary is new.",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Account balance, transaction history, beneficiary details, fraud score, and OTP status.",
        "example": "A customer asks the agent to transfer 120,000,000 VND to a never-before-seen account.",
    },
    {
        "id": 2,
        "name": "Sensitive profile update review",
        "trigger": "Customer requests a phone, email, or address change and identity signals are incomplete or ambiguous.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "KYC status, recent login activity, verification challenge results, and the full conversation transcript.",
        "example": "The user wants to change the recovery phone number but fails one of the identity checks.",
    },
    {
        "id": 3,
        "name": "Low-confidence policy answer audit",
        "trigger": "The agent answers a banking policy question with confidence below 0.9 or cites uncertain fee/rate information.",
        "hitl_model": "human-on-the-loop",
        "context_needed": "Draft response, source document timestamp, confidence score, and any judge feedback about accuracy or tone.",
        "example": "The agent answers an ATM withdrawal fee question but is unsure whether the latest pricing update is reflected.",
    },
]


def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
