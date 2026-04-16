"""
Main entry point for Lab 11 and Assignment 11.

Usage:
    python main.py              # Run lab parts 1-4
    python main.py --part 1     # Run only Part 1 (attacks)
    python main.py --part 2     # Run only Part 2 (guardrails)
    python main.py --part 3     # Run only Part 3 (testing pipeline)
    python main.py --part 4     # Run only Part 4 (HITL design)
    python main.py --part 5     # Run Assignment 11 defense pipeline
"""
import argparse
import asyncio

from core.config import setup_api_key


async def part1_attacks():
    """Part 1: Attack an unprotected agent."""
    print("\n" + "=" * 60)
    print("PART 1: Attack Unprotected Agent")
    print("=" * 60)

    from agents.agent import create_unsafe_agent, test_agent
    from attacks.attacks import run_attacks, generate_ai_attacks

    agent, runner = create_unsafe_agent()
    await test_agent(agent, runner)

    print("\n--- Running manual attacks (TODO 1) ---")
    await run_attacks(agent, runner)

    print("\n--- Generating AI attacks (TODO 2) ---")
    await generate_ai_attacks()


async def part2_guardrails():
    """Part 2: Implement and test guardrails."""
    print("\n" + "=" * 60)
    print("PART 2: Guardrails")
    print("=" * 60)

    print("\n--- Part 2A: Input Guardrails ---")
    from guardrails.input_guardrails import (
        test_injection_detection,
        test_topic_filter,
        test_input_plugin,
    )
    test_injection_detection()
    print()
    test_topic_filter()
    print()
    await test_input_plugin()

    print("\n--- Part 2B: Output Guardrails ---")
    from guardrails.output_guardrails import test_content_filter, _init_judge
    _init_judge()
    test_content_filter()

    print("\n--- Part 2C: NeMo Guardrails ---")
    try:
        from guardrails.nemo_guardrails import init_nemo, test_nemo_guardrails

        init_nemo()
        await test_nemo_guardrails()
    except ImportError:
        print("NeMo Guardrails not available. Skipping Part 2C.")
    except Exception as exc:
        print(f"NeMo error: {exc}. Skipping Part 2C.")


async def part3_testing():
    """Part 3: Before/after comparison plus the assignment-style pipeline."""
    print("\n" + "=" * 60)
    print("PART 3: Security Testing Pipeline")
    print("=" * 60)

    from testing.testing import run_comparison, print_comparison, SecurityTestPipeline

    print("\n--- TODO 10: Before/After Comparison ---")
    unprotected, protected = await run_comparison()
    print_comparison(unprotected, protected)

    print("\n--- TODO 11: Security Test Pipeline ---")
    pipeline = SecurityTestPipeline()
    results = await pipeline.run_all()
    pipeline.print_report(results)
    audit_path = pipeline.export_audit_log()
    print(f"Audit log exported to: {audit_path}")


def part4_hitl():
    """Part 4: HITL design."""
    print("\n" + "=" * 60)
    print("PART 4: Human-in-the-Loop Design")
    print("=" * 60)

    from hitl.hitl import test_confidence_router, test_hitl_points

    print("\n--- TODO 12: Confidence Router ---")
    test_confidence_router()

    print("\n--- TODO 13: HITL Decision Points ---")
    test_hitl_points()


async def part5_assignment():
    """Assignment 11: Run the production defense-in-depth pipeline only."""
    print("\n" + "=" * 60)
    print("PART 5: Assignment 11 Defense-in-Depth Pipeline")
    print("=" * 60)

    from testing.testing import SecurityTestPipeline

    pipeline = SecurityTestPipeline()
    results = await pipeline.run_all()
    pipeline.print_report(results)
    audit_path = pipeline.export_audit_log("audit_log.json")
    print(f"Audit log exported to: {audit_path}")


async def main(parts=None):
    """Run the full lab or selected parts."""
    setup_api_key()

    if parts is None:
        parts = [1, 2, 3, 4]

    for part in parts:
        if part == 1:
            await part1_attacks()
        elif part == 2:
            await part2_guardrails()
        elif part == 3:
            await part3_testing()
        elif part == 4:
            part4_hitl()
        elif part == 5:
            await part5_assignment()
        else:
            print(f"Unknown part: {part}")

    print("\n" + "=" * 60)
    print("Run complete. Check the printed results and audit log.")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Lab 11 and Assignment 11: Guardrails, HITL, and defense-in-depth"
    )
    parser.add_argument(
        "--part",
        type=int,
        choices=[1, 2, 3, 4, 5],
        help="Run a specific part. Use 5 for the Assignment 11 pipeline.",
    )
    args = parser.parse_args()

    if args.part:
        asyncio.run(main(parts=[args.part]))
    else:
        asyncio.run(main())
