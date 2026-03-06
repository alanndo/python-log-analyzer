#!/usr/bin/env python3
"""
Simple authentication log analyzer.

Features:
- Detects failed SSH login attempts
- Counts failures by IP and username
- Flags suspicious IPs over a threshold
- Detects successful logins after repeated failures
- Exports summary as JSON

Designed for educational and defensive use.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, TypeAlias


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

TOP_N_RESULTS = 10

FAILED_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for "
    r"(invalid user )?(?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

SUCCESS_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted password for "
    r"(?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Type alias for a parsed log event
LogEvent: TypeAlias = dict[str, str]


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious login activity."
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the log file to analyze.",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=5,
        help="Minimum failed attempts from an IP before flagging it as suspicious. Default: 5",
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional path to save results as JSON.",
    )
    return parser.parse_args()


# ------------------------------------------------------------------
# Core analysis
# ------------------------------------------------------------------

def analyze_log(file_path: Path, threshold: int) -> dict[str, Any]:
    failed_by_ip: Counter[str] = Counter()
    failed_by_user: Counter[str] = Counter()
    success_by_ip: Counter[str] = Counter()

    failure_events: list[LogEvent] = []
    success_events: list[LogEvent] = []

    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as log_file:
            # errors="ignore" silently drops non-UTF-8 bytes, which are
            # common in corrupted or rotated log files.
            for line in log_file:
                failed_match = FAILED_PATTERN.search(line)
                if failed_match:
                    event: LogEvent = {
                        "timestamp": failed_match.group("timestamp"),
                        "username": failed_match.group("username"),
                        "ip": failed_match.group("ip"),
                    }
                    failure_events.append(event)
                    failed_by_ip[event["ip"]] += 1
                    failed_by_user[event["username"]] += 1

                elif success_match := SUCCESS_PATTERN.search(line):
                    # elif makes mutual exclusivity explicit — a line can't
                    # be both a failure and a success.
                    event = {
                        "timestamp": success_match.group("timestamp"),
                        "username": success_match.group("username"),
                        "ip": success_match.group("ip"),
                    }
                    success_events.append(event)
                    success_by_ip[event["ip"]] += 1

    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {file_path}", file=sys.stderr)
        sys.exit(1)

    suspicious_ips = {
        ip: count
        for ip, count in failed_by_ip.items()
        if count >= threshold
    }

    # Cross-reference successful logins against the overall failure counts
    # for each IP, rather than tracking per-session state during parsing.
    success_after_failures = [
        {
            "timestamp": event["timestamp"],
            "username": event["username"],
            "ip": event["ip"],
            "prior_failed_attempts": failed_by_ip[event["ip"]],
        }
        for event in success_events
        if event["ip"] in failed_by_ip
    ]

    return {
        "log_file": str(file_path),
        "failed_attempts_total": sum(failed_by_ip.values()),
        "successful_logins_total": sum(success_by_ip.values()),
        "top_failed_ips": failed_by_ip.most_common(TOP_N_RESULTS),
        "top_targeted_usernames": failed_by_user.most_common(TOP_N_RESULTS),
        "suspicious_ips": suspicious_ips,
        "success_after_failures": success_after_failures,
    }


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------

def _print_section(title: str, items: list, format_item) -> None:
    """Print a titled section, falling back to a 'none found' message."""
    print(f"\n{title}:")
    if items:
        for item in items:
            print(f"  - {format_item(item)}")
    else:
        print("  None detected.")


def print_report(results: dict[str, Any]) -> None:
    print("\n=== Authentication Log Analysis Report ===")
    print(f"Log file: {results['log_file']}")
    print(f"Total failed attempts:    {results['failed_attempts_total']}")
    print(f"Total successful logins:  {results['successful_logins_total']}")

    _print_section(
        "Top failed IPs",
        results["top_failed_ips"],
        lambda item: f"{item[0]}: {item[1]} failed attempts",
    )

    _print_section(
        "Top targeted usernames",
        results["top_targeted_usernames"],
        lambda item: f"{item[0]}: {item[1]} failed attempts",
    )

    _print_section(
        "Suspicious IPs (over threshold)",
        list(results["suspicious_ips"].items()),
        lambda item: f"{item[0]}: {item[1]} failed attempts",
    )

    _print_section(
        "Successful logins after prior failures",
        results["success_after_failures"],
        lambda e: (
            f"{e['timestamp']} | {e['username']} from {e['ip']} "
            f"(prior failures: {e['prior_failed_attempts']})"
        ),
    )


# ------------------------------------------------------------------
# Output
# ------------------------------------------------------------------

def save_json(results: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as outfile:
        json.dump(results, outfile, indent=4)
    print(f"\n[INFO] Results written to: {output_path}")


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    file_path = Path(args.file)
    results = analyze_log(file_path, args.threshold)
    print_report(results)

    if args.output:
        save_json(results, Path(args.output))


if __name__ == "__main__":
    main()
