"""
Cybersecurity Log Analyzer & Brute-Force Detector

This tool analyzes authentication logs and identifies:
- Successful login attempts
- Failed login attempts
- Suspicious IP addresses
- Possible brute-force activity

This project is intended for defensive security analysis
using authorized or simulated log data.
"""

import argparse
import re
from collections import Counter


FAILED_LOGIN_PATTERN = re.compile(
    r"^(?P<timestamp>\S+\s+\S+)\s+"
    r"LOGIN_FAILED\s+"
    r"user=(?P<user>\S+)\s+"
    r"ip=(?P<ip>\S+)$"
)

SUCCESS_LOGIN_PATTERN = re.compile(
    r"^(?P<timestamp>\S+\s+\S+)\s+"
    r"LOGIN_SUCCESS\s+"
    r"user=(?P<user>\S+)\s+"
    r"ip=(?P<ip>\S+)$"
)


def read_logs(file_path):
    """Read log lines from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {file_path}")
        return []


def analyze_logs(log_lines, threshold):
    """Analyze authentication events."""
    failed_ips = Counter()
    successful_ips = Counter()
    failed_users = Counter()
    successful_users = Counter()

    failed_events = []
    successful_events = []
    ignored_lines = 0

    for line in log_lines:

        failed_match = FAILED_LOGIN_PATTERN.match(line)

        if failed_match:
            data = failed_match.groupdict()

            failed_ips[data["ip"]] += 1
            failed_users[data["user"]] += 1

            failed_events.append(data)
            continue

        success_match = SUCCESS_LOGIN_PATTERN.match(line)

        if success_match:
            data = success_match.groupdict()

            successful_ips[data["ip"]] += 1
            successful_users[data["user"]] += 1

            successful_events.append(data)
            continue

        ignored_lines += 1

    suspicious_ips = {
        ip: count
        for ip, count in failed_ips.items()
        if count >= threshold
    }

    return {
        "failed_ips": failed_ips,
        "successful_ips": successful_ips,
        "failed_users": failed_users,
        "successful_users": successful_users,
        "failed_events": failed_events,
        "successful_events": successful_events,
        "suspicious_ips": suspicious_ips,
        "ignored_lines": ignored_lines,
    }


def generate_report(results, threshold, output_file):
    """Generate a human-readable security report."""

    failed_ips = results["failed_ips"]
    successful_ips = results["successful_ips"]
    failed_users = results["failed_users"]
    successful_users = results["successful_users"]
    suspicious_ips = results["suspicious_ips"]

    total_failed = len(results["failed_events"])
    total_successful = len(results["successful_events"])

    with open(output_file, "w", encoding="utf-8") as report:

        report.write("CYBERSECURITY LOG ANALYSIS REPORT\n")
        report.write("=" * 45 + "\n\n")

        report.write("SUMMARY\n")
        report.write("-" * 45 + "\n")
        report.write(f"Successful login events : {total_successful}\n")
        report.write(f"Failed login events     : {total_failed}\n")
        report.write(f"Detection threshold     : {threshold}\n")
        report.write(
            f"Suspicious IP addresses : {len(suspicious_ips)}\n"
        )
        report.write(
            f"Ignored/unrecognized    : {results['ignored_lines']}\n\n"
        )

        report.write("FAILED LOGIN SOURCES\n")
        report.write("-" * 45 + "\n")

        if failed_ips:
            for ip, count in failed_ips.most_common():
                report.write(f"{ip:<20} {count} failed attempts\n")
        else:
            report.write("No failed login activity detected.\n")

        report.write("\nSUSPICIOUS IP ADDRESSES\n")
        report.write("-" * 45 + "\n")

        if suspicious_ips:
            for ip, count in sorted(
                suspicious_ips.items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                report.write(
                    f"[ALERT] {ip} -> "
                    f"{count} failed attempts "
                    f"(threshold: {threshold})\n"
                )
        else:
            report.write("No IP exceeded the detection threshold.\n")

        report.write("\nFAILED LOGIN USERS\n")
        report.write("-" * 45 + "\n")

        if failed_users:
            for user, count in failed_users.most_common():
                report.write(f"{user:<20} {count} failures\n")
        else:
            report.write("No failed login users detected.\n")

        report.write("\nSUCCESSFUL LOGIN SOURCES\n")
        report.write("-" * 45 + "\n")

        if successful_ips:
            for ip, count in successful_ips.most_common():
                report.write(f"{ip:<20} {count} successful logins\n")
        else:
            report.write("No successful login activity detected.\n")

        report.write("\nSECURITY ASSESSMENT\n")
        report.write("-" * 45 + "\n")

        if suspicious_ips:
            report.write(
                "POSSIBLE BRUTE-FORCE ACTIVITY DETECTED.\n"
            )
            report.write(
                "Recommended actions:\n"
            )
            report.write(
                "1. Investigate the suspicious source IP addresses.\n"
            )
            report.write(
                "2. Review affected user accounts.\n"
            )
            report.write(
                "3. Check authentication logs for additional activity.\n"
            )
            report.write(
                "4. Consider rate limiting or account lockout controls.\n"
            )
        else:
            report.write(
                "No brute-force pattern exceeded the configured threshold.\n"
            )


def print_summary(results, threshold):
    """Display a summary in the terminal."""

    print("\n" + "=" * 50)
    print("CYBERSECURITY LOG ANALYZER")
    print("=" * 50)

    print(f"Successful logins : {len(results['successful_events'])}")
    print(f"Failed logins     : {len(results['failed_events'])}")
    print(f"Detection threshold: {threshold}")

    print("\nFailed login sources:")

    if results["failed_ips"]:
        for ip, count in results["failed_ips"].most_common():
            print(f"  {ip} -> {count}")
    else:
        print("  None")

    print("\nSuspicious IP addresses:")

    if results["suspicious_ips"]:
        for ip, count in sorted(
            results["suspicious_ips"].items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print(
                f"  [ALERT] {ip} -> "
                f"{count} failed attempts"
            )
    else:
        print("  None")

    print("\nAnalysis complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious login activity."
    )

    parser.add_argument(
        "logfile",
        help="Path to the authentication log file"
    )

    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=5,
        help="Failed login threshold for suspicious IP detection (default: 5)"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="security_report.txt",
        help="Output report filename"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        print("[ERROR] Threshold must be at least 1.")
        return

    logs = read_logs(args.logfile)

    if not logs:
        print("[ERROR] No log data available.")
        return

    results = analyze_logs(logs, args.threshold)

    print_summary(results, args.threshold)

    generate_report(
        results,
        args.threshold,
        args.output
    )

    print(f"\nReport saved to: {args.output}")


if __name__ == "__main__":
    main()
