#!/usr/bin/env python3
"""
Secure Ping Utility

Features:
- Validates hostname/IP input
- Prevents command injection by avoiding shell=True
- Uses safe defaults
- Handles errors gracefully
- No hardcoded secrets
"""

import ipaddress
import platform
import re
import shutil
import subprocess  # nosec B404 - required for controlled system ping execution
import sys


MAX_HOSTNAME_LENGTH = 253

# Conservative allowlist for values passed to ping
SAFE_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9.\-:]+$")


def is_valid_hostname(hostname: str) -> bool:
    """
    Validate a DNS hostname according to common RFC constraints.
    """
    if not hostname or len(hostname) > MAX_HOSTNAME_LENGTH:
        return False

    if hostname.endswith("."):
        hostname = hostname[:-1]

    labels = hostname.split(".")

    hostname_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
    )

    return all(hostname_regex.match(label) for label in labels)


def is_valid_target(target: str) -> bool:
    """
    Accept either a valid IP address or hostname.
    """
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return is_valid_hostname(target)


def ping_host(target: str) -> int:
    """
    Ping the specified host using a safe subprocess invocation.
    Returns the subprocess return code.
    """
    # Defense in depth: ensure only expected characters can
    # ever be passed to the operating-system command.
    if not SAFE_TARGET_PATTERN.fullmatch(target):
        raise ValueError("Invalid target format.")

    ping_executable = shutil.which("ping")
    if ping_executable is None:
        print(
            "Error: 'ping' command not found on this system.",
            file=sys.stderr,
        )
        return 1

    count_flag = "-n" if platform.system().lower() == "windows" else "-c"

    command = [
        ping_executable,
        count_flag,
        "4",  # safe default
        target,
    ]

    try:
        result = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        print(result.stdout)

        if result.stderr:
            print(result.stderr, file=sys.stderr)

        return result.returncode

    except subprocess.TimeoutExpired:
        print("Error: Ping request timed out.", file=sys.stderr)
        return 1


def main() -> None:
    target = input("Enter a hostname or IP address to ping: ").strip()

    if not is_valid_target(target):
        print(
            "Error: Invalid hostname or IP address.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        exit_code = ping_host(target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if exit_code == 0:
        print("Ping completed successfully.")
    else:
        print("Ping failed.")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()