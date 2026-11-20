#!/usr/bin/env python3
"""
Secure Host Ping Utility.

Demonstrates OWASP Top 10 defensive practices for executing system utilities:
- Strict allowlist input validation (A03: Injection)
- Argument array execution without shell invocation (A03: Injection)
- Trusted binary resolution via os.defpath (A05: Security Misconfiguration)
- Safe resource limits and timeouts (A04: Insecure Design / DoS prevention)
"""

import ipaddress
import os
import platform
import re
import shutil
import subprocess  # nosec B404 - Audited: used strictly with shell=False and validated argument arrays
import sys

# Safe defaults and hard bounds to prevent resource exhaustion or hanging processes
DEFAULT_PACKET_COUNT = 4
MIN_PACKET_COUNT = 1
MAX_PACKET_COUNT = 10

DEFAULT_TIMEOUT_SECONDS = 5
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 30

MAX_HOSTNAME_LENGTH = 253

# Strict RFC 1123 hostname regex (prevents flag injection like '-c' or shell metacharacters)
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def validate_target(target: str) -> str:
    """
    Validates that the input is strictly a valid IPv4/IPv6 address or RFC 1123 hostname.
    Rejects leading hyphens to prevent argument/flag injection into the ping binary.
    """
    if not isinstance(target, str):
        raise ValueError("Target must be a string.")

    cleaned = target.strip()

    if not cleaned:
        raise ValueError("Target cannot be empty.")

    if len(cleaned) > MAX_HOSTNAME_LENGTH:
        raise ValueError(f"Target exceeds maximum length of {MAX_HOSTNAME_LENGTH} characters.")

    # Explicitly block leading dashes to prevent option/flag injection (e.g., "-f" for flood ping)
    if cleaned.startswith("-"):
        raise ValueError("Invalid target: cannot start with a hyphen.")

    # 1. Check if it is a valid IPv4 or IPv6 address
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        if ip_obj.is_unspecified or ip_obj.is_multicast:
            raise ValueError("Unspecified or multicast IP addresses are not permitted.")
        return str(ip_obj)
    except ValueError as ip_err:
        if "not permitted" in str(ip_err):
            raise

    # 2. Check if it is a valid DNS hostname
    if not HOSTNAME_PATTERN.match(cleaned):
        raise ValueError("Invalid hostname format. Only alphanumeric characters, hyphens, and dots are allowed.")

    return cleaned


def _validate_bounds(count: int, timeout: int) -> None:
    """Ensures packet count and timeout values stay within safe integer limits."""
    if not isinstance(count, int) or isinstance(count, bool) or not (MIN_PACKET_COUNT <= count <= MAX_PACKET_COUNT):
        raise ValueError(f"Packet count must be an integer between {MIN_PACKET_COUNT} and {MAX_PACKET_COUNT}.")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not (MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS):
        raise ValueError(f"Timeout must be an integer between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}.")


def build_ping_command(
    target: str,
    count: int = DEFAULT_PACKET_COUNT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> list[str]:
    """
    Constructs a parameterized argument list for the OS ping utility.
    Resolves the binary strictly from os.defpath to prevent PATH hijacking.
    """
    safe_target = validate_target(target)
    _validate_bounds(count, timeout)

    # Resolve strictly using os.defpath rather than the untrusted user PATH
    ping_binary = shutil.which("ping", path=os.defpath)
    if not ping_binary:
        raise RuntimeError("System 'ping' utility could not be found in default system paths.")

    system_os = platform.system().lower()

    if system_os == "windows":
        # Windows: -n (count), -w (timeout in milliseconds)
        return [
            ping_binary,
            "-n", str(count),
            "-w", str(timeout * 1000),
            safe_target,
        ]
    elif system_os == "darwin":
        # macOS: -c (count), -W (timeout in milliseconds)
        return [
            ping_binary,
            "-c", str(count),
            "-W", str(timeout * 1000),
            safe_target,
        ]
    else:
        # Linux / POSIX: -c (count), -W (timeout in seconds), '--' ends option parsing
        return [
            ping_binary,
            "-c", str(count),
            "-W", str(timeout),
            "--",
            safe_target,
        ]


def execute_ping(
    target: str,
    count: int = DEFAULT_PACKET_COUNT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> int:
    """
    Executes the ping command securely using subprocess without a shell.
    """
    command = build_ping_command(target, count=count, timeout=timeout)

    # Provide a minimal, sanitized environment to the child process
    safe_env = {"PATH": os.defpath}

    # Calculate an outer process timeout slightly larger than total packet timeouts
    max_execution_time = (count * timeout) + 5

    try:
        # nosec B603: binary is resolved from os.defpath, shell=False, and all arguments are strictly validated
        result = subprocess.run(  # nosec B603
            command,
            shell=False,          # CRITICAL: Never use shell=True with user input
            check=False,          # Handle non-zero exit codes (e.g., host unreachable) gracefully
            capture_output=True,  # Capture output rather than letting child inherit raw streams
            text=True,
            timeout=max_execution_time,
            env=safe_env,
        )

        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print(result.stderr.strip(), file=sys.stderr)

        return result.returncode

    except subprocess.TimeoutExpired:
        print(f"Error: Ping operation timed out after {max_execution_time} seconds.", file=sys.stderr)
        return 124
    except OSError as exc:
        print(f"System error executing ping: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    try:
        raw_input_host = input("Enter a hostname or IP address to ping: ")
        validated_host = validate_target(raw_input_host)
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.", file=sys.stderr)
        sys.exit(130)
    except ValueError as err:
        # Return clean validation feedback without exposing internal stack traces
        print(f"Validation Error: {err}", file=sys.stderr)
        sys.exit(2)

    print(f"Pinging {validated_host}...\n")
    exit_code = execute_ping(validated_host)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()