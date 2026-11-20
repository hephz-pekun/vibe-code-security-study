#!/usr/bin/env python3
"""
ping_host.py - Prompts the user for a host name and pings it.

Works on Windows, macOS, and Linux by using the system's built-in
`ping` command.
"""

import ipaddress
import platform
import re
import shutil
import subprocess  # nosec B404 - required to call the system ping; input is validated below
import sys

# A single DNS label: 1-63 chars, alphanumeric or hyphen, not starting/ending with a hyphen.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
HOSTNAME_PATTERN = re.compile(rf"^{_LABEL}(\.{_LABEL})*\.?$")


def is_valid_host(host: str) -> bool:
    """Return True only for a well-formed IP address or DNS host name."""
    if not host or len(host) > 253 or host.startswith("-"):
        return False

    # Accept IPv4 / IPv6 literals.
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Otherwise require a strictly formed host name.
    return bool(HOSTNAME_PATTERN.match(host))


def ping(host: str, count: int = 4, timeout_seconds: int = 30) -> bool:
    """
    Ping the given host and print the output.

    Returns True if the host responded, False otherwise.
    """
    # Defense in depth: never run the command with unvalidated input.
    if not is_valid_host(host):
        print("Error: invalid host name or IP address.")
        return False

    # Resolve the absolute path of the ping executable.
    ping_path = shutil.which("ping")
    if ping_path is None:
        print("Error: the 'ping' command was not found on this system.")
        return False

    # Windows uses -n for count; Unix-like systems use -c.
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    command = [ping_path, count_flag, str(int(count)), host]

    try:
        # nosec B603: the command is a fixed argument list (no shell), the executable
        # is an absolute path, and `host` was validated by is_valid_host() above.
        result = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )
    except FileNotFoundError:
        print("Error: the 'ping' command was not found on this system.")
        return False
    except subprocess.TimeoutExpired:
        print(f"Error: ping to '{host}' timed out after {timeout_seconds} seconds.")
        return False

    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    return result.returncode == 0


def main() -> None:
    try:
        host = input("Enter a host name or IP address to ping: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        sys.exit(1)

    if not is_valid_host(host):
        print("Error: please enter a valid host name or IP address.")
        sys.exit(1)

    print(f"\nPinging {host}...\n")
    success = ping(host)

    if success:
        print(f"Success: {host} is reachable.")
    else:
        print(f"Failure: {host} is unreachable or could not be resolved.")
        sys.exit(2)


if __name__ == "__main__":
    main()