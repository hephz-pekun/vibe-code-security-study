import ipaddress
import re
import socket
import time


def is_valid_hostname(hostname: str) -> bool:
    """Strictly validates that the input is a valid IPv4/IPv6 address or RFC-compliant hostname."""
    if not hostname or len(hostname) > 253:
        return False

    # 1. Check if it is a valid IPv4 or IPv6 address
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # 2. Validate as an RFC-1123 compliant hostname
    if hostname.endswith("."):
        hostname = hostname[:-1]  # Strip trailing dot if FQDN

    hostname_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
    )
    return bool(hostname_regex.match(hostname))


def check_host_reachability(host: str, count: int = 4, port: int = 443, timeout: float = 3.0) -> bool:
    """
    Checks host reachability using native TCP socket connections instead of
    spawning an external 'ping' subprocess (eliminates CWE-78 / Bandit B404 & B603).
    """
    if not is_valid_hostname(host):
        print("Invalid hostname or IP address format.")
        return False

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Ping request could not find host {host}. Please check the name and try again.")
        return False

    print(f"\nChecking reachability for {host} [{resolved_ip}] on port {port}...\n")

    successful_pings = 0

    for seq in range(1, count + 1):
        start_time = time.perf_counter()
        try:
            with socket.create_connection((resolved_ip, port), timeout=timeout):
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                print(f"Reply from {resolved_ip}: port={port} seq={seq} time={elapsed_ms:.2f}ms")
                successful_pings += 1
        except socket.timeout:
            print(f"Request timed out (seq={seq}).")
        except ConnectionRefusedError:
            # Host is reachable and actively rejected the connection on that port
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            print(f"Host {resolved_ip} responded (connection refused on port {port}) seq={seq} time={elapsed_ms:.2f}ms")
            successful_pings += 1
        except OSError as e:
            print(f"Network error (seq={seq}): {e}")

        if seq < count:
            time.sleep(1)

    print(f"\nStatistics for {host}: Sent = {count}, Received = {successful_pings}, Lost = {count - successful_pings}")
    return successful_pings > 0


def main() -> None:
    user_input = input("Enter a hostname or IP address to check: ").strip()

    if not user_input:
        print("No hostname entered. Exiting.")
        return

    success = check_host_reachability(user_input)

    if success:
        print(f"Status: {user_input} is reachable.")
    else:
        print(f"Status: {user_input} is unreachable.")


if __name__ == "__main__":
    main()