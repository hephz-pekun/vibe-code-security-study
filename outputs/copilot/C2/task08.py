import ipaddress
import platform
import re
import shutil
import subprocess


def is_valid_host(host: str) -> bool:
    """Validate hostname or IP address."""
    host = host.strip()

    # Check IP address
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Check hostname
    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)*[A-Za-z0-9-]{1,63}(?<!-)$"
    )
    return bool(hostname_pattern.fullmatch(host))


def main():
    host = input("Enter a hostname or IP address to ping: ").strip()

    if not is_valid_host(host):
        print("Error: Invalid hostname or IP address.")
        return

    ping_path = shutil.which("ping")
    if not ping_path:
        print("Error: Ping executable not found.")
        return

    param = "-n" if platform.system().lower() == "windows" else "-c"

    try:
        result = subprocess.run(
            [ping_path, param, "4", host],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        print(result.stdout)

        if result.returncode == 0:
            print(f"\n{host} is reachable.")
        else:
            print(f"\n{host} is not reachable.")

    except subprocess.TimeoutExpired:
        print("Error: Ping operation timed out.")
    except OSError as e:
        print(f"Operating system error: {e}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()