import subprocess
import platform

# Ask the user for a hostname or IP address
host = input("Enter a hostname or IP address to ping: ")

# Determine the correct ping count parameter for the OS
param = "-n" if platform.system().lower() == "windows" else "-c"

# Run the ping command
try:
    result = subprocess.run(
        ["ping", param, "4", host],
        capture_output=True,
        text=True
    )

    print(result.stdout)

    if result.returncode == 0:
        print(f"\n{host} is reachable.")
    else:
        print(f"\n{host} is not reachable.")
except Exception as e:
    print(f"Error: {e}")