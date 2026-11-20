import os
import sys
from datetime import datetime, timezone, timedelta
import requests

BASE_URL = "https://api.openweathermap.org/data/2.5/weather"


def get_api_key() -> str:
    """Retrieve the API key from the environment or prompt the user."""
    api_key = os.getenv("OPENWEATHER_API_KEY", "").strip()
    if not api_key:
        api_key = input("Enter your OpenWeatherMap API key: ").strip()
    if not api_key:
        print("Error: An API key is required to run this app.")
        sys.exit(1)
    return api_key


def fetch_weather(city: str, api_key: str, units: str = "imperial") -> dict:
    """Call the OpenWeatherMap API and return the parsed JSON response."""
    params = {
        "q": city,
        "appid": api_key,
        "units": units,  # "imperial" (°F, mph) or "metric" (°C, m/s)
    }
    response = requests.get(BASE_URL, params=params, timeout=10)
    response.raise_for_status()
    return response.json()


def format_local_time(unix_ts: int, tz_offset_seconds: int) -> str:
    """Convert a UTC Unix timestamp to local time using the city's timezone offset."""
    local_tz = timezone(timedelta(seconds=tz_offset_seconds))
    return datetime.fromtimestamp(unix_ts, tz=local_tz).strftime("%I:%M %p")


def display_weather(data: dict, units: str) -> None:
    """Format and print weather details to the console."""
    temp_unit = "°F" if units == "imperial" else "°C"
    speed_unit = "mph" if units == "imperial" else "m/s"

    city_name = data.get("name", "Unknown")
    country = data.get("sys", {}).get("country", "")
    weather_desc = data["weather"][0]["description"].title()

    main = data["main"]
    wind_speed = data.get("wind", {}).get("speed", 0)
    tz_offset = data.get("timezone", 0)
    sunrise = format_local_time(data["sys"]["sunrise"], tz_offset)
    sunset = format_local_time(data["sys"]["sunset"], tz_offset)

    header = f"Weather in {city_name}, {country}" if country else f"Weather in {city_name}"
    print("\n" + "=" * 42)
    print(f"  {header}")
    print("=" * 42)
    print(f"  Condition   : {weather_desc}")
    print(f"  Temperature : {main['temp']:.1f}{temp_unit} (Feels like {main['feels_like']:.1f}{temp_unit})")
    print(f"  High / Low  : {main['temp_max']:.1f}{temp_unit} / {main['temp_min']:.1f}{temp_unit}")
    print(f"  Humidity    : {main['humidity']}%")
    print(f"  Pressure    : {main['pressure']} hPa")
    print(f"  Wind Speed  : {wind_speed} {speed_unit}")
    print(f"  Sunrise     : {sunrise}")
    print(f"  Sunset      : {sunset}")
    print("=" * 42 + "\n")


def main() -> None:
    print("=== Python CLI Weather App ===")
    api_key = get_api_key()

    unit_choice = input("Choose units — (F)ahrenheit or (C)elsius [F]: ").strip().lower()
    units = "metric" if unit_choice == "c" else "imperial"

    while True:
        city = input("Enter a city name (or 'q' to quit): ").strip()
        if city.lower() in {"q", "quit", "exit"}:
            print("Goodbye!")
            break
        if not city:
            continue

        try:
            weather_data = fetch_weather(city, api_key, units)
            display_weather(weather_data, units)
        except requests.exceptions.HTTPError as err:
            status = err.response.status_code if err.response is not None else None
            if status == 401:
                print("Error: Invalid API key (or key not yet activated).\n")
            elif status == 404:
                print(f"Error: City '{city}' not found. Try adding a country code (e.g., 'London, UK').\n")
            else:
                print(f"HTTP error occurred: {err}\n")
        except requests.exceptions.RequestException as err:
            print(f"Network error: Could not connect to the weather service ({err}).\n")


if __name__ == "__main__":
    main()
