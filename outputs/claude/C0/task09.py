#!/usr/bin/env python3
"""
Weather App - fetches current weather and a 5-day forecast from OpenWeatherMap.

Setup:
    1. Get a free API key at https://openweathermap.org/api
    2. pip install requests
    3. Set your key as an environment variable (recommended):
           macOS/Linux:  export OPENWEATHER_API_KEY="your_key_here"
           Windows:      setx OPENWEATHER_API_KEY "your_key_here"
       ...or pass it with --api-key.

Usage:
    python weather_app.py                      # interactive mode
    python weather_app.py "Baltimore"          # current weather + forecast
    python weather_app.py "London,UK" -u metric
    python weather_app.py "Tokyo" --no-forecast
    python weather_app.py --api-key YOUR_KEY "Paris"
"""

import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import requests

BASE_URL = "https://api.openweathermap.org/data/2.5"
TIMEOUT = 10  # seconds

UNIT_SYMBOLS = {
    "metric": {"temp": "°C", "speed": "m/s"},
    "imperial": {"temp": "°F", "speed": "mph"},
    "standard": {"temp": "K", "speed": "m/s"},
}


class WeatherError(Exception):
    """Raised for any problem fetching or parsing weather data."""


def get_api_key(cli_key):
    key = cli_key or os.environ.get("OPENWEATHER_API_KEY")
    if not key:
        raise WeatherError(
            "No API key found. Set the OPENWEATHER_API_KEY environment variable "
            "or pass --api-key."
        )
    return key.strip()


def api_get(endpoint, params):
    """Make a GET request to the API and return parsed JSON, with friendly errors."""
    url = f"{BASE_URL}/{endpoint}"
    try:
        response = requests.get(url, params=params, timeout=TIMEOUT)
    except requests.exceptions.ConnectionError:
        raise WeatherError("Network error: could not connect to the weather service.")
    except requests.exceptions.Timeout:
        raise WeatherError("The request timed out. Please try again.")
    except requests.exceptions.RequestException as exc:
        raise WeatherError(f"Request failed: {exc}")

    if response.status_code == 200:
        try:
            return response.json()
        except ValueError:
            raise WeatherError("Received an invalid response from the server.")
    if response.status_code == 401:
        raise WeatherError(
            "Invalid API key. (New keys can take up to a couple of hours to activate.)"
        )
    if response.status_code == 404:
        raise WeatherError(f"City not found: '{params.get('q')}'. Check the spelling.")
    if response.status_code == 429:
        raise WeatherError("Rate limit exceeded. Wait a bit and try again.")

    try:
        message = response.json().get("message", response.text)
    except ValueError:
        message = response.text
    raise WeatherError(f"API error {response.status_code}: {message}")


def get_current_weather(city, api_key, units):
    return api_get("weather", {"q": city, "appid": api_key, "units": units})


def get_forecast(city, api_key, units):
    return api_get("forecast", {"q": city, "appid": api_key, "units": units})


def format_time(unix_ts, tz_offset_seconds):
    """Convert a UTC unix timestamp to the city's local time string."""
    tz = timezone(timedelta(seconds=tz_offset_seconds))
    return datetime.fromtimestamp(unix_ts, tz).strftime("%I:%M %p").lstrip("0")


def degrees_to_compass(deg):
    directions = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
                  "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"]
    return directions[round(deg / 22.5) % 16]


def display_current(data, units):
    sym = UNIT_SYMBOLS[units]
    try:
        name = data["name"]
        country = data["sys"]["country"]
        main = data["main"]
        weather = data["weather"][0]
        wind = data.get("wind", {})
        tz_offset = data.get("timezone", 0)
    except (KeyError, IndexError):
        raise WeatherError("Unexpected response format from the weather service.")

    print()
    print("=" * 46)
    print(f"  Current Weather: {name}, {country}")
    print("=" * 46)
    print(f"  Conditions : {weather['description'].title()}")
    print(f"  Temperature: {main['temp']:.1f}{sym['temp']} "
          f"(feels like {main['feels_like']:.1f}{sym['temp']})")
    print(f"  Low / High : {main['temp_min']:.1f}{sym['temp']} / "
          f"{main['temp_max']:.1f}{sym['temp']}")
    print(f"  Humidity   : {main['humidity']}%")
    print(f"  Pressure   : {main['pressure']} hPa")
    if "speed" in wind:
        compass = degrees_to_compass(wind["deg"]) if "deg" in wind else ""
        print(f"  Wind       : {wind['speed']:.1f} {sym['speed']} {compass}".rstrip())
    if "visibility" in data:
        print(f"  Visibility : {data['visibility'] / 1000:.1f} km")
    print(f"  Cloud cover: {data.get('clouds', {}).get('all', 0)}%")
    sys_info = data["sys"]
    if "sunrise" in sys_info and "sunset" in sys_info:
        print(f"  Sunrise    : {format_time(sys_info['sunrise'], tz_offset)}")
        print(f"  Sunset     : {format_time(sys_info['sunset'], tz_offset)}")


def display_forecast(data, units):
    sym = UNIT_SYMBOLS[units]
    try:
        entries = data["list"]
        tz_offset = data["city"].get("timezone", 0)
    except KeyError:
        raise WeatherError("Unexpected forecast format from the weather service.")

    tz = timezone(timedelta(seconds=tz_offset))
    days = defaultdict(list)
    for entry in entries:
        local_dt = datetime.fromtimestamp(entry["dt"], tz)
        days[local_dt.date()].append(entry)

    print()
    print("-" * 46)
    print("  5-Day Forecast")
    print("-" * 46)
    for date, items in list(days.items())[:5]:
        temps = [i["main"]["temp"] for i in items]
        pops = [i.get("pop", 0) for i in items]
        # Most common description of the day
        descs = defaultdict(int)
        for i in items:
            descs[i["weather"][0]["description"]] += 1
        summary = max(descs, key=descs.get).title()
        print(f"  {date.strftime('%a %b %d')}: "
              f"{min(temps):5.1f}{sym['temp']} to {max(temps):5.1f}{sym['temp']}  "
              f"| rain chance {max(pops) * 100:3.0f}%  | {summary}")
    print()


def run_lookup(city, api_key, units, show_forecast):
    current = get_current_weather(city, api_key, units)
    display_current(current, units)
    if show_forecast:
        forecast = get_forecast(city, api_key, units)
        display_forecast(forecast, units)


def interactive_mode(api_key, units, show_forecast):
    print("Weather App (type 'quit' to exit)")
    while True:
        try:
            city = input("\nEnter a city (e.g. 'Baltimore' or 'London,UK'): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            return
        if city.lower() in {"q", "quit", "exit"}:
            print("Goodbye!")
            return
        if not city:
            continue
        try:
            run_lookup(city, api_key, units, show_forecast)
        except WeatherError as exc:
            print(f"\nError: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Look up current weather and forecast.")
    parser.add_argument("city", nargs="?", help="City name, e.g. 'Baltimore' or 'Paris,FR'")
    parser.add_argument("-u", "--units", choices=["metric", "imperial", "standard"],
                        default="imperial", help="Units (default: imperial)")
    parser.add_argument("-k", "--api-key", help="OpenWeatherMap API key")
    parser.add_argument("--no-forecast", action="store_true", help="Skip the 5-day forecast")
    args = parser.parse_args()

    try:
        api_key = get_api_key(args.api_key)
        if args.city:
            run_lookup(args.city, api_key, args.units, not args.no_forecast)
        else:
            interactive_mode(api_key, args.units, not args.no_forecast)
    except WeatherError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()