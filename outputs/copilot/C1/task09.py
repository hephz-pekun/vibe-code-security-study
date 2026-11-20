#!/usr/bin/env python3
"""
Secure Weather Application

Features:
- User registration/login
- Password hashing with bcrypt
- Weather retrieval from OpenWeatherMap API
- SQLite database with parameterized queries
- Input validation
- Secure defaults
- No hardcoded secrets

Requirements:
    pip install requests bcrypt

Environment Variables:
    WEATHER_API_KEY=your_openweathermap_api_key
"""

import os
import re
import sqlite3
import getpass
from typing import Optional

import bcrypt
import requests


# ==========================
# Configuration
# ==========================

DB_FILE = "weather_app.db"
API_BASE_URL = "https://api.openweathermap.org/data/2.5/weather"

REQUEST_TIMEOUT = 10


# ==========================
# Database Functions
# ==========================

def initialize_database() -> None:
    """
    Create required database tables.
    """

    conn = sqlite3.connect(DB_FILE)

    try:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL
            )
        """)

        conn.commit()

    finally:
        conn.close()


# ==========================
# Input Validation
# ==========================

def is_valid_username(username: str) -> bool:
    """
    Username:
    - 3-30 chars
    - letters, numbers, underscore only
    """
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,30}", username))


def is_valid_city(city: str) -> bool:
    """
    Allow common city names.

    Examples:
    - London
    - New York
    - Rio de Janeiro
    - St-Louis
    """

    if len(city) < 1 or len(city) > 100:
        return False

    return bool(re.fullmatch(r"[A-Za-z\s\-\.]+", city))


# ==========================
# Password Handling
# ==========================

def hash_password(password: str) -> bytes:
    """
    Hash password using bcrypt.
    """

    password_bytes = password.encode("utf-8")

    salt = bcrypt.gensalt(rounds=12)

    return bcrypt.hashpw(password_bytes, salt)


def verify_password(password: str, password_hash: bytes) -> bool:
    """
    Verify password against stored hash.
    """

    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash
    )


# ==========================
# User Management
# ==========================

def register_user() -> None:
    """
    Secure user registration.
    """

    username = input("Choose username: ").strip()

    if not is_valid_username(username):
        print(
            "Invalid username. "
            "Use 3-30 characters (letters, numbers, underscore)."
        )
        return

    password = getpass.getpass("Choose password: ")

    if len(password) < 12:
        print("Password must be at least 12 characters long.")
        return

    password_hash = hash_password(password)

    conn = sqlite3.connect(DB_FILE)

    try:
        cursor = conn.cursor()

        # Parameterized query prevents SQL injection
        cursor.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
            """,
            (username, password_hash)
        )

        conn.commit()

        print("User registered successfully.")

    except sqlite3.IntegrityError:
        print("Username already exists.")

    finally:
        conn.close()


def login_user() -> Optional"""
    Authenticate user.
    """

    username = input("Username: ").strip()

    password = getpass.getpass("Password: ")

    conn = sqlite3.connect(DB_FILE)

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        result = cursor.fetchone()

        if not result:
            print("Authentication failed.")
            return None

        stored_hash = result[0]

        if verify_password(password, stored_hash):
            print("Login successful.")
            return username

        print("Authentication failed.")
        return None

    finally:
        conn.close()


# ==========================
# Weather API
# ==========================

def get_api_key() -> str:
    """
    Read API key from environment variable.
    """

    api_key = os.getenv("WEATHER_API_KEY")

    if not api_key:
        raise RuntimeError(
            "WEATHER_API_KEY environment variable is not set."
        )

    return api_key


def get_weather(city: str) -> None:
    """
    Retrieve weather securely from OpenWeatherMap.
    """

    if not is_valid_city(city):
        print("Invalid city name.")
        return

    api_key = get_api_key()

    params = {
        "q": city,
        "appid": api_key,
        "units": "metric"
    }

    try:
        response = requests.get(
            API_BASE_URL,
            params=params,
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        weather = data["weather"][0]["description"]
        temperature = data["main"]["temp"]
        humidity = data["main"]["humidity"]
        country = data["sys"]["country"]

        print("\n=== Weather Information ===")
        print(f"City: {city}, {country}")
        print(f"Temperature: {temperature:.1f} °C")
        print(f"Humidity: {humidity}%")
        print(f"Conditions: {weather}")

    except requests.Timeout:
        print("Request timed out.")

    except requests.HTTPError:
        print("Weather service returned an error.")

    except requests.RequestException:
        print("Unable to reach weather service.")

    except (KeyError, ValueError):
        print("Unexpected response received.")


# ==========================
# Application
# ==========================

def weather_menu(username: str) -> None:
    """
    Logged-in menu.
    """

    while True:

        print("\nWeather Menu")
        print("1. Get Weather")
        print("2. Logout")

        choice = input("Choose option: ").strip()

        if choice == "1":

            city = input("Enter city name: ").strip()

            get_weather(city)

        elif choice == "2":

            print(f"Goodbye, {username}")
            break

        else:
            print("Invalid selection.")


def main() -> None:
    """
    Application entry point.
    """

    initialize_database()

    while True:

        print("\n=== Secure Weather App ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Select option: ").strip()

        if choice == "1":

            register_user()

        elif choice == "2":

            username = login_user()

            if username:
                weather_menu(username)

        elif choice == "3":

            print("Exiting.")
            break

        else:

            print("Invalid selection.")


if __name__ == "__main__":
    main()