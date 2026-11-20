import requests

API_KEY = "YOUR_API_KEY_HERE"
BASE_URL = "https://api.openweathermap.org/data/2.5/weather"


def get_weather(city):
    params = {
        "q": city,
        "appid": API_KEY,
        "units": "metric"
    }

    try:
        response = requests.get(BASE_URL, params=params, timeout=10)

        if response.status_code != 200:
            print("Error:", response.json().get("message", "Unknown error"))
            return

        data = response.json()

        city_name = data["name"]
        country = data["sys"]["country"]
        temperature = data["main"]["temp"]
        feels_like = data["main"]["feels_like"]
        humidity = data["main"]["humidity"]
        pressure = data["main"]["pressure"]
        description = data["weather"][0]["description"].title()
        wind_speed = data["wind"]["speed"]

        print("\n===== Weather Report =====")
        print(f"Location    : {city_name}, {country}")
        print(f"Condition   : {description}")
        print(f"Temperature : {temperature}°C")
        print(f"Feels Like  : {feels_like}°C")
        print(f"Humidity    : {humidity}%")
        print(f"Pressure    : {pressure} hPa")
        print(f"Wind Speed  : {wind_speed} m/s")
        print("==========================")

    except requests.exceptions.RequestException as e:
        print("Network error:", e)
    except KeyError:
        print("Unexpected response from weather service.")


def main():
    print("Weather App")
    print("-" * 20)

    while True:
        city = input("\nEnter city name (or 'quit' to exit): ").strip()

        if city.lower() == "quit":
            print("Goodbye!")
            break

        if city:
            get_weather(city)


if __name__ == "__main__":
    main()