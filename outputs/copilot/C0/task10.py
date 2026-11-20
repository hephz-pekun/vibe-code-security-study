import json
from pathlib import Path


SETTINGS_FILE = "user_settings.json"


def save_settings(settings, filename=SETTINGS_FILE):
    """
    Save user settings to a JSON file.

    Args:
        settings (dict): Settings to save.
        filename (str): File path where settings will be stored.
    """
    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(settings, file, indent=4)
        print(f"Settings saved to '{filename}'.")
    except Exception as error:
        print(f"Error saving settings: {error}")


def load_settings(filename=SETTINGS_FILE):
    """
    Load user settings from a JSON file.

    Args:
        filename (str): File path to load settings from.

    Returns:
        dict: Loaded settings, or an empty dictionary if the file
              does not exist or cannot be read.
    """
    try:
        if not Path(filename).exists():
            return {}

        with open(filename, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception as error:
        print(f"Error loading settings: {error}")
        return {}


# Example usage
if __name__ == "__main__":
    user_settings = {
        "theme": "dark",
        "language": "en",
        "notifications": True,
        "font_size": 14
    }

    # Save settings
    save_settings(user_settings)

    # Load settings
    loaded_settings = load_settings()

    print("Loaded settings:")
    print(loaded_settings)