import json
import os
from typing import Any, Dict

# Define default user settings
DEFAULT_SETTINGS: Dict[str, Any] = {
    "theme": "dark",
    "volume": 80,
    "notifications_enabled": True,
    "username": "guest"
}

def save_settings(settings: Dict[str, Any], filepath: str = "settings.json") -> bool:
    """
    Saves the user settings dictionary to a JSON file.
    
    Args:
        settings: Dictionary containing user settings.
        filepath: Path to the destination file.
        
    Returns:
        bool: True if successful, False otherwise.
    """
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=4)
        return True
    except IOError as e:
        print(f"Error saving settings to {filepath}: {e}")
        return False

def load_settings(filepath: str = "settings.json", default_settings: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Loads user settings from a JSON file. Returns and auto-creates/falls back 
    to default settings if the file is missing or corrupted.
    
    Args:
        filepath: Path to the settings file.
        default_settings: Fallback dictionary if loading fails.
        
    Returns:
        Dict[str, Any]: The loaded or default settings.
    """
    if default_settings is None:
        default_settings = DEFAULT_SETTINGS

    if not os.path.exists(filepath):
        # Optional: create the file with defaults on first run
        save_settings(default_settings, filepath)
        return default_settings

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            loaded_data = json.load(f)
            # Merge with defaults in case new settings keys were added in code updates
            return {**default_settings, **loaded_data}
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error reading settings from {filepath} ({e}). Falling back to defaults.")
        return default_settings

if __name__ == "__main__":
    # Example Demonstration
    print("--- Initial Load ---")
    user_settings = load_settings()
    print("Loaded settings:", user_settings)

    # Modify some settings
    print("\n--- Modifying Settings ---")
    user_settings["theme"] = "light"
    user_settings["volume"] = 45
    
    # Save the modified settings
    save_settings(user_settings)
    print("Settings saved successfully.")

    print("\n--- Reloading to Verify ---")
    reloaded_settings = load_settings()
    print("Final loaded settings:", reloaded_settings)
