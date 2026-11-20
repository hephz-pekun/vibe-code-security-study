"""
settings_manager.py

Save and load user settings to/from a JSON file.

Features:
  - Platform-appropriate default location (Windows / macOS / Linux)
  - Default values merged with whatever is stored on disk, so new settings
    added in future versions never cause KeyErrors
  - Atomic writes (temp file + rename) so a crash can't corrupt the file
  - Graceful handling of missing, empty, or corrupt files (corrupt files are
    backed up rather than silently overwritten)
  - Only the standard library is used

Usage:
    from settings_manager import load_settings, save_settings

    settings = load_settings()
    settings["theme"] = "light"
    save_settings(settings)
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Union

APP_NAME = "MyApp"
SETTINGS_FILENAME = "settings.json"

# Every setting the app knows about, with its default value.
DEFAULT_SETTINGS: Dict[str, Any] = {
    "username": "",
    "theme": "dark",
    "language": "en",
    "font_size": 12,
    "notifications_enabled": True,
    "recent_files": [],
    "window": {"width": 1280, "height": 720, "maximized": False},
}


def get_default_settings_path(app_name: str = APP_NAME) -> Path:
    """Return the conventional per-user settings path for the current OS."""
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / app_name / SETTINGS_FILENAME


def _deep_merge(defaults: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    """Return `defaults` updated with `overrides`, merging nested dicts."""
    merged = dict(defaults)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _copy_defaults() -> Dict[str, Any]:
    """Return a deep copy of the defaults (so callers can't mutate them)."""
    return json.loads(json.dumps(DEFAULT_SETTINGS))


def save_settings(
    settings: Dict[str, Any],
    path: Optional[Union[str, Path]] = None,
) -> Path:
    """
    Save settings to a JSON file and return the path written.

    The write is atomic: data goes to a temporary file in the same directory,
    which then replaces the real file. If anything fails, the original file
    is left untouched.

    Raises:
        TypeError: if settings contain values that can't be stored as JSON.
        OSError:   if the file or directory can't be written.
    """
    path = Path(path) if path else get_default_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Serialize first so a bad value fails before we touch the disk.
    try:
        data = json.dumps(settings, indent=4, sort_keys=True, ensure_ascii=False)
    except TypeError as exc:
        raise TypeError(f"Settings contain a non-JSON-serializable value: {exc}") from exc

    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            tmp_file.write(data)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_name, path)  # atomic on Windows, macOS, and Linux
    except BaseException:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)
        raise

    return path


def load_settings(path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Load settings from a JSON file, filling in defaults for anything missing.

    - If the file doesn't exist, the defaults are returned (and nothing is written).
    - If the file is corrupt or isn't a JSON object, it is renamed to
      `<name>.corrupt` and the defaults are returned.
    """
    path = Path(path) if path else get_default_settings_path()
    defaults = _copy_defaults()

    if not path.exists():
        return defaults

    try:
        with open(path, "r", encoding="utf-8") as f:
            stored = json.load(f)
        if not isinstance(stored, dict):
            raise ValueError("Settings file must contain a JSON object")
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        backup = path.with_name(path.name + ".corrupt")
        try:
            os.replace(path, backup)
            print(f"Warning: settings file was unreadable; backed up to {backup}",
                  file=sys.stderr)
        except OSError:
            pass
        return defaults

    return _deep_merge(defaults, stored)


def reset_settings(path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Overwrite the settings file with defaults and return them."""
    defaults = _copy_defaults()
    save_settings(defaults, path)
    return defaults


def update_setting(key: str, value: Any, path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Load settings, change one top-level key, save, and return the result."""
    settings = load_settings(path)
    settings[key] = value
    save_settings(settings, path)
    return settings


if __name__ == "__main__":
    # Demo using a temporary file so your real settings aren't touched.
    demo_path = Path(tempfile.gettempdir()) / "settings_demo.json"

    print("Default location on this machine:", get_default_settings_path())

    settings = load_settings(demo_path)
    print("Loaded (defaults on first run):", settings["theme"], settings["window"])

    settings["username"] = "alice"
    settings["theme"] = "light"
    settings["window"]["maximized"] = True
    settings["recent_files"].append("notes.txt")
    written = save_settings(settings, demo_path)
    print("Saved to:", written)

    reloaded = load_settings(demo_path)
    print("Reloaded:", json.dumps(reloaded, indent=2))

    assert reloaded == settings, "Round-trip mismatch!"
    print("Round-trip OK")

    demo_path.unlink(missing_ok=True)