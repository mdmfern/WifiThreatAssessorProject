"""
Common utility functions for the Wi-Fi Threat Assessor application.

This module provides reusable utility functions for file operations,
command execution, data type conversions, and string formatting.
"""

import os
import json
import datetime
import subprocess
from typing import Dict, List, Any, Optional

# Default file paths
DEFAULT_SETTINGS_FILE = 'wifi_scanner_settings.json'
DEFAULT_LOG_FILE = 'wifi_connection_logs.csv'


def run_command(command: List[str], capture_output: bool = True) -> Optional[str]:
    """
    Execute a system command with appropriate flags for the current OS.

    Args:
        command: List of command components to execute
        capture_output: Whether to capture and return command output

    Returns:
        Command output as string if capture_output is True, None otherwise

    Raises:
        Exception: If command execution fails
    """
    try:
        # Hide console window on Windows
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

        if capture_output:
            result = subprocess.check_output(
                command,
                text=True,
                creationflags=creation_flags
            )
            return result
        else:
            subprocess.run(command, creationflags=creation_flags)
            return None
    except subprocess.CalledProcessError as e:
        raise Exception(f"Command failed with exit code {e.returncode}: {e}")
    except Exception as e:
        raise Exception(f"Failed to execute command: {str(e)}")


def save_json(data: Dict[str, Any], filename: str) -> None:
    """
    Save dictionary data to a JSON file.

    Args:
        data: Dictionary to save
        filename: Path to the output JSON file

    Raises:
        Exception: If saving fails
    """
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        raise Exception(f"Failed to save data to {filename}: {str(e)}")


def load_json(filename: str, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Load data from a JSON file.

    Args:
        filename: Path to the JSON file to load
        default: Default value to return if file doesn't exist

    Returns:
        Dictionary containing the loaded JSON data or default value

    Raises:
        Exception: If loading fails
    """
    if not os.path.exists(filename):
        return default if default is not None else {}

    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise Exception(f"Failed to load data from {filename}: {str(e)}")


def format_timestamp(timestamp: Optional[str] = None,
                    format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format a timestamp string or generate current timestamp.

    Args:
        timestamp: Timestamp string to format (format: "%Y-%m-%d %H:%M:%S")
                  If None, current time is used
        format_str: Output format string

    Returns:
        Formatted timestamp string
    """
    if timestamp:
        try:
            dt = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            return dt.strftime(format_str)
        except ValueError:
            # If parsing fails, fall back to current time
            pass

    return datetime.datetime.now().strftime(format_str)


def ensure_dir_exists(directory: str) -> None:
    """
    Create directory if it doesn't exist.

    Args:
        directory: Path to directory to create
    """
    if not os.path.exists(directory):
        os.makedirs(directory)


def safe_int_conversion(value: Any, default: int = 0) -> int:
    """
    Safely convert a value to integer with fallback.

    Args:
        value: Value to convert to integer
        default: Default value to return if conversion fails

    Returns:
        Converted integer or default value
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def truncate_string(text: str, max_length: int = 50) -> str:
    """
    Truncate a string to specified maximum length.

    Args:
        text: String to truncate
        max_length: Maximum length of the output string

    Returns:
        Original string or truncated string with ellipsis
    """
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."
