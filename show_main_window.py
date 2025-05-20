"""
Utility script to show the main window of the Wi-Fi Threat Assessor.

This script locates and displays the Wi-Fi Threat Assessor application window
if it's running but minimized to the system tray. If the application is not
running, it will start it automatically.

This utility is particularly useful when the application is running in the
background and the user wants to bring it to the foreground.
"""

import subprocess
import psutil
from typing import List, Optional


def enum_windows_callback(hwnd: int, result_list: List[int]) -> None:
    """
    Callback function for EnumWindows to find Wi-Fi Threat Assessor windows.

    Args:
        hwnd: Window handle
        result_list: List to store matching window handles
    """
    try:
        # Import here to avoid issues if win32gui is not available
        import win32gui

        if win32gui.IsWindowVisible(hwnd):
            window_text = win32gui.GetWindowText(hwnd)
            if "Wi-Fi" in window_text and ("Threat" in window_text or "Scanner" in window_text):
                result_list.append(hwnd)
    except Exception:
        # Silently ignore any errors during window enumeration
        pass


def find_threat_assessor_process() -> Optional[psutil.Process]:
    """
    Find the Wi-Fi Threat Assessor process if it's running.

    Returns:
        Process object if found, None otherwise
    """
    print("Searching for Wi-Fi Threat Assessor process...")

    for proc in psutil.process_iter(['pid', 'name']):
        if 'python' in proc.info['name'].lower():
            try:
                cmdline = proc.cmdline()
                if len(cmdline) >= 2 and 'main.py' in cmdline[1]:
                    print(f"Found Wi-Fi Threat Assessor process (PID: {proc.pid})")
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Skip processes we can't access
                pass

    return None


def start_threat_assessor() -> None:
    """Start the Wi-Fi Threat Assessor application."""
    print("Wi-Fi Threat Assessor is not running. Starting it now...")
    subprocess.Popen(['python', 'main.py'])
    print("Application started. The main window should be visible.")


def show_windows() -> bool:
    """
    Find and show all Wi-Fi Threat Assessor windows.

    Returns:
        True if windows were found and shown, False otherwise
    """
    try:
        import win32gui
        import win32con

        windows = []
        win32gui.EnumWindows(enum_windows_callback, windows)

        if windows:
            print(f"Found {len(windows)} matching windows. Attempting to show them...")
            for hwnd in windows:
                # Show and restore the window
                win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                win32gui.SetForegroundWindow(hwnd)
                print(f"Window '{win32gui.GetWindowText(hwnd)}' should now be visible")
            return True
        else:
            print("No matching windows found. The application might be minimized to the system tray.")
            print("Check the system tray area in the bottom-right corner of your screen.")
            print("If you can't see the icon, check the hidden icons area (up arrow in the system tray).")
            return False

    except ImportError:
        print("Could not import win32gui. Make sure pywin32 is installed.")
        print("You can install it with: pip install pywin32")
        return False


def find_and_show_window() -> None:
    """
    Find the Wi-Fi Threat Assessor process and show its window.

    This function first checks if the application is running. If it is,
    it attempts to find and show its window. If the application is not
    running, it starts it automatically.
    """
    # Check if the application is running
    process = find_threat_assessor_process()

    if not process:
        start_threat_assessor()
        return

    # Try to show the window
    show_windows()


if __name__ == "__main__":
    find_and_show_window()
