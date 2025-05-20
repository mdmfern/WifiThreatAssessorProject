"""
Notification Manager for Wi-Fi Threat Assessor.

This module provides a centralized way to handle notifications in the application,
including system tray notifications, application alerts, and popup notifications.
It implements a singleton pattern to ensure only one notification manager exists
throughout the application lifecycle and maintains a history of recent notifications.
"""

import time
from typing import Dict, Any, List
from tkinter import messagebox
import customtkinter as ctk
from ui_constants import COLORS

class NotificationManager:
    """
    Manages notifications for the Wi-Fi Threat Assessor application.

    This class implements a singleton pattern to ensure only one notification manager
    exists throughout the application. It handles system tray notifications,
    message boxes, and maintains a history of recent notifications.

    Attributes:
        tray_icon: The system tray icon object used for displaying notifications
        settings: Dictionary containing notification settings
        notification_history: List of recent notifications
        max_history: Maximum number of notifications to keep in history
    """

    _instance = None

    def __new__(cls) -> 'NotificationManager':
        """
        Implement singleton pattern to ensure only one notification manager exists.

        Returns:
            The singleton NotificationManager instance
        """
        if cls._instance is None:
            cls._instance = super(NotificationManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        """Initialize the notification manager with default settings."""
        self.tray_icon = None
        self.settings = {
            'tray_notifications': True
        }
        self.notification_history: List[Dict[str, Any]] = []
        self.max_history = 10

    def set_tray_icon(self, tray_icon: Any) -> None:
        """
        Set the system tray icon for notifications.

        Args:
            tray_icon: The system tray icon object with a notify method
        """
        self.tray_icon = tray_icon

    def update_settings(self, settings: Dict[str, Any]) -> None:
        """
        Update notification settings.

        Args:
            settings: Dictionary containing notification settings
        """
        if 'tray_notifications' in settings:
            self.settings['tray_notifications'] = settings['tray_notifications']

    def show_notification(self, title: str, message: str, level: str = "info") -> None:
        """
        Show a notification to the user and add it to history.

        Args:
            title: The notification title
            message: The notification message
            level: The notification level (info, warning, error, critical)
        """
        # Add to history
        self.notification_history.insert(0, {
            'title': title,
            'message': message,
            'level': level,
            'timestamp': time.time()
        })

        # Trim history if needed
        if len(self.notification_history) > self.max_history:
            self.notification_history = self.notification_history[:self.max_history]

        # Show system tray notification if enabled
        if self.settings.get('tray_notifications', True) and self.tray_icon:
            try:
                self.tray_icon.notify(message, title)
            except Exception:
                # Silently handle notification errors
                pass

    def show_message_box(self, title: str, message: str, level: str = "info") -> None:
        """
        Show a message box to the user.

        Args:
            title: The message box title
            message: The message box message
            level: The message box level (info, warning, error, critical)
        """
        if level == "error":
            messagebox.showerror(title, message)
        elif level == "warning":
            messagebox.showwarning(title, message)
        else:
            messagebox.showinfo(title, message)

    def get_notification_history(self) -> List[Dict[str, Any]]:
        """
        Get the notification history.

        Returns:
            List of notification dictionaries with title, message, level, and timestamp
        """
        return self.notification_history

    def show_popup_notification(self, title: str, message: str, level: str = "info",
                               duration: int = 5000) -> None:
        """
        Show a popup notification window.

        Creates and displays a custom popup notification that will automatically
        close after the specified duration.

        Args:
            title: The notification title
            message: The notification message
            level: The notification level (info, warning, error, critical)
            duration: How long to show the notification in milliseconds
        """
        try:
            # Add to notification history
            self.notification_history.insert(0, {
                'title': title,
                'message': message,
                'level': level,
                'timestamp': time.time()
            })

            # Trim history if needed
            if len(self.notification_history) > self.max_history:
                self.notification_history = self.notification_history[:self.max_history]

            # Create and show popup notification
            NotificationPopup(title=title, message=message, level=level, duration=duration)
        except Exception:
            # Silently handle notification errors
            pass


class NotificationPopup(ctk.CTkToplevel):
    """
    Custom popup notification window.

    This class provides a modern, customizable popup notification
    that appears briefly in the bottom-right corner of the screen and then
    automatically closes after a specified duration.

    Attributes:
        frame: The main frame containing the notification content
    """

    def __init__(self, title: str, message: str, duration: int = 5000,
                 level: str = "info", **kwargs) -> None:
        """
        Initialize the notification popup.

        Args:
            title: The notification title
            message: The notification message
            duration: How long to show the notification in milliseconds
            level: The notification level (info, warning, error, critical)
            **kwargs: Additional keyword arguments passed to CTkToplevel
        """
        super().__init__(**kwargs)

        self.title("")  # Empty title for the window
        self.overrideredirect(True)  # Remove window decorations
        self.attributes("-topmost", True)  # Keep on top of other windows

        # Set background color based on notification level
        if level in ("error", "critical"):
            bg_color = COLORS.get("danger", ("#e74c3c", "#e74c3c"))[0]
        elif level == "warning":
            bg_color = COLORS.get("warning", ("#f39c12", "#f39c12"))[0]
        else:  # info or default
            bg_color = COLORS.get("primary", ("#1f538d", "#1f538d"))[0]

        # Create the popup content frame
        self.frame = ctk.CTkFrame(self, fg_color=bg_color)
        self.frame.pack(fill="both", expand=True)

        # Title label with bold font
        ctk.CTkLabel(
            self.frame,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="white"
        ).pack(padx=15, pady=(15, 5), anchor="w")

        # Message label with word wrapping
        ctk.CTkLabel(
            self.frame,
            text=message,
            font=ctk.CTkFont(size=12),
            text_color="white",
            wraplength=300,
            justify="left"
        ).pack(padx=15, pady=(0, 15), anchor="w")

        # Position the window in the bottom-right corner of the screen
        self.update_idletasks()  # Update to get accurate window dimensions
        width = self.winfo_width()
        height = self.winfo_height()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        # Calculate position (20px padding from screen edges)
        x = screen_width - width - 20
        y = screen_height - height - 40

        self.geometry(f"{width}x{height}+{x}+{y}")

        # Schedule the popup to close after the specified duration
        self.after(duration, self.fade_out)

    def fade_out(self) -> None:
        """Close the notification window."""
        self.destroy()
