"""
Settings Manager for the Wi-Fi Threat Assessor application.

This module provides a comprehensive settings management system with a modern
tabbed interface. It allows users to configure various aspects of the application
including network scanning, display preferences, logging options, and advanced
system settings.
"""

import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from typing import Dict, Any, Callable, List

from ui_constants import (
    DEFAULT_THEMES, DEFAULT_APPEARANCE_MODES,
    INTERFACE_DENSITY_OPTIONS, FONT_SIZE_OPTIONS, ANIMATION_SPEED_OPTIONS
)


class SettingsTab(ctk.CTkScrollableFrame):
    """
    Base class for settings tabs.

    This class provides a scrollable frame with common functionality for creating
    and managing settings controls. It includes methods for adding section headers,
    option frames, and various types of controls (switches, dropdowns, sliders, etc.).

    Subclasses should override the load_settings and get_settings methods to handle
    their specific settings.
    """

    def __init__(self, parent, **kwargs):
        """
        Initialize a new settings tab.

        Args:
            parent: The parent widget
            **kwargs: Additional keyword arguments to pass to CTkScrollableFrame
        """
        # Set default styling if not provided
        if "fg_color" not in kwargs:
            kwargs["fg_color"] = ("gray95", "gray20")
        if "scrollbar_fg_color" not in kwargs:
            kwargs["scrollbar_fg_color"] = ("gray70", "gray30")
        if "scrollbar_button_color" not in kwargs:
            kwargs["scrollbar_button_color"] = ("gray80", "gray40")
        if "scrollbar_button_hover_color" not in kwargs:
            kwargs["scrollbar_button_hover_color"] = ("gray90", "gray50")

        super().__init__(parent, **kwargs)
        self.parent = parent
        self.settings = {}  # Stores the current settings
        self.variables = {}  # Stores tkinter variables for controls
        self.controls = {}   # Stores references to UI controls

    def add_section_header(self, text: str) -> ctk.CTkFrame:
        """
        Add a section header with a separator line.

        Args:
            text: The header text

        Returns:
            The created frame containing the header
        """
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="x", pady=(15, 5))

        ctk.CTkLabel(
            frame,
            text=text,
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w")

        separator = ctk.CTkFrame(frame, height=2, fg_color=("gray70", "gray30"))
        separator.pack(fill="x", pady=(5, 0))

        return frame

    def add_option_frame(self, label: str) -> ctk.CTkFrame:
        """
        Add a frame for a setting option with a label.

        Args:
            label: The label text for the option

        Returns:
            The created frame for adding controls
        """
        frame = ctk.CTkFrame(self)
        frame.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(
            frame,
            text=label,
            font=ctk.CTkFont(size=13),
            width=150,
            anchor="w"
        ).pack(side="left", padx=10)

        return frame

    def add_switch(self, section_frame: ctk.CTkFrame, label: str, key: str,
                  default: bool = False) -> tk.BooleanVar:
        """
        Add a switch control to the given frame.

        Args:
            section_frame: The frame to add the control to
            label: The label for the switch
            key: The settings key for this control
            default: The default value (True/False)

        Returns:
            The tkinter variable associated with the control
        """
        var = tk.BooleanVar(value=default)
        self.variables[key] = var

        switch = ctk.CTkSwitch(
            section_frame,
            text=label,
            variable=var
        )
        switch.pack(side="left", padx=20)
        self.controls[key] = switch

        return var

    def add_dropdown(self, section_frame: ctk.CTkFrame, options: List[str], key: str,
                    default: str = "") -> tk.StringVar:
        """
        Add a dropdown menu to the given frame.

        Args:
            section_frame: The frame to add the control to
            options: List of options for the dropdown
            key: The settings key for this control
            default: The default selected option

        Returns:
            The tkinter variable associated with the control
        """
        var = tk.StringVar(value=default if default else options[0])
        self.variables[key] = var

        dropdown = ctk.CTkOptionMenu(
            section_frame,
            values=options,
            variable=var
        )
        dropdown.pack(side="left", padx=20)
        self.controls[key] = dropdown

        return var

    def add_slider(self, section_frame: ctk.CTkFrame, key: str, from_: int, to: int,
                  default: int, label_suffix: str = "") -> tk.IntVar:
        """
        Add a slider control to the given frame.

        Args:
            section_frame: The frame to add the control to
            key: The settings key for this control
            from_: The minimum value of the slider
            to: The maximum value of the slider
            default: The default value
            label_suffix: Text to append to the value label (e.g. "px", "s")

        Returns:
            The tkinter variable associated with the control
        """
        var = tk.IntVar(value=default)
        self.variables[key] = var

        slider_frame = ctk.CTkFrame(section_frame, fg_color="transparent")
        slider_frame.pack(side="left", fill="x", expand=True, padx=20)

        value_label = ctk.CTkLabel(
            slider_frame,
            text=f"{default}{label_suffix}",
            width=50
        )
        value_label.pack(side="right", padx=(10, 0))

        slider = ctk.CTkSlider(
            slider_frame,
            from_=from_,
            to=to,
            number_of_steps=to-from_,
            variable=var,
            command=lambda v: value_label.configure(text=f"{int(v)}{label_suffix}")
        )
        slider.pack(side="left", fill="x", expand=True)
        self.controls[key] = slider

        return var

    def add_entry(self, section_frame: ctk.CTkFrame, key: str, default: str = "",
                 width: int = 80, suffix_text: str = "") -> tk.StringVar:
        """
        Add a text entry field to the given frame.

        Args:
            section_frame: The frame to add the control to
            key: The settings key for this control
            default: The default text value
            width: The width of the entry field
            suffix_text: Optional text to display after the entry field

        Returns:
            The tkinter variable associated with the control
        """
        var = tk.StringVar(value=str(default))
        self.variables[key] = var

        entry = ctk.CTkEntry(
            section_frame,
            textvariable=var,
            width=width
        )
        entry.pack(side="left", padx=10)
        self.controls[key] = entry

        if suffix_text:
            ctk.CTkLabel(section_frame, text=suffix_text).pack(side="left")

        return var


    def load_settings(self, settings: Dict[str, Any]) -> None:
        """
        Load settings into the tab.

        This base implementation just stores the settings dictionary.
        Subclasses should override this to update their UI controls.

        Args:
            settings: Dictionary containing settings
        """
        self.settings = settings

    def get_settings(self) -> Dict[str, Any]:
        """
        Get the current settings from the tab.

        This base implementation returns an empty dictionary.
        Subclasses should override this to return their specific settings.

        Returns:
            Dictionary containing the current settings
        """
        return {}

    def add_bottom_padding(self) -> None:
        """Add padding at the bottom of the tab for better spacing."""
        padding_frame = ctk.CTkFrame(self, fg_color="transparent", height=40)
        padding_frame.pack(fill="x", pady=20)


class NetworkScanningTab(SettingsTab):
    """
    Tab for network scanning settings.

    This tab allows configuration of automatic scanning, refresh intervals,
    scan depth, background scanning, and startup behavior.
    """

    def __init__(self, parent, **kwargs):
        """
        Initialize the network scanning settings tab.

        Args:
            parent: The parent widget
            **kwargs: Additional keyword arguments to pass to SettingsTab
        """
        super().__init__(parent, **kwargs)

        # Automatic Scanning section
        self.add_section_header("Automatic Scanning")

        refresh_frame = self.add_option_frame("Auto Refresh")
        self.add_switch(refresh_frame, "Enable Auto Refresh", "auto_refresh")

        interval_frame = self.add_option_frame("Refresh Interval")
        self.add_slider(interval_frame, "refresh_interval", 10, 120, 30, "s")

        # Scan Options section
        self.add_section_header("Scan Options")

        bg_scan_frame = self.add_option_frame("Background Scanning")
        self.add_switch(bg_scan_frame, "Enable Background Scanning", "background_scanning")

        startup_frame = self.add_option_frame("Startup Behavior")
        self.add_switch(startup_frame, "Scan on Startup", "startup_scan", True)

        self.add_bottom_padding()

    def load_settings(self, settings: Dict[str, Any]) -> None:
        """
        Load network scanning settings into the UI controls.

        Args:
            settings: Dictionary containing settings
        """
        self.settings = settings
        self.variables["auto_refresh"].set(settings.get("auto_refresh", False))
        self.variables["refresh_interval"].set(settings.get("refresh_interval", 30))
        self.variables["background_scanning"].set(settings.get("background_scanning", False))
        self.variables["startup_scan"].set(settings.get("startup_scan", True))

    def get_settings(self) -> Dict[str, Any]:
        """
        Get the current network scanning settings from the UI controls.

        Returns:
            Dictionary containing the current network scanning settings
        """
        return {
            "auto_refresh": self.variables["auto_refresh"].get(),
            "refresh_interval": int(self.variables["refresh_interval"].get()),
            "scan_depth": "Standard",  # Always use Standard scan depth
            "background_scanning": self.variables["background_scanning"].get(),
            "startup_scan": self.variables["startup_scan"].get()
        }


class DisplaySettingsTab(SettingsTab):
    """
    Tab for display and appearance settings.

    This tab allows configuration of theme, appearance mode, custom colors,
    interface styling, animations, and typography settings.
    """

    def __init__(self, parent, **kwargs):
        """
        Initialize the display settings tab.

        Args:
            parent: The parent widget
            **kwargs: Additional keyword arguments to pass to SettingsTab
        """
        super().__init__(parent, **kwargs)

        # Theme section
        self.add_section_header("Theme")

        theme_frame = self.add_option_frame("Color Theme")
        self.add_dropdown(theme_frame, DEFAULT_THEMES, "theme", "blue")

        appear_frame = self.add_option_frame("Appearance Mode")
        self.add_dropdown(appear_frame, DEFAULT_APPEARANCE_MODES, "appearance", "System")

        # Interface Styling section
        self.add_section_header("Interface Styling")

        corner_frame = self.add_option_frame("Corner Radius")
        self.add_slider(corner_frame, "corner_radius", 0, 20, 8, "px")

        density_frame = self.add_option_frame("Interface Density")
        self.add_dropdown(density_frame, INTERFACE_DENSITY_OPTIONS, "interface_density", "Standard")

        # Animation section
        self.add_section_header("Animation")

        anim_frame = self.add_option_frame("Animations")
        self.add_switch(anim_frame, "Enable Animations", "animation_enabled", True)

        speed_frame = self.add_option_frame("Animation Speed")
        self.add_dropdown(speed_frame, ANIMATION_SPEED_OPTIONS, "animation_speed", "Medium")

        # Typography section
        self.add_section_header("Typography")

        font_size_frame = self.add_option_frame("Font Size")
        self.add_dropdown(font_size_frame, FONT_SIZE_OPTIONS, "font_size", "Medium")

        font_family_frame = self.add_option_frame("Font Family")
        self.add_dropdown(font_family_frame, ["Segoe UI", "Arial", "Verdana", "Tahoma"],
                         "font_family", "Segoe UI")

        self.add_bottom_padding()

    def load_settings(self, settings: Dict[str, Any]) -> None:
        """
        Load display settings into the UI controls.

        Args:
            settings: Dictionary containing settings
        """
        self.settings = settings

        # Load theme settings
        self.variables["theme"].set(settings.get("theme", "blue"))
        self.variables["appearance"].set(settings.get("appearance", "System"))

        # Load interface styling settings
        self.variables["corner_radius"].set(settings.get("corner_radius", 8))
        self.variables["interface_density"].set(settings.get("interface_density", "Standard"))

        # Load animation settings
        self.variables["animation_enabled"].set(settings.get("animation_enabled", True))
        self.variables["animation_speed"].set(settings.get("animation_speed", "Medium"))

        # Load typography settings
        self.variables["font_size"].set(settings.get("font_size", "Medium"))
        self.variables["font_family"].set(settings.get("font_family", "Segoe UI"))

    def get_settings(self) -> Dict[str, Any]:
        """
        Get the current display settings from the UI controls.

        Returns:
            Dictionary containing the current display settings
        """
        return {
            "theme": self.variables["theme"].get(),
            "appearance": self.variables["appearance"].get(),
            "corner_radius": int(self.variables["corner_radius"].get()),
            "interface_density": self.variables["interface_density"].get(),
            "animation_enabled": self.variables["animation_enabled"].get(),
            "animation_speed": self.variables["animation_speed"].get(),
            "font_size": self.variables["font_size"].get(),
            "font_family": self.variables["font_family"].get()
        }


class LoggingSettingsTab(SettingsTab):
    """
    Tab for logging and history settings.

    This tab allows configuration of connection logging options and
    export preferences for log data.
    """

    def __init__(self, parent, **kwargs):
        """
        Initialize the logging settings tab.

        Args:
            parent: The parent widget
            **kwargs: Additional keyword arguments to pass to SettingsTab
        """
        super().__init__(parent, **kwargs)

        # Connection Logging section
        self.add_section_header("Connection Logging")

        auto_log_frame = self.add_option_frame("Auto Logging")
        self.add_switch(auto_log_frame, "Automatically Log Connections", "auto_logging", True)

        retention_frame = self.add_option_frame("Log Retention")
        self.add_slider(retention_frame, "log_retention", 1, 90, 30, " days")

        detail_frame = self.add_option_frame("Log Detail Level")
        self.add_dropdown(detail_frame, ["Basic", "Standard", "Detailed"],
                         "log_detail_level", "Standard")

        # Export Options section
        self.add_section_header("Export Options")

        export_format_frame = self.add_option_frame("Default Export Format")
        self.add_dropdown(export_format_frame, ["CSV", "JSON", "PDF"],
                         "export_format", "CSV")

        self.add_bottom_padding()

    def load_settings(self, settings: Dict[str, Any]) -> None:
        """
        Load logging settings into the UI controls.

        Args:
            settings: Dictionary containing settings
        """
        self.settings = settings
        self.variables["auto_logging"].set(settings.get("auto_logging", True))
        self.variables["log_retention"].set(settings.get("log_retention", 30))
        self.variables["log_detail_level"].set(settings.get("log_detail_level", "Standard"))
        self.variables["export_format"].set(settings.get("export_format", "CSV"))

    def get_settings(self) -> Dict[str, Any]:
        """
        Get the current logging settings from the UI controls.

        Returns:
            Dictionary containing the current logging settings
        """
        return {
            "auto_logging": self.variables["auto_logging"].get(),
            "log_retention": int(self.variables["log_retention"].get()),
            "log_detail_level": self.variables["log_detail_level"].get(),
            "export_format": self.variables["export_format"].get()
        }


class AdvancedSettingsTab(SettingsTab):
    """
    Tab for advanced application settings.

    This tab allows configuration of system tray behavior, automated notifications,
    and window position settings.
    """

    def __init__(self, parent, **kwargs):
        """
        Initialize the advanced settings tab.

        Args:
            parent: The parent widget
            **kwargs: Additional keyword arguments to pass to SettingsTab
        """
        super().__init__(parent, **kwargs)

        # System Tray section
        self.add_section_header("System Tray")

        enable_tray_frame = self.add_option_frame("System Tray Icon")
        self.add_switch(enable_tray_frame, "Enable System Tray Icon", "enable_system_tray", True)

        minimize_frame = self.add_option_frame("Minimize to Tray")
        self.add_switch(minimize_frame, "Minimize to Tray on Close", "minimize_to_tray", True)

        notify_frame = self.add_option_frame("Tray Notifications")
        self.add_switch(notify_frame, "Show Tray Notifications", "tray_notifications", True)

        # Automated Notifications section
        self.add_section_header("Automated Notifications")

        auto_notify_frame = self.add_option_frame("Automated Updates")
        self.add_switch(auto_notify_frame, "Enable Automated Notifications", "enable_automated_notifications", True)

        interval_frame = self.add_option_frame("Notification Interval")
        self.add_dropdown(interval_frame, ["5 minutes", "10 minutes", "15 minutes", "30 minutes", "1 hour"],
                         "notification_interval_display", "10 minutes")

        # Window Settings section
        self.add_section_header("Window Settings")

        save_pos_frame = self.add_option_frame("Window Position")
        self.add_switch(save_pos_frame, "Remember Window Position", "save_window_position", True)

        self.add_bottom_padding()

    def load_settings(self, settings: Dict[str, Any]) -> None:
        """
        Load advanced settings into the UI controls.

        Args:
            settings: Dictionary containing settings
        """
        self.settings = settings

        # Load system tray settings
        self.variables["enable_system_tray"].set(settings.get("enable_system_tray", True))
        self.variables["minimize_to_tray"].set(settings.get("minimize_to_tray", True))
        self.variables["tray_notifications"].set(settings.get("tray_notifications", True))

        # Load window settings
        self.variables["save_window_position"].set(settings.get("save_window_position", True))

        # Load automated notification settings
        self.variables["enable_automated_notifications"].set(settings.get("enable_automated_notifications", True))

        # Convert interval from seconds to display string
        interval_seconds = settings.get("notification_interval", 600)
        interval_display = self._seconds_to_interval_display(interval_seconds)
        self.variables["notification_interval_display"].set(interval_display)

    def get_settings(self) -> Dict[str, Any]:
        """
        Get the current advanced settings from the UI controls.

        Returns:
            Dictionary containing the current advanced settings
        """
        # Convert interval display string to seconds
        interval_display = self.variables["notification_interval_display"].get()
        interval_seconds = self._interval_display_to_seconds(interval_display)

        return {
            "enable_system_tray": self.variables["enable_system_tray"].get(),
            "minimize_to_tray": self.variables["minimize_to_tray"].get(),
            "tray_notifications": self.variables["tray_notifications"].get(),
            "save_window_position": self.variables["save_window_position"].get(),
            "enable_automated_notifications": self.variables["enable_automated_notifications"].get(),
            "notification_interval": interval_seconds
        }

    def _seconds_to_interval_display(self, seconds: int) -> str:
        """
        Convert seconds to a display string for the notification interval.

        Args:
            seconds: The interval in seconds

        Returns:
            A human-readable string representation of the interval
        """
        if seconds == 300:
            return "5 minutes"
        elif seconds == 600:
            return "10 minutes"
        elif seconds == 900:
            return "15 minutes"
        elif seconds == 1800:
            return "30 minutes"
        elif seconds == 3600:
            return "1 hour"
        else:
            # Default to 10 minutes if the value is not recognized
            return "10 minutes"

    def _interval_display_to_seconds(self, display: str) -> int:
        """
        Convert a display string to seconds for the notification interval.

        Args:
            display: The display string (e.g., "10 minutes")

        Returns:
            The interval in seconds
        """
        if display == "5 minutes":
            return 300
        elif display == "10 minutes":
            return 600
        elif display == "15 minutes":
            return 900
        elif display == "30 minutes":
            return 1800
        elif display == "1 hour":
            return 3600
        else:
            # Default to 10 minutes if the value is not recognized
            return 600

class SettingsDialog(ctk.CTkToplevel):
    """
    Modern settings dialog with tabbed interface.

    This dialog provides a user-friendly interface for configuring all application
    settings, organized into tabs for different categories of settings.
    """

    def __init__(self, parent, settings: Dict[str, Any], save_callback: Callable[[Dict[str, Any]], None]):
        """
        Initialize the settings dialog.

        Args:
            parent: The parent window
            settings: Dictionary containing current settings
            save_callback: Function to call with new settings when saved
        """
        super().__init__(parent)

        self.parent = parent
        self.settings = settings
        self.save_callback = save_callback
        self.result = None  # Will be set to True/False when dialog closes

        # Configure window properties
        self.title("Settings")
        self.geometry("800x600")
        self.minsize(700, 500)
        self.resizable(True, True)

        # Ensure dialog appears on top of parent window
        self.attributes('-topmost', True)
        self.update()
        self.attributes('-topmost', False)

        # Focus handling
        self.lift()
        self.focus_force()
        self.grab_set()

        # Create main container frame
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Create tabbed interface
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(fill="both", expand=True)

        # Add tabs
        self.tab_network = self.tabview.add("Network")
        self.tab_display = self.tabview.add("Display")
        self.tab_logging = self.tabview.add("Logging")
        self.tab_advanced = self.tabview.add("Advanced")

        # Create tab contents
        self.network_tab = NetworkScanningTab(self.tab_network)
        self.network_tab.pack(fill="both", expand=True, padx=10, pady=10)

        self.display_tab = DisplaySettingsTab(self.tab_display)
        self.display_tab.pack(fill="both", expand=True, padx=10, pady=10)

        self.logging_tab = LoggingSettingsTab(self.tab_logging)
        self.logging_tab.pack(fill="both", expand=True, padx=10, pady=10)

        self.advanced_tab = AdvancedSettingsTab(self.tab_advanced)
        self.advanced_tab.pack(fill="both", expand=True, padx=10, pady=10)

        # Create button frame
        self.button_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.button_frame.pack(fill="x", pady=(10, 0))

        # Add buttons
        self.cancel_button = ctk.CTkButton(
            self.button_frame,
            text="Cancel",
            command=self.on_cancel,
            width=100,
            fg_color="transparent",
            border_width=1,
            text_color=("gray10", "gray90")
        )
        self.cancel_button.pack(side="right", padx=(10, 0))

        self.save_button = ctk.CTkButton(
            self.button_frame,
            text="Save",
            command=self.on_save,
            width=100
        )
        self.save_button.pack(side="right")

        # Load current settings and set up close handler
        self.load_settings()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def load_settings(self) -> None:
        """Load current settings into all tabs."""
        self.network_tab.load_settings(self.settings)
        self.display_tab.load_settings(self.settings)
        self.logging_tab.load_settings(self.settings)
        self.advanced_tab.load_settings(self.settings)

    def get_settings(self) -> Dict[str, Any]:
        """
        Get the current settings from all tabs.

        Returns:
            Dictionary containing all settings merged from all tabs
        """
        # Get settings from each tab
        network_settings = self.network_tab.get_settings()
        display_settings = self.display_tab.get_settings()
        logging_settings = self.logging_tab.get_settings()
        advanced_settings = self.advanced_tab.get_settings()

        # Merge settings, preserving any settings not handled by the tabs
        merged_settings = {**self.settings}
        merged_settings.update(network_settings)
        merged_settings.update(display_settings)
        merged_settings.update(logging_settings)
        merged_settings.update(advanced_settings)

        return merged_settings

    def on_save(self) -> None:
        """Save settings and close the dialog."""
        try:
            new_settings = self.get_settings()
            self.save_callback(new_settings)
            self.result = True
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")

    def on_cancel(self) -> None:
        """Cancel without saving and close the dialog."""
        self.result = False
        self.destroy()

    def show(self) -> bool:
        """
        Show the dialog and wait for it to be closed.

        Returns:
            True if settings were saved, False if canceled
        """
        self.wait_window()
        return self.result