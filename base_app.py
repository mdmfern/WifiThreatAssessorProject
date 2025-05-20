"""
Base Application for Wi-Fi Threat Assessor.

This module provides a base class for the main application with common functionality
for settings management, theme management, window management, and system tray integration.
It serves as the foundation for the Wi-Fi Threat Assessor application, handling core
functionality that is shared across the application.
"""

from tkinter import messagebox
import customtkinter as ctk
import common_utils
from ui_constants import DEFAULT_SETTINGS
from notification_manager import NotificationManager

# Check if system tray functionality is available
try:
    from system_tray import SystemTrayApp
    SYSTEM_TRAY_AVAILABLE = True
except ImportError:
    SYSTEM_TRAY_AVAILABLE = False


class BaseApp(ctk.CTk):
    """
    Base application class with common functionality.

    This class provides core functionality for the Wi-Fi Threat Assessor application,
    including settings management, theme handling, window management, and system tray
    integration. It serves as a parent class for the main application, providing
    common methods and attributes that are used throughout the application.
    """

    def __init__(self):
        """
        Initialize the base application.

        Sets up the application with default settings, initializes the notification
        manager, configures the window close handler, and loads saved settings.
        """
        super().__init__()

        # Initialize settings with defaults
        self.settings = DEFAULT_SETTINGS.copy()

        # Initialize notification manager
        self.notification_manager = NotificationManager()

        # System tray reference (initialized later if available)
        self.system_tray = None

        # Flag to indicate if UI has been created
        self.ui_created = False

        # Set up window close handler
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Load saved settings at startup - will be applied after UI is created
        self.load_settings()

    def load_settings(self):
        """
        Load settings from the configuration file.

        Attempts to load settings from the 'wifi_scanner_settings.json' file.
        If loading fails, displays an error message and falls back to default settings.
        """
        try:
            settings = common_utils.load_json('wifi_scanner_settings.json', DEFAULT_SETTINGS)
            self.update_settings(settings)
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Failed to load settings: {str(e)}"
            )
            self.use_default_settings()

    def use_default_settings(self):
        """
        Apply default settings to the application.

        Resets all settings to their default values as defined in DEFAULT_SETTINGS.
        """
        self.update_settings(DEFAULT_SETTINGS)

    def update_settings(self, settings):
        """
        Update application settings and apply changes.

        This method updates the application settings, applies appearance changes,
        updates the UI theme if the UI has been created, handles system tray
        settings changes, and saves the settings to file.

        Args:
            settings: Dictionary containing the new settings to apply
        """
        # Store old system tray settings for comparison
        old_enable_system_tray = self.settings.get('enable_system_tray', True)
        old_tray_notifications = self.settings.get('tray_notifications', True)

        # Update settings dictionary
        self.settings = settings.copy()

        # Apply appearance settings
        ctk.set_appearance_mode(settings.get('appearance', 'System'))
        ctk.set_default_color_theme(settings.get('theme', 'blue'))

        # Only apply UI styling if the UI has been created
        if hasattr(self, 'ui_created') and self.ui_created:
            # Apply interface styling
            self._apply_interface_styling(settings)

            # Update UI theme
            self._update_ui_theme()

        # Handle system tray settings changes if system tray is available
        if SYSTEM_TRAY_AVAILABLE:
            enable_system_tray = settings.get('enable_system_tray', True)

            # If system tray setting changed
            if enable_system_tray != old_enable_system_tray:
                if enable_system_tray:
                    # Enable system tray if it was disabled
                    if not self.system_tray:
                        self.initialize_system_tray()
                else:
                    # Disable system tray if it was enabled
                    if self.system_tray:
                        self.system_tray.stop()
                        self.system_tray = None

            # Update notification manager settings
            self.notification_manager.update_settings(settings)

            # If system tray is active, update its icon if notification settings changed
            if self.system_tray and enable_system_tray:
                if old_tray_notifications != settings.get('tray_notifications', True):
                    self.system_tray.stop()
                    self.system_tray = SystemTrayApp(self)
                    self.system_tray.run()
                    self.notification_manager.set_tray_icon(self.system_tray.icon)

        # Note: Subclasses should call this method with super().update_settings(settings)
        # and then handle their specific settings

        # Save settings to file
        try:
            common_utils.save_json(self.settings, 'wifi_scanner_settings.json')
        except Exception as e:
            messagebox.showerror(
                "Settings Error",
                f"Failed to save settings to file: {str(e)}\n\nSettings will be applied for this session only."
            )

    def _apply_interface_styling(self, _settings):
        """
        Apply interface styling based on settings.

        This is a placeholder method that should be overridden by subclasses
        to implement specific interface styling based on the application settings.

        Args:
            _settings: Dictionary containing settings (unused in base class)
        """
        pass

    def _update_ui_theme(self):
        """
        Update UI theme based on settings.

        This is a placeholder method that should be overridden by subclasses
        to implement specific UI theme updates based on the application settings.
        """
        pass

    def initialize_system_tray(self):
        """
        Initialize the system tray icon if available and enabled in settings.

        Creates a system tray icon with menu options and sets up the notification manager.
        If system tray initialization fails, displays a warning message and continues
        without system tray functionality.
        """
        # Skip if system tray is not available
        if not SYSTEM_TRAY_AVAILABLE:
            return

        try:
            # Only initialize if enabled in settings
            if self.settings.get('enable_system_tray', True):
                # Create and start the system tray application
                self.system_tray = SystemTrayApp(self)
                self.system_tray.run()

                # Set the tray icon in the notification manager
                self.notification_manager.set_tray_icon(self.system_tray.icon)

                # Apply settings to notification manager
                self.notification_manager.update_settings(self.settings)

        except Exception as e:
            messagebox.showwarning(
                "System Tray Error",
                f"Could not initialize system tray: {str(e)}\n\n"
                "The application will continue to run without system tray functionality."
            )

    def on_close(self):
        """
        Handle window close event.

        If system tray is available and minimize_to_tray is enabled in settings,
        minimizes the application to the system tray instead of closing it.
        Otherwise, destroys the application.
        """
        # Check if we should minimize to tray instead of closing
        if (SYSTEM_TRAY_AVAILABLE and
            self.system_tray and
            self.settings.get('minimize_to_tray', True)):
            try:
                # Cancel ALL pending after callbacks to prevent errors
                try:
                    for after_id in self.tk.call('after', 'info'):
                        try:
                            self.after_cancel(after_id)
                        except Exception:
                            pass
                except Exception:
                    pass

                # Disable all update bindings for the entire application
                try:
                    # Unbind all Configure events at the root level
                    self.unbind_all('<Configure>')
                except Exception:
                    pass

                # Disable all CustomTkinter widget updates
                self._disable_widget_updates(self)

                # Minimize to tray instead of closing
                self.withdraw()

                # Show notification if enabled
                if self.settings.get('tray_notifications', True):
                    self.notification_manager.show_notification(
                        "Wi-Fi Threat Assessor",
                        "Application is still running in the system tray",
                        "info"
                    )
            except Exception:
                # If anything fails, just destroy the app
                self.destroy_app()
        else:
            # Actually close the application
            self.destroy_app()

    def _disable_widget_updates(self, widget):
        """
        Recursively disable update events for all CustomTkinter widgets.

        This method prevents CustomTkinter widgets from updating their appearance
        when the application is minimized to the system tray, which can cause
        performance issues and errors.

        Args:
            widget: Widget to disable updates for
        """
        try:
            # Check if this is a CustomTkinter widget with _update_dimensions_event
            if hasattr(widget, '_update_dimensions_event'):
                # Unbind the update event
                try:
                    widget.unbind('<Configure>', widget._update_dimensions_event_id)
                except Exception:
                    # If specific unbinding fails, unbind all Configure events
                    widget.unbind('<Configure>')

                # Disable the draw method to prevent further updates
                if hasattr(widget, '_draw'):
                    # Use underscore prefix for unused parameters to avoid linter warnings
                    widget._draw = lambda *_args, **_kwargs: None

            # Special handling for CTkScrollableFrame
            if widget.__class__.__name__ == 'CTkScrollableFrame':
                try:
                    # Disable the _set_scaling method
                    widget._set_scaling = lambda *_: None

                    # Disable the _update_dimensions method
                    widget._update_dimensions = lambda *_: None

                    # Disable the _create_grid method
                    if hasattr(widget, '_create_grid'):
                        widget._create_grid = lambda *_: None
                except Exception:
                    pass

            # Process all children recursively
            for child in widget.winfo_children():
                self._disable_widget_updates(child)

        except Exception:
            # Silently handle any exceptions during widget update disabling
            pass

    def destroy_app(self):
        """
        Clean up resources and close the application.

        This method performs a thorough cleanup before destroying the application:
        1. Cancels all pending after callbacks
        2. Disables all CustomTkinter widget updates
        3. Destroys all child widgets
        4. Stops the system tray if active
        5. Destroys the main window

        Each step is wrapped in its own try-except block to ensure that failure
        in one step doesn't prevent the others from executing.
        """
        # Cancel any pending after callbacks
        try:
            for after_id in self.tk.call('after', 'info'):
                self.after_cancel(after_id)
        except Exception:
            # Continue with cleanup even if this step fails
            pass

        # Disable all CustomTkinter widget updates
        try:
            self._disable_widget_updates(self)
        except Exception:
            # Continue with cleanup even if this step fails
            pass

        # Destroy all child widgets first to prevent Tcl errors
        try:
            for widget in self.winfo_children():
                try:
                    widget.destroy()
                except Exception:
                    # Continue with other widgets even if one fails
                    pass
        except Exception:
            # Continue with cleanup even if this step fails
            pass

        # Stop system tray if active
        if self.system_tray:
            try:
                self.system_tray.stop()
            except Exception:
                # Continue with cleanup even if this step fails
                pass

        # Destroy the main window
        try:
            self.destroy()
        except Exception:
            # At this point, we've done all we can to clean up
            pass
