"""
Wi-Fi Threat Assessor - Main Application Module

This module contains the main application class for the Wi-Fi Threat Assessor,
providing functionality for scanning networks, displaying network information,
and generating security reports.
"""

# Standard library imports
import datetime
import threading
from tkinter import messagebox, filedialog

# Third-party imports
import customtkinter as ctk

# Local application imports
import security_utils
import wifi_logger
import wifi_utils
from automated_notifications import AutomatedNotificationSystem
from base_app import BaseApp
from scrollable_network_frame import ScrollableNetworkFrame
from settings_manager import SettingsDialog
from speed_test import SpeedTest
from speed_test_logger import SpeedTestLogger
from state_manager import StateManager

# Optional imports - SystemTrayApp is used in BaseApp but we need to check availability
try:
    # Import but don't use directly - BaseApp will use it
    from system_tray import SystemTrayApp  # noqa: F401
    SYSTEM_TRAY_AVAILABLE = True
except ImportError:
    SYSTEM_TRAY_AVAILABLE = False

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class WiFiScannerApp(BaseApp):
    """
    Main application class for the Wi-Fi Threat Assessor.

    This class extends BaseApp to provide Wi-Fi scanning, network display,
    security auditing, and reporting functionality. It manages the main UI
    and coordinates between different modules of the application.
    """

    def __init__(self):
        """Initialize the Wi-Fi Scanner application with UI components and state management."""
        # Initialize instance variables before calling super().__init__()
        # to ensure they exist when BaseApp methods are called
        self.scanning = False
        self.current_tab = "networks"  # Default tab

        # Call parent class initializer
        super().__init__()

        # Initialize state manager
        self.state_manager = StateManager()

        # Initialize state with default values
        self._initialize_state()

        # Initialize loggers
        self.speed_test_logger = SpeedTestLogger()

        # Configure main window
        self.title("Wi-Fi Threat Assessor")
        self.geometry("900x700")  # Increased initial size for better display
        self.minsize(800, 600)  # Minimum size to ensure enough space for network list

        # Create modern header with gradient-like effect
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=("#1f538d", "#1f538d"))
        self.header_frame.pack(fill="x", padx=0, pady=0)

        # Add subtle accent line at the bottom of header
        accent_line = ctk.CTkFrame(self.header_frame, height=2, fg_color=("#3498db", "#3498db"))
        accent_line.pack(side="bottom", fill="x")

        # App title with modern typography and icon
        title_container = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_container.pack(side="left", padx=15, pady=10)

        # Wi-Fi icon
        wifi_icon = "📶"  # Wi-Fi icon

        self.title_label = ctk.CTkLabel(
            title_container,
            text=f"{wifi_icon} Wi-Fi Threat Assessor",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color="white"
        )
        self.title_label.pack(side="left")

        # Create a button container for better organization
        button_container = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        button_container.pack(side="right", padx=20, pady=10)  # More padding around buttons

        # Define common button style with more subtle appearance
        button_style = {
            "font": ctk.CTkFont(family="Segoe UI", size=12),  # More subtle font
            "corner_radius": 4,  # Less rounded corners
            "fg_color": ("#3498db", "#2980b9"),  # Brighter blue for better visibility
            "hover_color": ("#2980b9", "#1f6aa5"),  # Darker blue on hover
            "height": 32,  # Slightly shorter height
            "border_width": 0,  # No border for cleaner look
            "text_color": "white"
        }

        # Create a more visually separated button layout

        # Refresh button with clear, recognizable name
        self.refresh_button = ctk.CTkButton(
            button_container,
            text="Refresh",  # Simple, recognizable name
            command=lambda: self.scan_networks(force_refresh=True),
            width=110,  # Standard width
            **button_style
        )
        self.refresh_button.pack(side="left", padx=8, pady=5)  # Consistent spacing

        # Settings button with descriptive tooltip
        self.settings_button = ctk.CTkButton(
            button_container,
            text="Settings",
            command=self.open_settings,
            width=110,
            **button_style
        )
        self.settings_button.pack(side="left", padx=8, pady=5)

        # Add tooltip effect to settings button
        self._add_button_tooltip(self.settings_button, "Settings", "App Settings")

        # Security Audit button with descriptive tooltip
        self.audit_button = ctk.CTkButton(
            button_container,
            text="Security Audit",
            command=self.generate_security_audit,
            width=130,
            **button_style
        )
        self.audit_button.pack(side="left", padx=8, pady=5)

        # Add tooltip effect to audit button
        self._add_button_tooltip(self.audit_button, "Security Audit", "Generate Report")

        # Speed Test button with descriptive tooltip
        self.speed_test_button = ctk.CTkButton(
            button_container,
            text="Speed Test",
            command=self.open_speed_test,
            width=110,
            **button_style
        )
        self.speed_test_button.pack(side="left", padx=8, pady=5)

        # Add tooltip effect to speed test button
        self._add_button_tooltip(self.speed_test_button, "Speed Test", "Test Internet")

        # Create tab container
        self.tab_container = ctk.CTkFrame(self, fg_color="transparent")
        self.tab_container.pack(fill="x", padx=15, pady=(10, 0))

        # Tab button style
        tab_button_style = {
            "font": ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            "corner_radius": 6,
            "border_width": 1,
            "height": 36,
            "width": 160
        }

        # Networks tab button
        self.networks_tab_button = ctk.CTkButton(
            self.tab_container,
            text="Networks",
            command=lambda: self.switch_tab("networks"),
            fg_color=("#3498db", "#2980b9"),  # Active tab color
            hover_color=("#2980b9", "#1f6aa5"),
            border_color=("#3498db", "#2980b9"),
            text_color="white",
            **tab_button_style
        )
        self.networks_tab_button.pack(side="left", padx=(0, 5), pady=5)

        # Connection History tab button
        self.history_tab_button = ctk.CTkButton(
            self.tab_container,
            text="Connection History",
            command=lambda: self.switch_tab("history"),
            fg_color=("gray90", "gray20"),  # Inactive tab color
            hover_color=("#2980b9", "#1f6aa5"),
            border_color=("#3498db", "#2980b9"),
            text_color=("gray50", "gray70"),
            **tab_button_style
        )
        self.history_tab_button.pack(side="left", padx=5, pady=5)

        # Speed Test History tab button
        self.speed_history_tab_button = ctk.CTkButton(
            self.tab_container,
            text="Speed Test History",
            command=lambda: self.switch_tab("speed_history"),
            fg_color=("gray90", "gray20"),  # Inactive tab color
            hover_color=("#2980b9", "#1f6aa5"),
            border_color=("#3498db", "#2980b9"),
            text_color=("gray50", "gray70"),
            **tab_button_style
        )
        self.speed_history_tab_button.pack(side="left", padx=5, pady=5)

        # Modern status bar with subtle gradient and fixed height
        self.status_frame = ctk.CTkFrame(
            self,
            height=36,
            corner_radius=0,
            fg_color=("#f8f9fa", "#2d3436")  # Lighter/darker background for contrast
        )
        self.status_frame.pack(fill="x", padx=0, pady=0)
        self.status_frame.pack_propagate(False)  # Maintain fixed height

        # Add subtle top border
        status_border = ctk.CTkFrame(self.status_frame, height=1, fg_color=("gray80", "gray30"))
        status_border.pack(side="top", fill="x")

        # Status labels with icons and improved typography
        status_left = ctk.CTkFrame(self.status_frame, fg_color="transparent")
        status_left.pack(side="left", fill="y")

        # Networks found label without icon for clearer text
        self.networks_found_label = ctk.CTkLabel(
            status_left,
            text="Found 1 network",  # Removed icon for clearer text
            font=ctk.CTkFont(size=12, weight="bold"),  # Bold for better visibility
            text_color=("#2ecc71", "#2ecc71")
        )
        self.networks_found_label.pack(side="left", padx=(15, 10), pady=8)

        # Add a separator
        separator = ctk.CTkFrame(status_left, width=1, fg_color=("gray80", "gray60"))
        separator.pack(side="left", fill="y", padx=10, pady=8)

        # Last scan time (new feature)
        self.last_scan_label = ctk.CTkLabel(
            status_left,
            text="Last scan: Just now",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=("gray50", "gray70")
        )
        self.last_scan_label.pack(side="left", padx=10, pady=8)

        # Connection status without icon for clearer text
        self.connection_label = ctk.CTkLabel(
            self.status_frame,
            text="Connected to: SLT-4G_1F1F76 (97%)",  # Removed icon for clearer text
            font=ctk.CTkFont(size=12, weight="bold"),  # Bold for better visibility
            text_color=("#2ecc71", "#2ecc71")
        )
        self.connection_label.pack(side="right", padx=(10, 15), pady=8)

        # Create a container frame for tab content
        self.content_container = ctk.CTkFrame(self, fg_color="transparent")
        self.content_container.pack(fill="both", expand=True, padx=15, pady=(5, 15))

        # Networks tab content
        self.networks_content = ctk.CTkFrame(self.content_container, fg_color="transparent")
        self.networks_content.pack(fill="both", expand=True)

        # Network list section with modern card-style title
        self.title_frame = ctk.CTkFrame(
            self.networks_content,
            fg_color=("#f0f4f8", "#2d3436"),  # Subtle background color
            corner_radius=10,
            height=50
        )
        self.title_frame.pack(fill="x", pady=(0, 15))
        self.title_frame.pack_propagate(False)  # Maintain fixed height

        # Available Networks title with clearer text
        self.networks_title = ctk.CTkLabel(
            self.title_frame,
            text="Available Networks",  # Removed icon for clearer text
            font=ctk.CTkFont(size=14, weight="bold"),  # Slightly smaller font
            text_color=("#1f538d", "#3498db")  # Brand color for consistency
        )
        self.networks_title.pack(side="left", padx=15, pady=12)

        # Network list with modern card-style design - increased size for better readability
        self.networks_frame = ScrollableNetworkFrame(
            self.networks_content,
            label_text="",
            fg_color=("gray95", "#1e2124"),  # Lighter/darker background for better contrast
            corner_radius=12,  # More rounded corners for modern look
            border_width=1,    # Subtle border
            border_color=("gray85", "#3d3d3d")  # Subtle border color
        )
        self.networks_frame.pack(fill="both", expand=True)

        # Connection History tab content (initially hidden)
        self.history_content = ctk.CTkFrame(self.content_container, fg_color="transparent")

        # Create the connection log panel
        self.connection_log_panel = wifi_logger.ConnectionLogPanel(self.history_content)
        self.connection_log_panel.pack(fill="both", expand=True)

        # Speed Test History tab content (initially hidden)
        self.speed_history_content = ctk.CTkFrame(self.content_container, fg_color="transparent")

        # Create the speed test history panel
        from speed_test_history import SpeedTestHistoryPanel
        self.speed_history_panel = SpeedTestHistoryPanel(self.speed_history_content)
        self.speed_history_panel.pack(fill="both", expand=True)

        # Initially hide the history content
        self.history_content.pack_forget()
        self.speed_history_content.pack_forget()

        # Variable to track if a scan is in progress
        self.scanning = False

        # Perform initial network scan
        self.update_connection_status()
        self.scan_networks()

        # Load saved settings at startup
        self.load_settings()

        # Mark UI as created
        self.ui_created = True

        # Apply settings now that UI is created
        self._update_ui_theme()

        # Initialize system tray if available and enabled
        self.initialize_system_tray()

        # Set up window close handler
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def switch_tab(self, tab_name):
        """
        Switch between tabs.

        Args:
            tab_name: Name of the tab to switch to
        """
        # Check if already on this tab
        if tab_name == self.current_tab:
            return

        # Update state
        self.state_manager.set_state('current_tab', tab_name)
        self.current_tab = tab_name  # Keep for backward compatibility

        # Reset all tab buttons to inactive state
        for button in [self.networks_tab_button, self.history_tab_button, self.speed_history_tab_button]:
            button.configure(
                fg_color=("gray90", "gray20"),  # Inactive tab color
                text_color=("gray50", "gray70")
            )

        # Hide all content frames
        for frame in [self.networks_content, self.history_content, self.speed_history_content]:
            frame.pack_forget()

        # Map of tab names to their UI components and refresh functions
        tab_config = {
            "networks": {
                "button": self.networks_tab_button,
                "content": self.networks_content,
                "refresh": lambda: self._refresh_networks_if_needed()
            },
            "history": {
                "button": self.history_tab_button,
                "content": self.history_content,
                "refresh": lambda: self.connection_log_panel.refresh_logs()
            },
            "speed_history": {
                "button": self.speed_history_tab_button,
                "content": self.speed_history_content,
                "refresh": lambda: self.speed_history_panel.refresh_logs()
            }
        }

        # Apply configuration for the selected tab
        if tab_name in tab_config:
            config = tab_config[tab_name]

            # Activate tab button
            config["button"].configure(
                fg_color=("#3498db", "#2980b9"),  # Active tab color
                text_color="white"
            )

            # Show tab content
            config["content"].pack(fill="both", expand=True)

            # Refresh tab content
            config["refresh"]()

        # Update UI theme to reflect the current tab
        self._update_ui_theme()

    def _refresh_networks_if_needed(self):
        """Refresh networks if not currently scanning."""
        if not self.state_manager.get_state('scanning'):
            self.scan_networks(force_refresh=False)

    def open_connection_history(self):
        self.switch_tab("history")

    def open_speed_test_history(self):
        self.switch_tab("speed_history")

    def open_speed_test(self):
        connection = wifi_utils.get_connection_status()

        if not connection:
            messagebox.showwarning(
                "Not Connected",
                "You are not currently connected to any Wi-Fi network. "
                "The speed test requires an active internet connection."
            )
            return

        speed_test_window = SpeedTest(self)
        speed_test_window.focus()

    def update_connection_status(self):
        """Update the connection status display."""
        # Get current connection from state manager or fetch it
        if hasattr(self, 'state_manager'):
            connection = self.state_manager.get_state('current_connection')
            if connection is None:
                connection = wifi_utils.get_connection_status()
                if connection:
                    self.state_manager.set_state('current_connection', connection)
        else:
            connection = wifi_utils.get_connection_status()

        if connection:
            # Get security color based on authentication type
            security_color = security_utils.get_security_color(connection.get('auth_type', ''))

            # Create connection text
            connection_text = f"Connected to: {connection['ssid']} ({connection['signal']}%)"
            if 'auth_type' in connection:
                connection_text += f" | {connection['auth_type']}"

            # Update connection label
            self.connection_label.configure(
                text=connection_text,
                text_color=("#2ecc71", "#2ecc71"),
                font=ctk.CTkFont(size=12, weight="bold")
            )

            # Update or create connection indicator
            if hasattr(self, 'connection_indicator'):
                self.connection_indicator.configure(fg_color=security_color)
            else:
                self.connection_indicator = ctk.CTkFrame(
                    self.title_frame,
                    width=10,
                    height=10,
                    corner_radius=5,
                    fg_color=security_color
                )
                self.connection_indicator.pack(side="right", padx=15)
        else:
            # Update connection label for not connected state
            self.connection_label.configure(
                text="Not connected",
                text_color=("gray50", "gray70"),
                font=ctk.CTkFont(size=12)
            )

            # Update connection indicator for not connected state
            if hasattr(self, 'connection_indicator'):
                self.connection_indicator.configure(fg_color=("gray70", "gray50"))

    def scan_networks(self, force_refresh: bool = False):
        """
        Scan for Wi-Fi networks.

        Args:
            force_refresh: Whether to force a refresh of the network list
        """
        # Check if already scanning
        if self.state_manager.get_state('scanning'):
            return

        # Update scanning state
        self.state_manager.set_state('scanning', True)
        self.scanning = True  # For backward compatibility

        # Update UI to show scanning in progress
        self._update_ui_for_scanning_start()

        def scan_thread():
            """Worker thread to perform network scanning."""
            try:
                # Scan for networks
                networks = wifi_utils.scan_networks(force_refresh=force_refresh)

                # Update state and UI on the main thread
                self.after(0, lambda: self._update_network_display(networks))
            except Exception as e:
                # Handle errors on the main thread
                self.after(0, lambda: self._handle_scan_error(str(e)))
            finally:
                # Reset scanning state
                self.scanning = False
                self.state_manager.set_state('scanning', False)

                # Reset refresh button on the main thread
                self.after(0, self._update_ui_for_scanning_end)

        # Start scanning in a separate thread
        threading.Thread(target=scan_thread, daemon=True).start()

    def _update_ui_for_scanning_start(self):
        """Update UI elements to indicate scanning has started."""
        self.refresh_button.configure(
            state="disabled",
            text="Refreshing...",
            fg_color=("#5dade2", "#3498db"),
            border_width=0
        )
        self.networks_found_label.configure(
            text="Scanning for networks...",
            text_color=("#f39c12", "#f39c12")
        )
        self.last_scan_label.configure(
            text="Scanning in progress...",
            text_color=("#f39c12", "#f39c12")
        )

    def _update_ui_for_scanning_end(self):
        """Update UI elements to indicate scanning has completed."""
        self.refresh_button.configure(
            state="normal",
            text="Refresh",
            fg_color=("#3498db", "#2980b9"),
            border_width=0
        )

    def _update_network_display(self, networks):
        """
        Update the network display with the scanned networks.

        Args:
            networks: List of network dictionaries
        """
        # Sort networks by signal strength
        networks.sort(key=lambda x: x['signal'], reverse=True)

        # Update state if state manager exists
        if hasattr(self, 'state_manager'):
            self.state_manager.set_state('networks', networks)
            self.state_manager.set_state('network_count', len(networks))
            self.state_manager.set_state('last_scan_time', datetime.datetime.now())

        # Update UI
        self.networks_frame.update_networks(networks)

        # Log current connection
        current_connection = wifi_utils.get_connection_status()
        if current_connection:
            # Update state if state manager exists
            if hasattr(self, 'state_manager'):
                self.state_manager.set_state('current_connection', current_connection)

            # Log connection
            logger = wifi_logger.WiFiConnectionLogger()
            logger.log_connection(current_connection)

        # Update connection status in UI
        self.update_connection_status()

        # Update network count label
        network_count = len(networks)
        network_text = "network" if network_count == 1 else "networks"

        if networks:
            self.networks_found_label.configure(
                text=f"Found {network_count} {network_text}",
                text_color=("#2ecc71", "#2ecc71")
            )
        else:
            self.networks_found_label.configure(
                text="No networks found",
                text_color=("#e74c3c", "#e74c3c")
            )

        # Update last scan time label
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        self.last_scan_label.configure(
            text=f"Last scan: {current_time}"
        )

    def _handle_scan_error(self, error_message):
        self.networks_found_label.configure(
            text=f"Error scanning networks",
            text_color=("#e74c3c", "#e74c3c")
        )

        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        self.last_scan_label.configure(
            text=f"Scan failed at {current_time}",
            text_color=("#e74c3c", "#e74c3c")
        )

        messagebox.showerror(
            "Scan Error",
            f"An error occurred while scanning networks:\n\n{error_message}\n\nPlease try again or check your Wi-Fi adapter."
        )



    def open_settings(self):
        self.settings_dialog = SettingsDialog(self, self.settings, self.update_settings)
        self.settings_dialog.focus_force()

    def destroy(self):
        """Clean up and close the application."""
        # Call the parent class method
        super().destroy()

    def update_settings(self, settings):
        """
        Update application settings.

        Args:
            settings: Dictionary containing settings
        """
        # Call the parent class method to handle common settings
        super().update_settings(settings)

        # Update WiFiScannerApp specific settings
        self.log_retention = settings.get('log_retention', 30)
        self.auto_logging = settings.get('auto_logging', True)

        # Handle automated notification settings
        if SYSTEM_TRAY_AVAILABLE and self.system_tray:
            enable_auto_notifications = settings.get('enable_automated_notifications', True)
            notification_interval = settings.get('notification_interval', 600)

            # Update or create automated notifications
            if hasattr(self, 'automated_notifications') and self.automated_notifications:
                if enable_auto_notifications:
                    # Update interval if changed
                    if self.automated_notifications.notification_interval != notification_interval:
                        self.automated_notifications.set_interval(notification_interval)

                    # Make sure it's running if it should be
                    if not self.automated_notifications.enabled:
                        self.automated_notifications.start()
                else:
                    # Stop if it should be disabled
                    if self.automated_notifications.enabled:
                        self.automated_notifications.stop()
            elif enable_auto_notifications:
                # Create new automated notifications if needed
                self.automated_notifications = AutomatedNotificationSystem(
                    self,
                    self.system_tray,
                    self.notification_manager,
                    notification_interval
                )
                self.automated_notifications.start()

        # Refresh the network display if UI is created
        if hasattr(self, 'ui_created') and self.ui_created:
            self.after(100, lambda: self.scan_networks(force_refresh=True))



    def _apply_interface_styling(self, settings):
        """
        Apply interface styling based on settings.

        Args:
            settings: Dictionary containing settings
        """
        corner_radius = settings.get('corner_radius', 8)

        for widget in [self.title_frame, self.networks_frame, self.networks_tab_button,
                      self.history_tab_button, self.speed_history_tab_button,
                      self.connection_log_panel]:
            if hasattr(widget, 'configure'):
                try:
                    widget.configure(corner_radius=corner_radius)
                except Exception:
                    pass

        density = settings.get('interface_density', 'Standard')
        if density == 'Compact':
            padding = 5
        elif density == 'Comfortable':
            padding = 15
        else:
            padding = 10

        if hasattr(self.networks_frame, 'update_padding'):
            try:
                self.networks_frame.update_padding(padding)
            except Exception:
                pass

        self._apply_font_size()

    def _apply_font_size(self):
        """Apply font sizes based on settings."""
        font_size = self.settings.get('font_size', 'Medium')
        font_family = self.settings.get('font_family', 'Segoe UI')

        font_sizes = {
            'Small': {
                'header': 14,
                'button': 11,
                'label': 10,
                'title': 12
            },
            'Medium': {
                'header': 16,
                'button': 12,
                'label': 12,
                'title': 14
            },
            'Large': {
                'header': 18,
                'button': 14,
                'label': 14,
                'title': 16
            },
            'Extra Large': {
                'header': 22,
                'button': 16,
                'label': 16,
                'title': 20
            }
        }

        sizes = font_sizes.get(font_size, font_sizes['Medium'])

        try:
            self.title_label.configure(font=ctk.CTkFont(family=font_family, size=sizes['header'], weight="bold"))
        except Exception:
            pass

        for button in [self.refresh_button, self.settings_button,
                      self.speed_test_button, self.audit_button]:
            try:
                button.configure(font=ctk.CTkFont(family=font_family, size=sizes['button']))
            except Exception:
                pass

        for button in [self.networks_tab_button, self.history_tab_button,
                       self.speed_history_tab_button]:
            try:
                button.configure(font=ctk.CTkFont(family=font_family, size=sizes['button'], weight="bold"))
            except Exception:
                pass

        for label in [self.networks_found_label, self.last_scan_label, self.connection_label]:
            try:
                label.configure(font=ctk.CTkFont(family=font_family, size=sizes['label']))
            except Exception:
                pass

        try:
            self.networks_title.configure(font=ctk.CTkFont(family=font_family, size=sizes['title'], weight="bold"))
        except Exception:
            pass

        try:
            if hasattr(self.networks_frame, '_header_frame'):
                for child in self.networks_frame._header_frame.winfo_children():
                    if isinstance(child, ctk.CTkLabel):
                        child.configure(font=ctk.CTkFont(family=font_family, size=sizes['label'], weight="bold"))
        except Exception:
            pass

    def _update_ui_theme(self):
        """Update UI theme based on settings."""
        # Default colors
        primary_color = "#1f538d"
        secondary_color = "#3498db"
        hover_color = "#2980b9"

        # Update header color
        self.header_frame.configure(fg_color=primary_color)

        # Update all action buttons with consistent colors
        button_colors = {
            "fg_color": secondary_color,
            "hover_color": hover_color
        }

        for button in [self.refresh_button, self.settings_button,
                      self.speed_test_button, self.audit_button]:
            button.configure(**button_colors)

        # Update tab buttons - first set all to inactive
        inactive_tab_style = {
            "fg_color": ("gray90", "gray20"),
            "text_color": ("gray50", "gray70"),
            "border_color": secondary_color
        }

        active_tab_style = {
            "fg_color": secondary_color,
            "hover_color": hover_color,
            "border_color": secondary_color,
            "text_color": "white"
        }

        # Map of tab names to their buttons
        tab_buttons = {
            "networks": self.networks_tab_button,
            "history": self.history_tab_button,
            "speed_history": self.speed_history_tab_button
        }

        # Set all tabs to inactive first
        for button in tab_buttons.values():
            button.configure(**inactive_tab_style)

        # Set the active tab
        if self.current_tab in tab_buttons:
            tab_buttons[self.current_tab].configure(**active_tab_style)

        # Update status frame color based on appearance mode
        appearance = self.settings.get('appearance', 'System')
        if appearance == 'Dark':
            self.status_frame.configure(fg_color="#333333")
        elif appearance == 'Light':
            self.status_frame.configure(fg_color="#f0f0f0")
        else:
            self.status_frame.configure(fg_color=("#f0f0f0", "#333333"))

        # Update network frame color
        self.networks_frame.configure(fg_color=("gray78", "#2d2d2d"))

        # Apply font sizes
        self._apply_font_size()

        # Update the UI
        self.update()

    # load_settings and use_default_settings methods are inherited from BaseApp

    def generate_security_audit(self):
        """Generate a security audit report for available Wi-Fi networks."""
        # Update UI to show report generation is in progress
        self.networks_found_label.configure(
            text="Generating security audit report...",
            text_color=("#f39c12", "#f39c12")
        )
        self.update_idletasks()

        try:
            # Import required modules here to avoid circular imports
            import time
            from security_audit import SecurityAudit
            from wifi_report_generator import SecurityReportGenerator

            # Start timing the scan
            scan_start_time = time.time()

            # Scan for networks
            networks = wifi_utils.scan_networks(force_refresh=True)
            if not networks:
                self._handle_no_networks()
                return

            # Generate audit data
            auditor = SecurityAudit()
            audit_data = auditor.generate_network_audit(networks)
            scan_duration = time.time() - scan_start_time

            # Create report generator
            report_gen = SecurityReportGenerator(audit_data, networks, scan_duration)

            # Generate default filename based on networks
            default_filename = self._generate_report_filename(networks)

            # Ask user where to save the report
            file_path = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")],
                initialfile=default_filename,
                title="Save Security Audit Report"
            )

            # Generate and open the report if a path was selected
            if file_path:
                self._generate_and_open_report(report_gen, file_path)

            # Update UI to show scan results
            self.networks_found_label.configure(
                text=f"Found {len(networks)} networks",
                text_color=("#2ecc71", "#2ecc71")
            )

        except Exception as e:
            self._handle_audit_error(e)

    def _handle_no_networks(self):
        """Handle the case when no networks are found for audit."""
        messagebox.showinfo(
            "No Networks",
            "No WiFi networks were found to analyze. Please try again when networks are available."
        )
        self.networks_found_label.configure(
            text="No networks found",
            text_color=("#e74c3c", "#e74c3c")
        )

    def _generate_report_filename(self, networks):
        """Generate a default filename for the security audit report."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if len(networks) == 1:
            ssid = networks[0].get('ssid', 'Unknown').replace(' ', '_')
            return f"Security_Audit_Report_{ssid}_{timestamp}.pdf"
        else:
            return f"Security_Audit_Report_Multiple_Networks_{timestamp}.pdf"

    def _generate_and_open_report(self, report_gen, file_path):
        """Generate the report and offer to open it."""
        try:
            report_path = report_gen.generate_report(file_path)

            messagebox.showinfo(
                "Report Generated",
                f"Security audit report has been saved to:\n{report_path}"
            )

            if messagebox.askyesno(
                "Open Report",
                "Would you like to open the report now?"
            ):
                try:
                    import os
                    os.startfile(report_path)
                except Exception as e:
                    messagebox.showerror("Error Opening File", f"Could not open the PDF file: {str(e)}")
        except Exception as e:
            messagebox.showerror(
                "Report Generation Error",
                f"Failed to generate the report: {str(e)}"
            )

    def _handle_audit_error(self, error):
        """Handle errors during the audit process."""
        error_message = str(error)
        self.networks_found_label.configure(
            text=f"Error: {error_message[:30]}..." if len(error_message) > 30 else f"Error: {error_message}",
            text_color=("#e74c3c", "#e74c3c")
        )
        messagebox.showerror(
            "Audit Error",
            f"Failed to generate security audit report:\n{error_message}"
        )

    def initialize_system_tray(self):
        """Initialize the system tray icon and set up automated notifications."""
        # Call the parent class method first to initialize system tray
        super().initialize_system_tray()

        # Initialize automated notification system if system tray is available
        if SYSTEM_TRAY_AVAILABLE and self.system_tray:
            self._setup_automated_notifications()

    def _setup_automated_notifications(self):
        """Set up the automated notification system if enabled in settings."""
        # Check if automated notifications are already set up
        if hasattr(self, 'automated_notifications') and self.automated_notifications is not None:
            return

        # Check if automated notifications are enabled in settings
        if not self.settings.get('enable_automated_notifications', True):
            return

        # Create and start automated notifications
        notification_interval = self.settings.get('notification_interval', 600)  # Default: 10 minutes
        self.automated_notifications = AutomatedNotificationSystem(
            self,
            self.system_tray,
            self.notification_manager,
            notification_interval
        )
        self.automated_notifications.start()

    def on_close(self):
        """Handle window close event."""
        # Pause automated notifications
        self._pause_automated_notifications()

        # Clean up specific panels that cause issues
        self._cleanup_panels()

        # Call the parent class method
        super().on_close()

    def _pause_automated_notifications(self):
        """Pause automated notifications without stopping the timer."""
        if not hasattr(self, 'automated_notifications') or not self.automated_notifications:
            return

        try:
            # Replace the notification function with a no-op
            if hasattr(self.automated_notifications, '_send_notification'):
                self.automated_notifications._send_notification = lambda: None
        except Exception:
            # Silently ignore errors - this is just a cleanup operation
            pass

    def _cleanup_panels(self):
        """Clean up specific panels that cause issues when minimized."""
        # Clean up ConnectionLogPanel
        if hasattr(self, 'connection_log_panel'):
            try:
                # Disable any update methods
                if hasattr(self.connection_log_panel, 'refresh_logs'):
                    self.connection_log_panel.refresh_logs = lambda *_: None
            except Exception:
                pass

        # Clean up SpeedTestHistoryPanel
        if hasattr(self, 'speed_history_panel'):
            try:
                # Disable any update methods
                if hasattr(self.speed_history_panel, 'refresh_logs'):
                    self.speed_history_panel.refresh_logs = lambda *_: None

                # Clean up all canvas widgets
                for widget in self.speed_history_panel.winfo_children():
                    if widget.__class__.__name__ == 'CTkCanvas':
                        widget.delete('all')
            except Exception:
                pass

    def destroy_app(self):
        """Clean up and close the application."""
        # Stop automated notifications if active
        self._stop_automated_notifications()

        # Clear state manager observers
        self._clear_state_observers()

        # Call the parent class method
        super().destroy_app()

    def _stop_automated_notifications(self):
        """Stop the automated notification system if active."""
        if hasattr(self, 'automated_notifications') and self.automated_notifications:
            try:
                self.automated_notifications.stop()
            except Exception:
                # Silently ignore errors - this is just a cleanup operation
                pass

    def _clear_state_observers(self):
        """Clear all state manager observers."""
        if hasattr(self, 'state_manager'):
            try:
                self.state_manager.clear_observers()
            except Exception:
                # Silently ignore errors - this is just a cleanup operation
                pass

    def _on_scanning_changed(self, scanning):
        """
        Handle scanning state changes.

        Args:
            scanning: New scanning state
        """
        # Update instance variable for backward compatibility
        self.scanning = scanning

    def _initialize_state(self):
        """Initialize the application state with default values and register observers."""
        # Set initial state values
        self.state_manager.set_state('scanning', False)
        self.state_manager.set_state('current_tab', 'networks')
        self.state_manager.set_state('networks', [])
        self.state_manager.set_state('current_connection', None)
        self.state_manager.set_state('network_count', 0)
        self.state_manager.set_state('last_scan_time', None)

        # Register observers for state changes
        self.state_manager.register_observer('scanning', self._on_scanning_changed)
        self.state_manager.register_observer('current_tab', self._on_tab_changed)

    def _add_button_tooltip(self, button, default_text, hover_text):
        """
        Add a tooltip-like effect to a button by changing its text on hover.

        Args:
            button: The button widget to add the tooltip to
            default_text: The default button text
            hover_text: The text to show when hovering
        """
        def show_tooltip(_):
            button.configure(text=hover_text)

        def hide_tooltip(_):
            button.configure(text=default_text)

        button.bind("<Enter>", show_tooltip)
        button.bind("<Leave>", hide_tooltip)

    def _on_tab_changed(self, tab_name):
        """
        Handle tab changes.

        Args:
            tab_name: New tab name
        """
        # Update instance variable for backward compatibility
        self.current_tab = tab_name




if __name__ == "__main__":
    app = WiFiScannerApp()
    app.mainloop()