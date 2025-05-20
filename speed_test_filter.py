"""
Advanced Filter Dialog for Speed Test History.

This module provides a user interface for filtering speed test results based on
various criteria including date range, speed metrics, network properties, and server.
It allows users to apply complex filters to their speed test history data.
"""

import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from typing import Dict, List, Optional, Callable, Tuple
import tkcalendar

from speed_test_logger import SpeedTestLogger
from ui_constants import COLORS

class AdvancedFilterDialog(ctk.CTkToplevel):
    """Dialog for advanced filtering of speed test history.

    This class provides a modal dialog that allows users to filter speed test results
    based on date range, speed metrics (download, upload, ping), network properties
    (SSID, BSSID, security type, band), and server information.
    """

    def __init__(self, parent, callback: Callable[[Dict], None]):
        """Initialize the advanced filter dialog.

        Args:
            parent: The parent widget
            callback: Function to call with filter data when applied
        """
        super().__init__(parent)

        self.parent = parent
        self.callback = callback
        self.logger = SpeedTestLogger()

        # Initialize filter values
        self.date_filter = {'start': None, 'end': None}
        self.speed_filter = {
            'min_download': None, 'max_download': None,
            'min_upload': None, 'max_upload': None,
            'min_ping': None, 'max_ping': None
        }
        self.network_filter = {
            'ssid': None, 'bssid': None,
            'security_type': None, 'band': None
        }
        self.server_filter = None

        # Configure window
        self.title("Advanced Speed Test Filters")
        self.geometry("700x600")
        self.minsize(600, 500)
        self.grab_set()  # Make window modal

        # Create main frame
        self.main_frame = ctk.CTkScrollableFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(
            self.main_frame,
            text="Advanced Speed Test Filters",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.pack(pady=(0, 20))

        # Create filter sections
        self._create_date_filter_section()
        self._create_speed_filter_section()
        self._create_network_filter_section()
        self._create_server_filter_section()

        # Buttons
        button_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=(20, 0))

        # Apply button
        apply_button = ctk.CTkButton(
            button_frame,
            text="Apply Filters",
            command=self._apply_filters,
            font=ctk.CTkFont(size=14),
            height=36,
            corner_radius=4,
            fg_color=COLORS["primary"],
            hover_color=COLORS["primary_dark"]
        )
        apply_button.pack(side="right", padx=5)

        # Reset button
        reset_button = ctk.CTkButton(
            button_frame,
            text="Reset Filters",
            command=self._reset_filters,
            font=ctk.CTkFont(size=14),
            height=36,
            corner_radius=4,
            fg_color=COLORS["secondary"],
            hover_color=COLORS["secondary_dark"]
        )
        reset_button.pack(side="right", padx=5)

        # Cancel button
        cancel_button = ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=self.destroy,
            font=ctk.CTkFont(size=14),
            height=36,
            corner_radius=4
        )
        cancel_button.pack(side="right", padx=5)

    def _create_section(self, title):
        """Create a section with a title.

        Args:
            title: The title text for the section

        Returns:
            A CTkFrame that can be used as a container for section content
        """
        section = ctk.CTkFrame(self.main_frame)
        section.pack(fill="x", pady=(0, 15))

        # Section header
        header = ctk.CTkFrame(section, fg_color=("#e6f0fa", "#2d3748"))
        header.pack(fill="x")

        # Section title
        ctk.CTkLabel(
            header,
            text=title,
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["primary"]
        ).pack(anchor="w", padx=15, pady=10)

        # Content frame
        content = ctk.CTkFrame(section, fg_color="transparent")
        content.pack(fill="x", padx=15, pady=15)

        return content

    def _create_date_filter_section(self):
        """Create the date filter section with date pickers for start and end dates."""
        content = self._create_section("Date Range Filter")

        # Create date picker frames
        start_frame = ctk.CTkFrame(content, fg_color="transparent")
        start_frame.pack(fill="x", pady=(0, 10))

        end_frame = ctk.CTkFrame(content, fg_color="transparent")
        end_frame.pack(fill="x")

        # Start date label
        ctk.CTkLabel(
            start_frame,
            text="Start Date:",
            font=ctk.CTkFont(size=14),
            width=100,
            anchor="w"
        ).pack(side="left", padx=(0, 10))

        # Start date entry
        self.start_date_var = tk.StringVar()
        self.start_date_entry = ctk.CTkEntry(
            start_frame,
            textvariable=self.start_date_var,
            placeholder_text="YYYY-MM-DD",
            font=ctk.CTkFont(size=14),
            width=150
        )
        self.start_date_entry.pack(side="left", padx=(0, 10))

        # Start date picker button
        start_date_button = ctk.CTkButton(
            start_frame,
            text="Select",
            command=lambda: self._show_date_picker(self.start_date_var),
            font=ctk.CTkFont(size=12),
            width=70,
            height=28,
            corner_radius=4
        )
        start_date_button.pack(side="left")

        # End date label
        ctk.CTkLabel(
            end_frame,
            text="End Date:",
            font=ctk.CTkFont(size=14),
            width=100,
            anchor="w"
        ).pack(side="left", padx=(0, 10))

        # End date entry
        self.end_date_var = tk.StringVar()
        self.end_date_entry = ctk.CTkEntry(
            end_frame,
            textvariable=self.end_date_var,
            placeholder_text="YYYY-MM-DD",
            font=ctk.CTkFont(size=14),
            width=150
        )
        self.end_date_entry.pack(side="left", padx=(0, 10))

        # End date picker button
        end_date_button = ctk.CTkButton(
            end_frame,
            text="Select",
            command=lambda: self._show_date_picker(self.end_date_var),
            font=ctk.CTkFont(size=12),
            width=70,
            height=28,
            corner_radius=4
        )
        end_date_button.pack(side="left")

    def _create_speed_filter_section(self):
        """Create the speed filter section with min/max inputs for download, upload, and ping."""
        content = self._create_section("Speed Range Filter")

        # Create grid layout for speed filters
        grid_frame = ctk.CTkFrame(content, fg_color="transparent")
        grid_frame.pack(fill="x")

        # Download speed filters
        download_label = ctk.CTkLabel(
            grid_frame,
            text="Download Speed (Mbps):",
            font=ctk.CTkFont(size=14),
            anchor="w"
        )
        download_label.grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 10))

        min_download_frame = ctk.CTkFrame(grid_frame, fg_color="transparent")
        min_download_frame.grid(row=0, column=1, sticky="w", padx=(0, 20), pady=(0, 10))

        ctk.CTkLabel(
            min_download_frame,
            text="Min:",
            font=ctk.CTkFont(size=14),
            width=40,
            anchor="w"
        ).pack(side="left", padx=(0, 5))

        self.min_download_var = tk.StringVar()
        self.min_download_entry = ctk.CTkEntry(
            min_download_frame,
            textvariable=self.min_download_var,
            placeholder_text="0",
            font=ctk.CTkFont(size=14),
            width=80
        )
        self.min_download_entry.pack(side="left")

        max_download_frame = ctk.CTkFrame(grid_frame, fg_color="transparent")
        max_download_frame.grid(row=0, column=2, sticky="w", pady=(0, 10))

        ctk.CTkLabel(
            max_download_frame,
            text="Max:",
            font=ctk.CTkFont(size=14),
            width=40,
            anchor="w"
        ).pack(side="left", padx=(0, 5))

        self.max_download_var = tk.StringVar()
        self.max_download_entry = ctk.CTkEntry(
            max_download_frame,
            textvariable=self.max_download_var,
            placeholder_text="∞",
            font=ctk.CTkFont(size=14),
            width=80
        )
        self.max_download_entry.pack(side="left")

        # Upload speed filters
        upload_label = ctk.CTkLabel(
            grid_frame,
            text="Upload Speed (Mbps):",
            font=ctk.CTkFont(size=14),
            anchor="w"
        )
        upload_label.grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 10))

        min_upload_frame = ctk.CTkFrame(grid_frame, fg_color="transparent")
        min_upload_frame.grid(row=1, column=1, sticky="w", padx=(0, 20), pady=(0, 10))

        ctk.CTkLabel(
            min_upload_frame,
            text="Min:",
            font=ctk.CTkFont(size=14),
            width=40,
            anchor="w"
        ).pack(side="left", padx=(0, 5))

        self.min_upload_var = tk.StringVar()
        self.min_upload_entry = ctk.CTkEntry(
            min_upload_frame,
            textvariable=self.min_upload_var,
            placeholder_text="0",
            font=ctk.CTkFont(size=14),
            width=80
        )
        self.min_upload_entry.pack(side="left")

        max_upload_frame = ctk.CTkFrame(grid_frame, fg_color="transparent")
        max_upload_frame.grid(row=1, column=2, sticky="w", pady=(0, 10))

        ctk.CTkLabel(
            max_upload_frame,
            text="Max:",
            font=ctk.CTkFont(size=14),
            width=40,
            anchor="w"
        ).pack(side="left", padx=(0, 5))

        self.max_upload_var = tk.StringVar()
        self.max_upload_entry = ctk.CTkEntry(
            max_upload_frame,
            textvariable=self.max_upload_var,
            placeholder_text="∞",
            font=ctk.CTkFont(size=14),
            width=80
        )
        self.max_upload_entry.pack(side="left")

        # Ping filters
        ping_label = ctk.CTkLabel(
            grid_frame,
            text="Ping (ms):",
            font=ctk.CTkFont(size=14),
            anchor="w"
        )
        ping_label.grid(row=2, column=0, sticky="w", padx=(0, 10))

        min_ping_frame = ctk.CTkFrame(grid_frame, fg_color="transparent")
        min_ping_frame.grid(row=2, column=1, sticky="w", padx=(0, 20))

        ctk.CTkLabel(
            min_ping_frame,
            text="Min:",
            font=ctk.CTkFont(size=14),
            width=40,
            anchor="w"
        ).pack(side="left", padx=(0, 5))

        self.min_ping_var = tk.StringVar()
        self.min_ping_entry = ctk.CTkEntry(
            min_ping_frame,
            textvariable=self.min_ping_var,
            placeholder_text="0",
            font=ctk.CTkFont(size=14),
            width=80
        )
        self.min_ping_entry.pack(side="left")

        max_ping_frame = ctk.CTkFrame(grid_frame, fg_color="transparent")
        max_ping_frame.grid(row=2, column=2, sticky="w")

        ctk.CTkLabel(
            max_ping_frame,
            text="Max:",
            font=ctk.CTkFont(size=14),
            width=40,
            anchor="w"
        ).pack(side="left", padx=(0, 5))

        self.max_ping_var = tk.StringVar()
        self.max_ping_entry = ctk.CTkEntry(
            max_ping_frame,
            textvariable=self.max_ping_var,
            placeholder_text="∞",
            font=ctk.CTkFont(size=14),
            width=80
        )
        self.max_ping_entry.pack(side="left")

    def _create_network_filter_section(self):
        """Create the network filter section with inputs for SSID, BSSID, security type, and band."""
        content = self._create_section("Network Filter")

        # Create grid layout for network filters
        grid_frame = ctk.CTkFrame(content, fg_color="transparent")
        grid_frame.pack(fill="x")

        # SSID filter
        ssid_label = ctk.CTkLabel(
            grid_frame,
            text="Network Name (SSID):",
            font=ctk.CTkFont(size=14),
            anchor="w"
        )
        ssid_label.grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 10))

        self.ssid_var = tk.StringVar()
        self.ssid_entry = ctk.CTkEntry(
            grid_frame,
            textvariable=self.ssid_var,
            placeholder_text="Enter network name...",
            font=ctk.CTkFont(size=14),
            width=200
        )
        self.ssid_entry.grid(row=0, column=1, columnspan=2, sticky="w", pady=(0, 10))

        # BSSID filter
        bssid_label = ctk.CTkLabel(
            grid_frame,
            text="BSSID:",
            font=ctk.CTkFont(size=14),
            anchor="w"
        )
        bssid_label.grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 10))

        self.bssid_var = tk.StringVar()
        self.bssid_entry = ctk.CTkEntry(
            grid_frame,
            textvariable=self.bssid_var,
            placeholder_text="XX:XX:XX:XX:XX:XX",
            font=ctk.CTkFont(size=14),
            width=200
        )
        self.bssid_entry.grid(row=1, column=1, columnspan=2, sticky="w", pady=(0, 10))

        # Security type filter
        security_label = ctk.CTkLabel(
            grid_frame,
            text="Security Type:",
            font=ctk.CTkFont(size=14),
            anchor="w"
        )
        security_label.grid(row=2, column=0, sticky="w", padx=(0, 10), pady=(0, 10))

        # Get unique security types from logs
        security_types = self._get_unique_values('security_type')
        security_types.insert(0, "Any")

        self.security_var = ctk.StringVar(value="Any")
        self.security_dropdown = ctk.CTkOptionMenu(
            grid_frame,
            values=security_types,
            variable=self.security_var,
            font=ctk.CTkFont(size=14),
            width=200
        )
        self.security_dropdown.grid(row=2, column=1, columnspan=2, sticky="w", pady=(0, 10))

        # Band filter
        band_label = ctk.CTkLabel(
            grid_frame,
            text="Band:",
            font=ctk.CTkFont(size=14),
            anchor="w"
        )
        band_label.grid(row=3, column=0, sticky="w", padx=(0, 10))

        # Get unique bands from logs
        bands = self._get_unique_values('band')
        bands.insert(0, "Any")

        self.band_var = ctk.StringVar(value="Any")
        self.band_dropdown = ctk.CTkOptionMenu(
            grid_frame,
            values=bands,
            variable=self.band_var,
            font=ctk.CTkFont(size=14),
            width=200
        )
        self.band_dropdown.grid(row=3, column=1, columnspan=2, sticky="w")

    def _create_server_filter_section(self):
        """Create the server filter section with a dropdown of available test servers."""
        content = self._create_section("Server Filter")

        # Server filter
        server_frame = ctk.CTkFrame(content, fg_color="transparent")
        server_frame.pack(fill="x")

        server_label = ctk.CTkLabel(
            server_frame,
            text="Test Server:",
            font=ctk.CTkFont(size=14),
            anchor="w",
            width=100
        )
        server_label.pack(side="left", padx=(0, 10))

        # Get unique servers from logs
        servers = self._get_unique_values('server')
        servers.insert(0, "Any")

        self.server_var = ctk.StringVar(value="Any")
        self.server_dropdown = ctk.CTkOptionMenu(
            server_frame,
            values=servers,
            variable=self.server_var,
            font=ctk.CTkFont(size=14),
            width=300
        )
        self.server_dropdown.pack(side="left")

    def _get_unique_values(self, field: str) -> List[str]:
        """Get unique values for a field from the speed test logs.

        Args:
            field: The field name to extract unique values for

        Returns:
            A sorted list of unique values for the specified field
        """
        logs = self.logger.get_all_logs()
        unique_values = set()

        for log in logs:
            value = log.get(field, "Unknown")
            if value and value != "Unknown":
                unique_values.add(value)

        return sorted(list(unique_values))

    def _show_date_picker(self, string_var: tk.StringVar):
        """Show a date picker dialog for selecting dates.

        Args:
            string_var: The StringVar that will store the selected date
        """
        try:
            # Create a top level window for the date picker
            top = ctk.CTkToplevel(self)
            top.title("Select Date")
            top.geometry("300x250")
            top.resizable(False, False)
            top.grab_set()

            # Create a calendar widget
            cal = tkcalendar.Calendar(
                top,
                selectmode='day',
                date_pattern='yyyy-mm-dd'
            )
            cal.pack(padx=10, pady=10, fill="both", expand=True)

            # Function to set the selected date
            def set_date():
                date = cal.get_date()
                string_var.set(date)
                top.destroy()

            # Add buttons
            button_frame = ctk.CTkFrame(top, fg_color="transparent")
            button_frame.pack(fill="x", padx=10, pady=10)

            ok_button = ctk.CTkButton(
                button_frame,
                text="OK",
                command=set_date,
                width=80,
                height=30
            )
            ok_button.pack(side="right", padx=5)

            cancel_button = ctk.CTkButton(
                button_frame,
                text="Cancel",
                command=top.destroy,
                width=80,
                height=30
            )
            cancel_button.pack(side="right", padx=5)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open date picker: {str(e)}")

    def _try_float_conversion(self, value: str) -> Optional[float]:
        """Try to convert a string to float, returning None if conversion fails.

        Args:
            value: The string value to convert

        Returns:
            The float value if conversion succeeds, None otherwise
        """
        if not value or value.strip() == "":
            return None

        try:
            return float(value)
        except ValueError:
            return None

    def _collect_date_filter(self) -> Optional[Tuple[str, str]]:
        """Collect date filter values from the UI.

        Returns:
            A tuple of (start_date, end_date) if both are provided, None otherwise
        """
        start_date = self.start_date_var.get().strip()
        end_date = self.end_date_var.get().strip()

        return (start_date, end_date) if start_date and end_date else None

    def _collect_speed_filter(self) -> Optional[Dict]:
        """Collect speed filter values from the UI.

        Returns:
            A dictionary with speed filter parameters if any are provided, None otherwise
        """
        min_download = self._try_float_conversion(self.min_download_var.get())
        max_download = self._try_float_conversion(self.max_download_var.get())
        min_upload = self._try_float_conversion(self.min_upload_var.get())
        max_upload = self._try_float_conversion(self.max_upload_var.get())
        min_ping = self._try_float_conversion(self.min_ping_var.get())
        max_ping = self._try_float_conversion(self.max_ping_var.get())

        if any([min_download, max_download, min_upload, max_upload, min_ping, max_ping]):
            return {
                'min_download': min_download,
                'max_download': max_download,
                'min_upload': min_upload,
                'max_upload': max_upload,
                'min_ping': min_ping,
                'max_ping': max_ping
            }
        return None

    def _collect_network_filter(self) -> Optional[Dict]:
        """Collect network filter values from the UI.

        Returns:
            A dictionary with network filter parameters if any are provided, None otherwise
        """
        ssid = self.ssid_var.get().strip()
        bssid = self.bssid_var.get().strip()
        security_type = self.security_var.get() if self.security_var.get() != "Any" else None
        band = self.band_var.get() if self.band_var.get() != "Any" else None

        if any([ssid, bssid, security_type, band]):
            return {
                'ssid': ssid or None,
                'bssid': bssid or None,
                'security_type': security_type,
                'band': band
            }
        return None

    def _collect_server_filter(self) -> Optional[str]:
        """Collect server filter value from the UI.

        Returns:
            The server name if selected, None otherwise
        """
        server = self.server_var.get()
        return server if server != "Any" else None

    def _apply_filters(self):
        """Apply the filters and call the callback function with the filter data.

        Collects all filter values from the UI, constructs a filter data dictionary,
        and passes it to the callback function before closing the dialog.
        """
        try:
            # Collect all filter values
            date_range = self._collect_date_filter()
            speed_range = self._collect_speed_filter()
            network_filter = self._collect_network_filter()
            server = self._collect_server_filter()

            # Create filter data
            filter_data = {
                'date_range': date_range,
                'speed_range': speed_range,
                'network_filter': network_filter,
                'server': server
            }

            # Call the callback function
            self.callback(filter_data)

            # Close the dialog
            self.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply filters: {str(e)}")

    def _reset_filters(self):
        """Reset all filters to their default values.

        Clears all input fields and resets dropdowns to their default values.
        """
        # Reset date filter
        self._reset_date_filter()

        # Reset speed filter
        self._reset_speed_filter()

        # Reset network filter
        self._reset_network_filter()

        # Reset server filter
        self._reset_server_filter()

    def _reset_date_filter(self):
        """Reset date filter fields to default values."""
        self.start_date_var.set("")
        self.end_date_var.set("")

    def _reset_speed_filter(self):
        """Reset speed filter fields to default values."""
        self.min_download_var.set("")
        self.max_download_var.set("")
        self.min_upload_var.set("")
        self.max_upload_var.set("")
        self.min_ping_var.set("")
        self.max_ping_var.set("")

    def _reset_network_filter(self):
        """Reset network filter fields to default values."""
        self.ssid_var.set("")
        self.bssid_var.set("")
        self.security_var.set("Any")
        self.band_var.set("Any")

    def _reset_server_filter(self):
        """Reset server filter field to default value."""
        self.server_var.set("Any")
