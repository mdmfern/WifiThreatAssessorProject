"""
Speed Test History Panel for the Wi-Fi Threat Assessor application.
This module provides a UI for viewing and managing speed test history.
It includes functionality for filtering, sorting, and exporting speed test logs.
"""

# Standard library imports
import datetime
import platform
import socket
from typing import Dict

# Third-party imports
import customtkinter as ctk

# Local imports
from speed_test_logger import SpeedTestLogger
from speed_test_filter import AdvancedFilterDialog
from ui_constants import COLORS

class SpeedTestHistoryPanel(ctk.CTkFrame):
    """Panel for displaying and managing speed test history.

    This class provides a UI panel for viewing, filtering, sorting, and exporting
    speed test history logs. It includes functionality for basic text filtering,
    advanced filtering options, and sorting by various criteria.
    """

    def __init__(self, master, **kwargs):
        """Initialize the speed test history panel.

        Args:
            master: The parent widget
            **kwargs: Additional keyword arguments passed to the parent class
        """
        super().__init__(master, **kwargs)

        # Initialize instance variables
        self.logger = SpeedTestLogger()
        self.filtered_logs = []
        self.all_logs = []
        self.current_sort = "time_desc"  # Default sort by time descending
        self.filter_text = ""
        self.selected_log = None
        self.advanced_filter_active = False
        self.advanced_filter_data = None

        # Configure the main layout
        self.configure(corner_radius=10)

        # Create UI components
        self._create_title_bar()
        self._create_filter_controls()
        self._create_log_display_area()

        # Bind events
        self.filter_entry.bind("<Return>", lambda _: self.apply_filter())

        # Load and display logs
        self.refresh_logs()

    def _create_title_bar(self):
        """Create the title bar with panel title and action buttons."""
        # Panel title and controls
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(fill="x", padx=15, pady=(15, 5))

        # Panel title
        self.title_label = ctk.CTkLabel(
            title_frame,
            text="Speed Test History",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.title_label.pack(side="left")

        # Refresh button
        self.refresh_button = ctk.CTkButton(
            title_frame,
            text="Refresh",
            command=self.refresh_logs,
            font=ctk.CTkFont(size=12),
            width=80,
            height=28,
            corner_radius=4,
            fg_color=COLORS["primary_light"],
            hover_color=COLORS["primary_dark"]
        )
        self.refresh_button.pack(side="right", padx=5)

        # Export button
        self.export_button = ctk.CTkButton(
            title_frame,
            text="Export PDF",
            command=self.export_logs,
            font=ctk.CTkFont(size=12),
            width=100,
            height=28,
            corner_radius=4,
            fg_color=COLORS["secondary"],
            hover_color=COLORS["secondary_dark"]
        )
        self.export_button.pack(side="right", padx=5)

        # Separator
        self.separator = ctk.CTkFrame(self, height=2, fg_color=("gray70", "gray30"))
        self.separator.pack(fill="x", padx=15, pady=(0, 10))

    def _create_filter_controls(self):
        """Create the filter and sort controls."""
        # Filter and sort controls
        controls_frame = ctk.CTkFrame(self, fg_color="transparent")
        controls_frame.pack(fill="x", padx=15, pady=(0, 10))

        # Search/filter
        filter_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        filter_frame.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            filter_frame,
            text="Filter:",
            font=ctk.CTkFont(size=12),
            width=50
        ).pack(side="left", padx=(0, 5))

        self.filter_entry = ctk.CTkEntry(
            filter_frame,
            placeholder_text="Search by network name...",
            font=ctk.CTkFont(size=12),
            width=200
        )
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.filter_button = ctk.CTkButton(
            filter_frame,
            text="Apply",
            command=self.apply_filter,
            font=ctk.CTkFont(size=12),
            width=60,
            height=24,
            corner_radius=4
        )
        self.filter_button.pack(side="left", padx=(0, 5))

        # Advanced filter button
        self.advanced_filter_button = ctk.CTkButton(
            filter_frame,
            text="Advanced",
            command=self.show_advanced_filter,
            font=ctk.CTkFont(size=12),
            width=80,
            height=24,
            corner_radius=4,
            fg_color=COLORS["primary_light"],
            hover_color=COLORS["primary_dark"]
        )
        self.advanced_filter_button.pack(side="left")

        # Sort options
        sort_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        sort_frame.pack(side="right")

        ctk.CTkLabel(
            sort_frame,
            text="Sort by:",
            font=ctk.CTkFont(size=12),
            width=50
        ).pack(side="left", padx=(0, 5))

        self.sort_option = ctk.CTkOptionMenu(
            sort_frame,
            values=["Newest First", "Oldest First", "Fastest Download", "Fastest Upload", "Best Ping"],
            command=self.change_sort,
            font=ctk.CTkFont(size=12),
            width=150,
            height=24
        )
        self.sort_option.set("Newest First")
        self.sort_option.pack(side="left")

    def _create_log_display_area(self):
        """Create the scrollable frame for displaying log entries."""
        # Create scrollable frame for logs
        self.log_frame = ctk.CTkScrollableFrame(
            self,
            label_text="",
            fg_color=("gray85", "#2d2d2d"),
            corner_radius=5
        )
        self.log_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # Create a frame for the detail view (initially hidden)
        self.detail_frame = ctk.CTkFrame(
            self,
            fg_color=("gray90", "#1e1e1e"),
            corner_radius=5,
            height=0
        )
        self.detail_frame.pack(fill="x", padx=15, pady=(0, 15))
        self.detail_frame.pack_forget()  # Hide initially

    def refresh_logs(self) -> None:
        """Refresh the displayed logs.

        Fetches all logs from the logger, resets filters, and updates the display.
        """
        # Clear existing log items
        for widget in self.log_frame.winfo_children():
            widget.destroy()

        # Get all logs
        logs = self.logger.get_all_logs()

        # Store logs for filtering
        self.all_logs = logs.copy()

        # Reset advanced filters
        self.reset_advanced_filters()

        # Apply current filter and sort
        self._apply_filter_and_sort()

    def reset_advanced_filters(self) -> None:
        """Reset advanced filters to their default state.

        Clears any active advanced filters and resets the button appearance.
        """
        self.advanced_filter_active = False
        self.advanced_filter_data = None

        # Reset button appearance
        self.advanced_filter_button.configure(
            text="Advanced",
            fg_color=COLORS["primary_light"],
            hover_color=COLORS["primary_dark"]
        )

    def _apply_filter_and_sort(self) -> None:
        """Apply the current filter and sort settings to the logs.

        Filters logs based on current filter settings, sorts them according to
        the selected sort option, and updates the display.
        """
        # Clear existing log items
        for widget in self.log_frame.winfo_children():
            widget.destroy()

        # If no logs, show message
        if not self.all_logs:
            self._show_no_logs_message()
            return

        # Apply filters to get filtered logs
        filtered_logs = self._apply_filters()

        # Apply sorting to filtered logs
        filtered_logs = self._sort_logs(filtered_logs)

        # Store filtered logs
        self.filtered_logs = filtered_logs

        # Add filtered log entries to the display
        for i, log in enumerate(filtered_logs):
            self._add_log_entry(log, i)

        # Show filter results summary if filters are active
        self._show_filter_results_summary()

    def _show_no_logs_message(self) -> None:
        """Display a message when no logs are available."""
        no_logs_label = ctk.CTkLabel(
            self.log_frame,
            text="No speed test history available",
            text_color=("gray50", "gray70"),
            font=ctk.CTkFont(size=13),
        )
        no_logs_label.pack(pady=20)

    def _apply_filters(self) -> list:
        """Apply current filters to the logs.

        Returns:
            List of filtered log dictionaries
        """
        if self.advanced_filter_active and self.advanced_filter_data:
            # Apply advanced filters
            filtered_logs = self.logger.get_advanced_filtered_logs(
                date_range=self.advanced_filter_data.get('date_range'),
                speed_range=self.advanced_filter_data.get('speed_range'),
                network_filter=self.advanced_filter_data.get('network_filter'),
                server=self.advanced_filter_data.get('server')
            )

            # Apply simple text filter if also present
            if self.filter_text:
                filtered_logs = [
                    log for log in filtered_logs
                    if self.filter_text.lower() in log.get('ssid', '').lower()
                ]
        else:
            # Apply simple text filter only
            filtered_logs = self.all_logs.copy() if not self.filter_text else [
                log for log in self.all_logs if self.filter_text.lower() in log.get('ssid', '').lower()
            ]

        return filtered_logs

    def _sort_logs(self, logs: list) -> list:
        """Sort logs based on the current sort setting.

        Args:
            logs: List of log dictionaries to sort

        Returns:
            Sorted list of log dictionaries
        """
        if self.current_sort == "time_asc":
            logs.reverse()  # Oldest first
        elif self.current_sort == "download":
            logs.sort(key=lambda x: float(x.get('download_speed', 0)), reverse=True)
        elif self.current_sort == "upload":
            logs.sort(key=lambda x: float(x.get('upload_speed', 0)), reverse=True)
        elif self.current_sort == "ping":
            logs.sort(key=lambda x: float(x.get('ping', 999)))  # Lower ping is better

        return logs

    def _show_filter_results_summary(self) -> None:
        """Display a summary of the filter results if filters are active."""
        filter_text = []
        if self.filter_text:
            filter_text.append(f"text '{self.filter_text}'")

        if self.advanced_filter_active:
            filter_text.append("advanced filters")

        if filter_text:
            result_text = f"Found {len(self.filtered_logs)} tests matching {' and '.join(filter_text)}"
            filter_result = ctk.CTkLabel(
                self.log_frame,
                text=result_text,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["primary_light"]
            )
            filter_result.pack(pady=(0, 10), anchor="w", padx=10)

    def apply_filter(self) -> None:
        """Apply the current filter text to the logs.

        Gets the filter text from the entry field and applies it to the logs.
        """
        self.filter_text = self.filter_entry.get().strip()
        self._apply_filter_and_sort()

    def show_advanced_filter(self) -> None:
        """Show the advanced filter dialog.

        Creates and displays the advanced filter dialog with callback.
        """
        AdvancedFilterDialog(self, self.apply_advanced_filter)

    def apply_advanced_filter(self, filter_data: Dict) -> None:
        """Apply advanced filters from the dialog.

        Args:
            filter_data: Dictionary containing filter settings including date_range,
                        speed_range, network_filter, and server
        """
        # Store filter data
        self.advanced_filter_data = filter_data

        # Check if any filters are active
        has_filters = any([
            filter_data.get('date_range'),
            filter_data.get('speed_range'),
            filter_data.get('network_filter'),
            filter_data.get('server')
        ])

        # Set filter status
        self.advanced_filter_active = has_filters

        # Update button appearance to indicate active filters
        if has_filters:
            self.advanced_filter_button.configure(
                text="Advanced ✓",
                fg_color=COLORS["secondary"],
                hover_color=COLORS["secondary_dark"]
            )
        else:
            self.advanced_filter_button.configure(
                text="Advanced",
                fg_color=COLORS["primary_light"],
                hover_color=COLORS["primary_dark"]
            )

        # Apply filters
        self._apply_filter_and_sort()

    def change_sort(self, option: str) -> None:
        """Change the sort order based on the selected option.

        Args:
            option: The sort option selected by the user
        """
        sort_mapping = {
            "Newest First": "time_desc",
            "Oldest First": "time_asc",
            "Fastest Download": "download",
            "Fastest Upload": "upload",
            "Best Ping": "ping"
        }

        self.current_sort = sort_mapping.get(option, "time_desc")
        self._apply_filter_and_sort()

    def export_logs(self) -> None:
        """Export the speed test logs to a PDF report.

        Generates a PDF report containing the currently filtered logs.
        Shows appropriate messages for success or failure.
        """
        # Import here to avoid circular imports
        from tkinter import messagebox, filedialog

        try:
            # Check if there are any logs to export
            if not self.filtered_logs:
                messagebox.showinfo(
                    "No Data to Export",
                    "There are no speed test logs to export."
                )
                return

            # Create a default filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            default_filename = f"speed_test_history_{timestamp}.pdf"

            # Ask user for save location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
                initialfile=default_filename
            )

            if not file_path:
                return  # User cancelled

            # Import here to avoid circular imports
            from speed_test_report import SpeedTestReportGenerator

            # Generate the report
            generator = SpeedTestReportGenerator(self.filtered_logs)
            output_path = generator.generate_report(file_path)

            # Show success message
            messagebox.showinfo(
                "Export Successful",
                f"Speed test history exported as PDF to:\n{output_path}"
            )

        except Exception as e:
            # Show error message
            messagebox.showerror(
                "Export Failed",
                f"Failed to export speed test history:\n{str(e)}"
            )

    def _add_log_entry(self, log_data: Dict, index: int) -> None:
        """Add a log entry to the display.

        Creates a UI card for a single speed test log entry with network information,
        test results, and action buttons.

        Args:
            log_data: Dictionary containing the speed test data
            index: Index of the log entry for alternating row colors
        """
        # Create frame for this log entry with alternating colors
        entry_frame = self._create_log_entry_frame(index)

        # Main content frame
        content_frame = ctk.CTkFrame(entry_frame, fg_color="transparent")
        content_frame.pack(fill="x", padx=10, pady=5)

        # Left side: Network info
        info_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True)

        # Add network name
        self._add_network_name_to_entry(info_frame, log_data)

        # Add timestamp
        self._add_timestamp_to_entry(info_frame, log_data)

        # Add speed information
        self._add_speed_info_to_entry(info_frame, log_data)

        # Right side: Action buttons
        self._add_action_buttons_to_entry(content_frame, log_data)

    def _create_log_entry_frame(self, index: int) -> ctk.CTkFrame:
        """Create a frame for a log entry with alternating colors and hover effect.

        Args:
            index: Index of the log entry for alternating row colors

        Returns:
            The created frame
        """
        # Determine colors based on index (alternating rows)
        normal_color = ("gray90" if index % 2 == 0 else "gray85",
                        "gray17" if index % 2 == 0 else "gray20")
        hover_color = ("gray95", "gray25")

        # Create the frame
        entry_frame = ctk.CTkFrame(
            self.log_frame,
            fg_color=normal_color,
            corner_radius=6
        )
        entry_frame.pack(fill="x", padx=5, pady=2)

        # Add hover effect
        entry_frame.bind("<Enter>", lambda _: entry_frame.configure(fg_color=hover_color))
        entry_frame.bind("<Leave>", lambda _: entry_frame.configure(fg_color=normal_color))

        return entry_frame

    def _add_network_name_to_entry(self, parent_frame: ctk.CTkFrame, log_data: Dict) -> None:
        """Add network name to the log entry.

        Args:
            parent_frame: The parent frame to add the network name to
            log_data: Dictionary containing the speed test data
        """
        name_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        name_frame.pack(fill="x", anchor="w")

        ssid_label = ctk.CTkLabel(
            name_frame,
            text=log_data['ssid'],
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w"
        )
        ssid_label.pack(side="left")

    def _add_timestamp_to_entry(self, parent_frame: ctk.CTkFrame, log_data: Dict) -> None:
        """Add formatted timestamp to the log entry.

        Args:
            parent_frame: The parent frame to add the timestamp to
            log_data: Dictionary containing the speed test data
        """
        details_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        details_frame.pack(fill="x", anchor="w", pady=(5, 0))

        # Format timestamp
        try:
            timestamp_obj = datetime.datetime.strptime(log_data['timestamp'], "%Y-%m-%d %H:%M:%S")
            formatted_time = timestamp_obj.strftime("%b %d, %Y at %I:%M %p")
        except (ValueError, TypeError):
            formatted_time = log_data.get('timestamp', 'Unknown')

        time_label = ctk.CTkLabel(
            details_frame,
            text=f"Test: {formatted_time}",
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray70"),
            anchor="w"
        )
        time_label.pack(side="left")

    def _add_speed_info_to_entry(self, parent_frame: ctk.CTkFrame, log_data: Dict) -> None:
        """Add speed information to the log entry.

        Args:
            parent_frame: The parent frame to add the speed info to
            log_data: Dictionary containing the speed test data
        """
        speed_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        speed_frame.pack(fill="x", anchor="w", pady=(5, 0))

        # Download speed
        download_speed = float(log_data.get('download_speed', 0))
        download_label = ctk.CTkLabel(
            speed_frame,
            text=f"↓ {download_speed:.2f} Mbps",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["primary_light"],
            anchor="w",
            width=120
        )
        download_label.pack(side="left")

        # Upload speed
        upload_speed = float(log_data.get('upload_speed', 0))
        upload_label = ctk.CTkLabel(
            speed_frame,
            text=f"↑ {upload_speed:.2f} Mbps",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["secondary"],
            anchor="w",
            width=120
        )
        upload_label.pack(side="left")

        # Ping
        ping = float(log_data.get('ping', 0))
        ping_label = ctk.CTkLabel(
            speed_frame,
            text=f"Ping: {ping:.1f} ms",
            font=ctk.CTkFont(size=13),
            text_color=("gray50", "gray70"),
            anchor="w"
        )
        ping_label.pack(side="left")

    def _add_action_buttons_to_entry(self, parent_frame: ctk.CTkFrame, log_data: Dict) -> None:
        """Add action buttons to the log entry.

        Args:
            parent_frame: The parent frame to add the buttons to
            log_data: Dictionary containing the speed test data
        """
        button_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        button_frame.pack(side="right", padx=(10, 0))

        # View details button
        details_button = ctk.CTkButton(
            button_frame,
            text="Details",
            command=lambda d=log_data: self.show_log_details(d),
            font=ctk.CTkFont(size=12),
            width=70,
            height=28,
            corner_radius=4,
            fg_color=COLORS["primary_light"],
            hover_color=COLORS["primary_dark"]
        )
        details_button.pack(side="top")

    def show_log_details(self, log_data: Dict) -> None:
        """Show detailed information for a specific log entry.

        Creates and displays a modal window with detailed information about
        the selected speed test.

        Args:
            log_data: Dictionary containing the speed test data
        """
        detail_window = SpeedTestDetailWindow(self, log_data)
        detail_window.grab_set()  # Make window modal


class SpeedTestDetailWindow(ctk.CTkToplevel):
    """Window for displaying detailed information about a speed test.

    This class provides a modal window that displays comprehensive information
    about a specific speed test, including test information, speed results,
    network information, and device information.
    """

    def __init__(self, parent, log_data: Dict):
        """Initialize the speed test detail window.

        Args:
            parent: The parent widget
            log_data: Dictionary containing the speed test data
        """
        super().__init__(parent)

        self.parent = parent
        self.log_data = log_data
        self.logger = SpeedTestLogger()

        # Configure window
        self.title(f"Speed Test Details: {log_data['ssid']}")
        self.geometry("700x600")
        self.minsize(600, 500)

        # Create UI components
        self._create_main_layout()
        self._create_header()
        self._create_detail_sections()
        self._create_bottom_buttons()

    def _create_main_layout(self) -> None:
        """Create the main scrollable frame for the window content."""
        self.main_frame = ctk.CTkScrollableFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

    def _create_header(self) -> None:
        """Create the header with network name."""
        title_frame = ctk.CTkFrame(self.main_frame, fg_color=COLORS["primary"])
        title_frame.pack(fill="x", pady=(0, 20))

        header_content = ctk.CTkFrame(title_frame, fg_color="transparent")
        header_content.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(
            header_content,
            text=self.log_data['ssid'],
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="white"
        ).pack(side="left", pady=5)

    def _create_detail_sections(self) -> None:
        """Create all detail sections for the speed test."""
        self._create_test_info_section()
        self._create_speed_results_section()
        self._create_network_info_section()
        self._create_device_info_section()

    def _create_bottom_buttons(self) -> None:
        """Create buttons at the bottom of the window."""
        button_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=(20, 0))

        close_button = ctk.CTkButton(
            button_frame,
            text="Close",
            command=self.destroy,
            font=ctk.CTkFont(size=13),
            height=32,
            corner_radius=4
        )
        close_button.pack(side="right", padx=5)

    def _add_section(self, title: str) -> ctk.CTkFrame:
        """Add a section to the detail window.

        Args:
            title: The title of the section

        Returns:
            The created section frame
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

        return section

    def _add_fields(self, section: ctk.CTkFrame, fields: list) -> None:
        """Add fields to a section.

        Args:
            section: The section frame to add fields to
            fields: List of (label, value) tuples to add as fields
        """
        content = ctk.CTkFrame(section, fg_color="transparent")
        content.pack(fill="x", padx=15, pady=15)

        for label, value in fields:
            # Create frame for this field
            field_frame = ctk.CTkFrame(content, fg_color="transparent")
            field_frame.pack(fill="x", pady=(0, 10))

            # Label
            ctk.CTkLabel(
                field_frame,
                text=f"{label}:",
                font=ctk.CTkFont(size=14, weight="bold"),
                width=150,
                anchor="w"
            ).pack(side="left")

            # Value
            ctk.CTkLabel(
                field_frame,
                text=str(value),
                font=ctk.CTkFont(size=14),
                anchor="w",
                wraplength=400
            ).pack(side="left", fill="x", expand=True)

    def _create_test_info_section(self) -> None:
        """Create the test information section with date, time, and server details."""
        section = self._add_section("Test Information")

        # Format timestamp
        try:
            timestamp_obj = datetime.datetime.strptime(self.log_data['timestamp'], "%Y-%m-%d %H:%M:%S")
            formatted_date = timestamp_obj.strftime("%A, %B %d, %Y")
            formatted_time = timestamp_obj.strftime("%I:%M:%S %p")
        except (ValueError, TypeError):
            formatted_date = "Unknown"
            formatted_time = "Unknown"

        test_details = [
            ("Test Date", formatted_date),
            ("Test Time", formatted_time),
            ("Test Server", self.log_data.get('server', 'Unknown')),
        ]

        self._add_fields(section, test_details)

    def _create_speed_results_section(self) -> None:
        """Create the speed results section with download, upload, and ping metrics."""
        section = self._add_section("Speed Test Results")

        # Get speed values
        download_speed = float(self.log_data.get('download_speed', 0))
        upload_speed = float(self.log_data.get('upload_speed', 0))
        ping = float(self.log_data.get('ping', 0))

        # Get ratings
        download_rating, _ = self.logger.get_speed_rating(download_speed, True)
        upload_rating, _ = self.logger.get_speed_rating(upload_speed, False)
        ping_rating, _ = self.logger.get_ping_rating(ping)

        speed_details = [
            ("Download Speed", f"{download_speed:.2f} Mbps ({download_rating})"),
            ("Upload Speed", f"{upload_speed:.2f} Mbps ({upload_rating})"),
            ("Ping", f"{ping:.1f} ms ({ping_rating})"),
        ]

        self._add_fields(section, speed_details)

    def _create_network_info_section(self) -> None:
        """Create the network information section with SSID, BSSID, security, etc."""
        section = self._add_section("Network Information")

        network_details = [
            ("Network Name (SSID)", self.log_data.get('ssid', 'Unknown')),
            ("BSSID", self.log_data.get('bssid', 'Unknown')),
            ("Security Type", self.log_data.get('security_type', 'Unknown')),
            ("Channel", self.log_data.get('channel', 'Unknown')),
            ("Band", self.log_data.get('band', 'Unknown')),
            ("IP Address", self.log_data.get('ip_address', 'Unknown')),
        ]

        self._add_fields(section, network_details)

    def _create_device_info_section(self) -> None:
        """Create the device information section with device name, OS, and location."""
        section = self._add_section("Device Information")

        device_details = [
            ("Device Name", self.log_data.get('device_name', socket.gethostname())),
            ("Operating System", platform.system() + ' ' + platform.release()),
            ("Location", self.log_data.get('location', 'Not available')),
        ]

        self._add_fields(section, device_details)
