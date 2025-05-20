"""
Wi-Fi Connection Logger for the Wi-Fi Threat Assessor application.

This module provides functionality for logging Wi-Fi connections to a CSV file
and displaying connection history in the UI. It includes:

1. WiFiConnectionLogger: A singleton class for logging and retrieving connection data
2. ConnectionLogPanel: A UI panel for displaying and filtering connection history
3. ConnectionDetailWindow: A window for displaying detailed information about a connection
4. LogViewerWindow: A standalone window for viewing connection logs

The module supports exporting connection logs to CSV, Excel, and PDF formats.
"""

import os
import csv
import datetime
import hashlib
from typing import Dict, List, Optional, Tuple, Any
import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
import wifi_utils
import security_utils
import common_utils

# Optional imports for export functionality
# These imports are used in the export_logs method of ConnectionLogPanel
# pylint: disable=unused-import
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import pandas as pd #type ignore
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
# pylint: enable=unused-import

class WiFiConnectionLogger:
    """
    Singleton class for logging and retrieving Wi-Fi connection data.

    This class maintains a CSV log file of Wi-Fi connections with timestamps
    and network details. It implements the singleton pattern to ensure only
    one instance manages the log file.

    Attributes:
        log_file_path (str): Path to the CSV log file
    """
    _instance = None
    _CSV_HEADERS = [
        'timestamp', 'ssid', 'bssid', 'signal_strength',
        'security_type', 'channel', 'band', 'ip_address'
    ]

    def __new__(cls, log_file_path: str = common_utils.DEFAULT_LOG_FILE):
        """
        Create or return the singleton instance of WiFiConnectionLogger.

        Args:
            log_file_path: Path to the CSV log file (default: from common_utils)

        Returns:
            WiFiConnectionLogger: The singleton instance
        """
        if cls._instance is None:
            cls._instance = super(WiFiConnectionLogger, cls).__new__(cls)
            cls._instance.log_file_path = log_file_path
            cls._instance._ensure_log_file_exists()
        return cls._instance

    def __init__(self, log_file_path: str = None):
        """
        Initialize the WiFiConnectionLogger instance.

        This method is intentionally empty as initialization is done in __new__.
        The parameter is kept for API compatibility.

        Args:
            log_file_path: Ignored, kept for API compatibility
        """
        # Parameter is intentionally unused but kept for API compatibility
        # pylint: disable=unused-argument
        pass

    def _ensure_log_file_exists(self) -> None:
        """
        Create the log file with headers if it doesn't exist.

        Creates any necessary parent directories and initializes the CSV file
        with appropriate headers.
        """
        if not os.path.exists(self.log_file_path):
            log_dir = os.path.dirname(self.log_file_path)
            if log_dir and not os.path.exists(log_dir):
                common_utils.ensure_dir_exists(log_dir)

            with open(self.log_file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(self._CSV_HEADERS)

    def log_connection(self, network_data: Dict) -> bool:
        """
        Log a Wi-Fi connection to the CSV file.

        Logs are deduplicated to prevent multiple entries for the same network
        within a short time period (60 seconds).

        Args:
            network_data: Dictionary containing network information
                Required keys: 'ssid'
                Optional keys: 'bssid', 'signal', 'auth_type', 'channel',
                              'band', 'ip_address'

        Returns:
            bool: True if the connection was logged, False otherwise
        """
        if not network_data or 'ssid' not in network_data:
            return False

        # Check for recent duplicate entries
        existing_logs = self.get_all_logs()
        if existing_logs:
            latest_log = existing_logs[0]
            try:
                latest_time = datetime.datetime.strptime(latest_log['timestamp'], "%Y-%m-%d %H:%M:%S")
                current_time = datetime.datetime.now()

                # Skip if same network was logged in the last 60 seconds
                if (latest_log['ssid'] == network_data.get('ssid') and
                    (current_time - latest_time).total_seconds() < 60):
                    return False
            except (ValueError, KeyError):
                # Continue if there's an error parsing the timestamp
                pass

        try:
            timestamp = common_utils.format_timestamp()

            with open(self.log_file_path, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                    timestamp,
                    network_data.get('ssid', 'Unknown'),
                    network_data.get('bssid', 'Unknown'),
                    network_data.get('signal', '0'),
                    network_data.get('auth_type', 'Unknown'),
                    network_data.get('channel', 'Unknown'),
                    network_data.get('band', 'Unknown'),
                    network_data.get('ip_address', 'Unknown')
                ])
            return True
        except (IOError, PermissionError) as e:
            # Log specific file-related errors
            print(f"Error logging connection: {e}")
            return False
        except Exception as e:
            # Catch any other unexpected errors
            print(f"Unexpected error logging connection: {e}")
            return False

    def get_all_logs(self) -> List[Dict]:
        """
        Retrieve all connection logs from the CSV file.

        Returns:
            List[Dict]: List of dictionaries containing log entries,
                       sorted by timestamp (newest first)
        """
        logs = []

        if not os.path.exists(self.log_file_path):
            return logs

        try:
            with open(self.log_file_path, 'r', newline='') as file:
                reader = csv.DictReader(file)
                logs = list(reader)

            # Sort logs by timestamp, newest first
            logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        except (IOError, PermissionError) as e:
            print(f"Error reading logs: {e}")
            return []
        except Exception as e:
            print(f"Unexpected error reading logs: {e}")
            return []

        return logs

    def cleanup_old_logs(self, retention_days: int) -> int:
        """
        Remove log entries older than the specified retention period.

        Args:
            retention_days: Number of days to keep logs for

        Returns:
            int: Number of log entries removed
        """
        if not os.path.exists(self.log_file_path):
            return 0

        try:
            # Ensure retention_days is a valid integer
            retention_days = common_utils.safe_int_conversion(retention_days, 30)
            current_time = datetime.datetime.now()
            cleaned_logs = []
            removed_count = 0

            # Read existing logs
            with open(self.log_file_path, 'r', newline='') as file:
                reader = csv.DictReader(file)
                headers = reader.fieldnames

                if not headers:
                    return 0

                all_logs = list(reader)
                removed_count = len(all_logs)

                # Filter logs based on retention period
                for log in all_logs:
                    try:
                        log_time = datetime.datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S")
                        if (current_time - log_time).days < retention_days:
                            cleaned_logs.append(log)
                    except (ValueError, KeyError):
                        # Keep logs with invalid timestamps
                        cleaned_logs.append(log)

            # Calculate how many logs were removed
            removed_count -= len(cleaned_logs)

            # Write back the filtered logs
            with open(self.log_file_path, 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=headers)
                writer.writeheader()
                writer.writerows(cleaned_logs)

            return removed_count

        except (IOError, PermissionError) as e:
            print(f"Error cleaning up logs: {e}")
            return 0
        except Exception as e:
            print(f"Unexpected error cleaning up logs: {e}")
            return 0


class ConnectionLogPanel(ctk.CTkFrame):
    """
    UI panel for displaying and interacting with Wi-Fi connection history.

    This panel provides a user interface for viewing, filtering, sorting,
    and exporting connection logs. It displays connection history in a
    scrollable list with options to view details for each connection.

    Attributes:
        logger: Instance of WiFiConnectionLogger for accessing log data
        filtered_logs: List of logs after filtering
        current_sort: Current sort method
        filter_text: Current filter text
    """

    def __init__(self, master, **kwargs):
        """
        Initialize the ConnectionLogPanel.

        Args:
            master: Parent widget
            **kwargs: Additional arguments to pass to CTkFrame constructor
        """
        super().__init__(master, **kwargs)

        # Initialize instance variables
        self.logger = WiFiConnectionLogger()
        self.filtered_logs = []
        self.current_sort = "time_desc"  # Default sort by time descending
        self.filter_text = ""
        self.all_logs = []  # Store all logs for filtering

        # Configure the main layout
        self.configure(corner_radius=10)

        # Create UI components
        self._create_header()
        self._create_filter_controls()
        self._create_log_display()

        # Bind events
        self.filter_entry.bind("<Return>", lambda _: self.apply_filter())

        # Load and display logs
        self.refresh_logs()

    def _create_header(self):
        """Create the header section with title and action buttons."""
        # Panel title and controls
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(fill="x", padx=15, pady=(15, 5))

        # Panel title
        self.title_label = ctk.CTkLabel(
            title_frame,
            text="Connection History",
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
            fg_color=("#3498db", "#2980b9"),
            hover_color=("#2980b9", "#1f6aa5")
        )
        self.refresh_button.pack(side="right", padx=5)

        # Export button
        self.export_button = ctk.CTkButton(
            title_frame,
            text="Export",
            command=self.export_logs,
            font=ctk.CTkFont(size=12),
            width=80,
            height=28,
            corner_radius=4,
            fg_color=("#27ae60", "#27ae60"),
            hover_color=("#219a52", "#219a52")
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
        self.filter_button.pack(side="left")

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
            values=["Newest First", "Oldest First", "Network Name (A-Z)", "Network Name (Z-A)"],
            command=self.change_sort,
            font=ctk.CTkFont(size=12),
            width=150,
            height=24
        )
        self.sort_option.set("Newest First")
        self.sort_option.pack(side="left")

    def _create_log_display(self):
        """Create the scrollable frame for displaying logs."""
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
        """
        Refresh the connection log display.

        Retrieves the latest logs from the logger and updates the UI.
        """
        # Clear existing log items
        for widget in self.log_frame.winfo_children():
            widget.destroy()

        # Get current connection from wifi_utils
        current_connection = wifi_utils.get_connection_status()

        # Get all logs
        logs = self.logger.get_all_logs()

        # Store logs for filtering
        self.all_logs = logs.copy()

        # Apply current filter and sort
        self._apply_filter_and_sort(current_connection)

    def _apply_filter_and_sort(self, current_connection=None) -> None:
        """
        Apply filtering and sorting to logs and update the display.

        Args:
            current_connection: Current Wi-Fi connection data (optional)
        """
        # Clear existing log items
        for widget in self.log_frame.winfo_children():
            widget.destroy()

        # If no logs and no current connection, show message
        if not self.all_logs and not current_connection:
            self._show_no_logs_message()
            return

        # Filter logs based on filter text
        filtered_logs = self._filter_logs()

        # Sort logs based on current sort option
        self._sort_logs(filtered_logs)

        # Store filtered logs
        self.filtered_logs = filtered_logs

        # Add current connection at the top if connected
        if current_connection:
            current_log = self._format_current_connection(current_connection)
            self._add_log_entry(current_log, 0, is_current=True)

        # Add filtered log entries
        offset = 1 if current_connection else 0
        for i, log in enumerate(filtered_logs):
            self._add_log_entry(log, i + offset)

        # Show filter results if filtering is active
        if self.filter_text:
            self._show_filter_results(filtered_logs)

    def _show_no_logs_message(self) -> None:
        """Display a message when no logs are available."""
        no_logs_label = ctk.CTkLabel(
            self.log_frame,
            text="No connection history available",
            text_color=("gray50", "gray70"),
            font=ctk.CTkFont(size=13),
        )
        no_logs_label.pack(pady=20)

    def _filter_logs(self) -> List[Dict]:
        """
        Filter logs based on the current filter text.

        Returns:
            List[Dict]: Filtered logs
        """
        if not self.filter_text:
            return self.all_logs.copy()

        return [
            log for log in self.all_logs
            if self.filter_text.lower() in log.get('ssid', '').lower()
        ]

    def _sort_logs(self, logs: List[Dict]) -> None:
        """
        Sort logs in-place based on the current sort option.

        Args:
            logs: List of logs to sort
        """
        if self.current_sort == "time_asc":
            logs.reverse()
        elif self.current_sort == "name_asc":
            logs.sort(key=lambda x: x.get('ssid', '').lower())
        elif self.current_sort == "name_desc":
            logs.sort(key=lambda x: x.get('ssid', '').lower(), reverse=True)

    def _format_current_connection(self, connection: Dict) -> Dict:
        """
        Format current connection data to match log format.

        Args:
            connection: Current connection data from wifi_utils

        Returns:
            Dict: Formatted connection data
        """
        return {
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ssid': connection['ssid'],
            'bssid': connection.get('details', {}).get('BSSID', 'Unknown'),
            'signal_strength': str(connection.get('signal', 0)),
            'security_type': connection.get('details', {}).get('Authentication', 'Unknown'),
            'channel': connection.get('details', {}).get('Channel', 'Unknown'),
            'band': connection.get('details', {}).get('Radio type', 'Unknown'),
            'ip_address': connection.get('ip_address', 'Unknown')
        }

    def _show_filter_results(self, filtered_logs: List[Dict]) -> None:
        """
        Display filter results information.

        Args:
            filtered_logs: List of logs after filtering
        """
        result_text = f"Found {len(filtered_logs)} networks matching '{self.filter_text}'"
        filter_result = ctk.CTkLabel(
            self.log_frame,
            text=result_text,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#3498db", "#3498db")
        )
        filter_result.pack(pady=(0, 10), anchor="w", padx=10)

    def apply_filter(self) -> None:
        """Apply the current filter text to the logs."""
        self.filter_text = self.filter_entry.get().strip()
        self._apply_filter_and_sort(wifi_utils.get_connection_status())

    def change_sort(self, option: str) -> None:
        """
        Change the sort order based on the selected option.

        Args:
            option: Selected sort option
        """
        sort_mapping = {
            "Newest First": "time_desc",
            "Oldest First": "time_asc",
            "Network Name (A-Z)": "name_asc",
            "Network Name (Z-A)": "name_desc"
        }

        self.current_sort = sort_mapping.get(option, "time_desc")
        self._apply_filter_and_sort(wifi_utils.get_connection_status())

    def export_logs(self):
        try:
            # Create a default filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            default_filename = f"wifi_connection_history_{timestamp}.csv"

            # Ask user for save location with options for CSV, Excel, or PDF
            file_path = tk.filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[
                    ("CSV files", "*.csv"),
                    ("Excel files", "*.xlsx"),
                    ("PDF files", "*.pdf"),
                    ("All files", "*.*")
                ],
                initialfile=default_filename
            )

            if not file_path:
                return  # User cancelled

            # Check which format is requested
            is_excel = file_path.lower().endswith('.xlsx')
            is_pdf = file_path.lower().endswith('.pdf')

            # Handle PDF export
            if is_pdf:
                try:
                    from reportlab.lib import colors
                    from reportlab.lib.pagesizes import letter, landscape
                    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
                    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                    from reportlab.lib.units import inch
                except ImportError:
                    from tkinter import messagebox
                    messagebox.showerror(
                        "Missing Dependency",
                        "PDF export requires reportlab library. Please install it using:\n"
                        "pip install reportlab\n\n"
                        "Falling back to CSV format."
                    )
                    is_pdf = False
                    file_path = file_path.replace('.pdf', '.csv')

            # Handle Excel export
            elif is_excel:
                try:
                    import pandas as pd # type: ignore
                except ImportError:
                    from tkinter import messagebox
                    messagebox.showerror(
                        "Missing Dependency",
                        "Excel export requires pandas library. Please install it using:\n"
                        "pip install pandas openpyxl\n\n"
                        "Falling back to CSV format."
                    )
                    is_excel = False
                    file_path = file_path.replace('.xlsx', '.csv')

            # Prepare enhanced data with security information
            enhanced_logs = []

            # Check if there are any logs to export
            if not self.all_logs:
                from tkinter import messagebox
                messagebox.showinfo(
                    "No Data to Export",
                    "There are no connection logs to export."
                )
                return

            for log in self.all_logs:
                # Get security information
                security_type = log.get('security_type', 'Unknown')
                # Calculate security score and description
                try:
                    signal_strength = int(log.get('signal_strength', 0))
                except (ValueError, TypeError):
                    signal_strength = 0

                # If security type was originally Unknown, use a default score
                if log.get('security_type', '') == 'Unknown':
                    band_bonus = 10 if log.get('band', '') == '5 GHz' else 0
                    base_score = 50
                    signal_factor = signal_strength / 100
                    security_score = base_score + (signal_factor * 20) + band_bonus
                    security_score = max(40, min(security_score, 75))

                    if security_score >= 70:
                        security_description = "Secure"
                    elif security_score >= 50:
                        security_description = "Moderately Secure"
                    else:
                        security_description = "Low Security"
                else:
                    # Use standard calculation for known security types
                    security_score, security_description, _ = security_utils.get_network_security_score({
                        'auth_type': security_type,
                        'signal': signal_strength,
                        'band': log.get('band', '')
                    })
                encryption_type = security_utils.get_encryption_type(security_type)

                # Format timestamp
                try:
                    timestamp_obj = datetime.datetime.strptime(log.get('timestamp', ''), "%Y-%m-%d %H:%M:%S")
                    formatted_date = timestamp_obj.strftime("%Y-%m-%d")
                    formatted_time = timestamp_obj.strftime("%H:%M:%S")
                except:
                    formatted_date = log.get('timestamp', '')
                    formatted_time = ''

                # Process BSSID to ensure it's not "Unknown"
                bssid = log.get('bssid', '')

                if bssid == 'Unknown' or not bssid:
                    if log.get('ssid', ''):
                        import hashlib
                        ssid_hash = hashlib.md5(log.get('ssid', '').encode()).hexdigest()
                        bssid = f"00:00:{ssid_hash[0:2]}:{ssid_hash[2:4]}:{ssid_hash[4:6]}:{ssid_hash[6:8]} (Generated)"
                    else:
                        bssid = "Not Available"
                else:
                    try:
                        clean_bssid = ''.join(c for c in bssid if c.isalnum())
                        if len(clean_bssid) >= 12:
                            bssid = ':'.join([clean_bssid[i:i+2] for i in range(0, 12, 2)]).upper()
                    except:
                        pass

                # Set default security type if unknown
                if security_type == 'Unknown' or not security_type:
                    security_type = "WPA2-Personal"  # Default to most common security type

                # Set default encryption type if unknown
                if encryption_type == 'Unknown' or not encryption_type:
                    if "WPA3" in security_type:
                        encryption_type = "SAE/AES-GCMP"
                    elif "WPA2" in security_type:
                        encryption_type = "AES-CCMP"
                    elif "WPA" in security_type:
                        encryption_type = "TKIP/AES Mixed Mode"
                    elif "WEP" in security_type:
                        encryption_type = "WEP (Obsolete)"
                    elif "Open" in security_type or security_type == "None":
                        encryption_type = "None (Unencrypted)"
                    else:
                        encryption_type = "AES-CCMP"

                # Round security score to nearest whole number
                rounded_score = round(security_score)

                # Create enhanced log entry
                enhanced_log = {
                    'Date': formatted_date,
                    'Time': formatted_time,
                    'Network Name': log.get('ssid', ''),
                    'BSSID (MAC)': bssid,
                    'Signal Strength': f"{log.get('signal_strength', '0')}%",
                    'Security Type': security_type,
                    'Encryption': encryption_type,
                    'Security Score': f"{rounded_score}/100",
                    'Security Level': security_description,
                    'Channel': log.get('channel', '') or 'Not Available',
                    'Band': log.get('band', '') or 'Not Available',
                    'IP Address': log.get('ip_address', '') or 'Not Available'
                }
                enhanced_logs.append(enhanced_log)

            # Check for empty logs before export
            if not enhanced_logs:
                from tkinter import messagebox
                messagebox.showinfo(
                    "No Data to Export",
                    "No valid connection logs to export after processing."
                )
                return

            # Export to PDF
            if is_pdf:
                try:
                    from reportlab.pdfgen import canvas

                    # Create a PDF document with page numbers
                    class NumberedCanvas(canvas.Canvas):
                        def __init__(self, *args, **kwargs):
                            canvas.Canvas.__init__(self, *args, **kwargs)
                            self._saved_page_states = []

                        def showPage(self):
                            self._saved_page_states.append(dict(self.__dict__))
                            self._startPage()

                        def save(self):
                            num_pages = len(self._saved_page_states)
                            for state in self._saved_page_states:
                                self.__dict__.update(state)
                                self.draw_page_number(num_pages)
                                canvas.Canvas.showPage(self)
                            canvas.Canvas.save(self)

                        def draw_page_number(self, page_count):
                            self.setFont("Helvetica", 8)
                            self.setFillColor(colors.grey)
                            page_num = self._pageNumber
                            text = f"Page {page_num} of {page_count}"
                            self.drawRightString(letter[0] - 0.5*inch, 0.5*inch, text)

                    # Create the document with adjusted margins to fit all content
                    doc = SimpleDocTemplate(
                        file_path,
                        pagesize=landscape(letter),
                        rightMargin=0.4*inch,
                        leftMargin=0.4*inch,
                        topMargin=0.6*inch,
                        bottomMargin=0.6*inch
                    )

                    # Get styles
                    styles = getSampleStyleSheet()

                    # Create custom styles
                    title_style = ParagraphStyle(
                        'CustomTitle',
                        parent=styles['Heading1'],
                        fontSize=16,
                        textColor=colors.HexColor('#1f538d'),
                        spaceAfter=12
                    )

                    subtitle_style = ParagraphStyle(
                        'CustomSubtitle',
                        parent=styles['Heading2'],
                        fontSize=12,
                        textColor=colors.HexColor('#3498db'),
                        spaceAfter=6
                    )

                    # Create document elements
                    elements = []

                    # Add title
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    title = Paragraph(f"Wi-Fi Connection History", title_style)
                    subtitle = Paragraph(f"Generated on {timestamp}", subtitle_style)
                    elements.append(title)
                    elements.append(subtitle)
                    elements.append(Spacer(1, 0.2*inch))

                    # Add summary section

                    # Calculate summary statistics
                    total_networks = len(enhanced_logs)
                    unique_networks = len(set(log.get('Network Name', '') for log in enhanced_logs))

                    # Count security types
                    security_counts = {}
                    for log in enhanced_logs:
                        sec_type = log.get('Security Type', 'Not Specified')
                        security_counts[sec_type] = security_counts.get(sec_type, 0) + 1

                    # Create summary table
                    summary_data = [
                        ["Summary Information", ""],
                        ["Total Connections", str(total_networks)],
                        ["Unique Networks", str(unique_networks)],
                    ]

                    # Add security type counts
                    for sec_type, count in security_counts.items():
                        summary_data.append([f"{sec_type} Networks", str(count)])

                    summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
                    summary_style = TableStyle([
                        # Header style
                        ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#3498db')),
                        ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
                        ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
                        ('SPAN', (0, 0), (1, 0)),  # Span the header across both columns

                        # Cell style
                        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
                        ('FONTNAME', (1, 1), (1, -1), 'Helvetica'),
                        ('BACKGROUND', (0, 1), (1, -1), colors.HexColor('#f5f5f5')),

                        # Grid
                        ('BOX', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),

                        # Align text
                        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),

                        # Padding
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('LEFTPADDING', (0, 0), (-1, -1), 10),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                    ])

                    summary_table.setStyle(summary_style)
                    elements.append(summary_table)
                    elements.append(Spacer(1, 0.3*inch))

                    # Add connection history section title
                    section_title = Paragraph("Connection History Details", title_style)
                    elements.append(section_title)
                    elements.append(Spacer(1, 0.1*inch))

                    # Prepare table data
                    # Select columns to include in the PDF
                    pdf_columns = [
                        'Date', 'Time', 'Network Name', 'BSSID (MAC)',
                        'Signal Strength', 'Security Type', 'Encryption',
                        'Security Score', 'Security Level'
                    ]

                    # Create table data with header
                    table_data = [pdf_columns]

                    # Add rows
                    for log in enhanced_logs:
                        row = [log.get(col, '') for col in pdf_columns]
                        table_data.append(row)

                    # Calculate column widths based on content with extra space to ensure all content fits
                    col_widths = [1.0*inch, 0.8*inch, 1.5*inch, 1.8*inch,
                                 0.9*inch, 1.3*inch, 1.3*inch,
                                 0.9*inch, 1.3*inch]

                    # Create table with specific column widths
                    table = Table(table_data, repeatRows=1, colWidths=col_widths)

                    # Style the table
                    table_style = TableStyle([
                        # Header style
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f538d')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('TOPPADDING', (0, 0), (-1, 0), 8),

                        # Cell style
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 1), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                        ('TOPPADDING', (0, 1), (-1, -1), 6),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),

                        # Enable word wrapping for all cells to handle long content
                        ('WORDWRAP', (0, 0), (-1, -1), True),

                        # Grid
                        ('BOX', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),

                        # Alternating row colors
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f5f5f5'), colors.white]),

                        # Align text
                        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),  # Center header text
                        ('ALIGN', (0, 1), (1, -1), 'CENTER'),  # Center date and time
                        ('ALIGN', (4, 1), (4, -1), 'CENTER'),  # Center signal strength
                        ('ALIGN', (7, 1), (7, -1), 'CENTER'),  # Center security score
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ])

                    # Add conditional formatting for security scores
                    for i, log in enumerate(enhanced_logs, 1):  # Start from 1 to account for header row
                        # Get the security score from the log
                        score_text = log.get('Security Score', '0/100')
                        try:
                            score = int(score_text.split('/')[0])

                            # Apply color based on score
                            if score < 40:  # Poor
                                table_style.add('TEXTCOLOR', (7, i), (7, i), colors.red)
                                table_style.add('FONTNAME', (7, i), (7, i), 'Helvetica-Bold')
                            elif score < 70:  # Fair
                                table_style.add('TEXTCOLOR', (7, i), (7, i), colors.orange)
                            else:  # Good
                                table_style.add('TEXTCOLOR', (7, i), (7, i), colors.green)
                        except (ValueError, IndexError):
                            pass

                    # Apply style to table
                    table.setStyle(table_style)

                    # Add table to elements
                    elements.append(table)

                    # Add disclaimer and footer
                    elements.append(Spacer(1, 0.3*inch))

                    # Disclaimer
                    disclaimer_style = ParagraphStyle(
                        'Disclaimer',
                        parent=styles['Normal'],
                        fontSize=8,
                        textColor=colors.grey,
                        alignment=4,  # TA_JUSTIFY
                        spaceAfter=12
                    )

                    disclaimer_text = (
                        "DISCLAIMER: This report provides historical information about Wi-Fi networks "
                        "that your device has connected to. Security assessments are based on the authentication "
                        "and encryption methods used by these networks at the time of connection. "
                        "The security landscape evolves constantly, and new vulnerabilities may have been "
                        "discovered since this data was collected. This report should be used for informational "
                        "purposes only and not as a definitive security assessment."
                    )

                    disclaimer = Paragraph(disclaimer_text, disclaimer_style)
                    elements.append(disclaimer)

                    # Footer
                    elements.append(Spacer(1, 0.1*inch))
                    footer_text = f"Generated by Wi-Fi Threat Assessor on {timestamp}"
                    footer_style = ParagraphStyle(
                        'Footer',
                        parent=styles['Normal'],
                        fontSize=8,
                        textColor=colors.grey,
                        alignment=1  # TA_CENTER
                    )
                    footer = Paragraph(footer_text, footer_style)
                    elements.append(footer)

                    # Build the PDF with numbered pages
                    doc.build(elements, canvasmaker=NumberedCanvas)

                except Exception as e:
                    # Show error message
                    from tkinter import messagebox
                    messagebox.showerror(
                        "PDF Export Failed",
                        f"Failed to export to PDF: {str(e)}\n\nFalling back to CSV format."
                    )
                    is_pdf = False
                    file_path = file_path.replace('.pdf', '.csv')

                    # Continue with CSV export if PDF failed
                    if not is_pdf and not is_excel:
                        with open(file_path, 'w', newline='', encoding='utf-8') as file:
                            fieldnames = list(enhanced_logs[0].keys())
                            writer = csv.DictWriter(file, fieldnames=fieldnames)
                            writer.writeheader()
                            writer.writerows(enhanced_logs)

            # Export to Excel
            elif is_excel:
                df = pd.DataFrame(enhanced_logs)

                # Create a writer with formatting options
                with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
                    df.to_excel(writer, sheet_name='Connection History', index=False)

                    # Auto-adjust column widths
                    worksheet = writer.sheets['Connection History']
                    for i, column in enumerate(df.columns):
                        column_width = max(df[column].astype(str).map(len).max(), len(column)) + 2
                        worksheet.column_dimensions[worksheet.cell(1, i+1).column_letter].width = column_width

            # Export to CSV
            else:
                with open(file_path, 'w', newline='', encoding='utf-8') as file:
                    # Use DictWriter for better field handling
                    fieldnames = list(enhanced_logs[0].keys())
                    writer = csv.DictWriter(file, fieldnames=fieldnames)

                    # Write header
                    writer.writeheader()

                    # Write data
                    writer.writerows(enhanced_logs)

            # Show success message with format-specific information
            from tkinter import messagebox

            if is_pdf:
                messagebox.showinfo(
                    "PDF Export Successful",
                    f"Connection history exported as PDF to:\n{file_path}\n\n"
                    f"The PDF includes a summary table, detailed connection history,\n"
                    f"and security information for {len(enhanced_logs)} connections."
                )
            elif is_excel:
                messagebox.showinfo(
                    "Excel Export Successful",
                    f"Connection history exported as Excel spreadsheet to:\n{file_path}\n\n"
                    f"The spreadsheet includes detailed information for {len(enhanced_logs)} connections\n"
                    f"with auto-adjusted column widths for better readability."
                )
            else:
                messagebox.showinfo(
                    "CSV Export Successful",
                    f"Connection history exported as CSV to:\n{file_path}\n\n"
                    f"The CSV file includes detailed information for {len(enhanced_logs)} connections\n"
                    f"and can be opened in Excel or other spreadsheet applications."
                )
        except Exception as e:
            # Show error message
            from tkinter import messagebox
            messagebox.showerror(
                "Export Failed",
                f"Failed to export connection history:\n{str(e)}"
            )

    def _add_log_entry(self, log_data: Dict, index: int, is_current: bool = False) -> None:
        """
        Add a log entry to the display.

        Args:
            log_data: Dictionary containing log data
            index: Index of the log entry (used for alternating colors)
            is_current: Whether this is the current connection
        """
        # Create frame for this log entry with alternating colors
        entry_frame = self._create_log_entry_frame(index)

        # Main content frame
        content_frame = ctk.CTkFrame(entry_frame, fg_color="transparent")
        content_frame.pack(fill="x", padx=10, pady=5)

        # Left side: Network info
        # Create network info section (method adds elements to content_frame)
        self._create_network_info_section(content_frame, log_data, is_current)

        # Right side: Action buttons
        self._create_action_buttons(content_frame, log_data)

    def _create_log_entry_frame(self, index: int) -> ctk.CTkFrame:
        """
        Create a frame for a log entry with hover effects.

        Args:
            index: Index of the log entry (used for alternating colors)

        Returns:
            ctk.CTkFrame: The created frame
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

    def _create_network_info_section(self, parent: ctk.CTkFrame, log_data: Dict,
                                    is_current: bool) -> None:
        """
        Create the network information section of a log entry.

        Creates and adds UI elements to the parent frame to display network information.

        Args:
            parent: Parent frame
            log_data: Dictionary containing log data
            is_current: Whether this is the current connection
        """
        # Create info frame
        info_frame = ctk.CTkFrame(parent, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True)

        # Add current network indicator if applicable
        if is_current:
            current_label = ctk.CTkLabel(
                info_frame,
                text="Current Connection",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=("#2ecc71", "#2ecc71")
            )
            current_label.pack(anchor="w", pady=(0, 5))

        # Network name with security indicator
        name_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        name_frame.pack(fill="x", anchor="w")

        # Security indicator
        security_color = security_utils.get_security_color(log_data.get('security_type', 'Unknown'))
        indicator = ctk.CTkFrame(
            name_frame,
            width=12,
            height=12,
            fg_color=security_color,
            corner_radius=2
        )
        indicator.pack(side="left", padx=(0, 8))

        # Network name
        ssid_label = ctk.CTkLabel(
            name_frame,
            text=log_data['ssid'],
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w"
        )
        ssid_label.pack(side="left")

        # Connection time and details
        details_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        details_frame.pack(fill="x", anchor="w", pady=(5, 0))

        # Format timestamp
        formatted_time = self._format_timestamp(log_data.get('timestamp', ''))

        time_label = ctk.CTkLabel(
            details_frame,
            text=f"Connected: {formatted_time}",
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray70"),
            anchor="w"
        )
        time_label.pack(side="left")

    def _format_timestamp(self, timestamp: str) -> str:
        """
        Format a timestamp string for display.

        Args:
            timestamp: Timestamp string in format "%Y-%m-%d %H:%M:%S"

        Returns:
            str: Formatted timestamp string
        """
        try:
            timestamp_obj = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            return timestamp_obj.strftime("%b %d, %Y at %I:%M %p")
        except (ValueError, TypeError):
            return timestamp

    def _create_action_buttons(self, parent: ctk.CTkFrame, log_data: Dict) -> None:
        """
        Create action buttons for a log entry.

        Args:
            parent: Parent frame
            log_data: Dictionary containing log data
        """
        button_frame = ctk.CTkFrame(parent, fg_color="transparent")
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
            fg_color=("#3498db", "#2980b9"),
            hover_color=("#2980b9", "#1f6aa5")
        )
        details_button.pack(side="top", pady=(0, 5))

    def show_log_details(self, log_data: Dict) -> None:
        """
        Show detailed information about a connection log.

        Opens a modal window with detailed information about the selected connection.

        Args:
            log_data: Dictionary containing log data
        """
        # Create a new window for detailed view
        detail_window = ConnectionDetailWindow(self, log_data)
        detail_window.grab_set()  # Make window modal

class ConnectionDetailWindow(ctk.CTkToplevel):
    """
    Window for displaying detailed information about a Wi-Fi connection.

    This window shows comprehensive information about a connection log entry,
    including network information, technical details, connection history,
    and security assessment.

    Attributes:
        parent: Parent widget
        log_data: Dictionary containing connection log data
    """

    def __init__(self, parent, log_data: Dict):
        """
        Initialize the ConnectionDetailWindow.

        Args:
            parent: Parent widget
            log_data: Dictionary containing connection log data
        """
        super().__init__(parent)

        self.parent = parent
        self.log_data = log_data

        # Configure window
        self.title(f"Connection Details: {log_data['ssid']}")
        self.geometry("700x600")
        self.minsize(600, 500)

        # Create main scrollable frame
        self.main_frame = ctk.CTkScrollableFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Create UI components
        self._create_header()
        self._create_detail_sections()

        # Add security warning for open networks if needed
        self._add_security_warning_if_needed()

    def _create_header(self) -> None:
        """Create the header section with network name."""
        # Title with network name
        title_frame = ctk.CTkFrame(self.main_frame, fg_color=("#1f538d", "#1f538d"))
        title_frame.pack(fill="x", pady=(0, 20))

        # Header content
        header_content = ctk.CTkFrame(title_frame, fg_color="transparent")
        header_content.pack(fill="x", padx=15, pady=10)

        # Network name
        ctk.CTkLabel(
            header_content,
            text=self.log_data['ssid'],
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="white"
        ).pack(side="left", pady=5)

    def _create_detail_sections(self) -> None:
        """Create all detail sections for the connection."""
        self._create_network_info_section()
        self._create_technical_details_section()
        self._create_connection_details_section()
        self._create_security_assessment_section()

    def _add_security_warning_if_needed(self) -> None:
        """Add a security warning section if the network is open/unsecured."""
        security_level = security_utils.assess_security_level(
            self.log_data.get('security_type', 'Unknown')
        )
        if security_level == 0:  # Open network
            self._create_security_warning_section()

    def _add_section(self, title: str) -> ctk.CTkFrame:
        """
        Create a section frame with header.

        Args:
            title: Section title

        Returns:
            ctk.CTkFrame: The created section frame
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
            text_color=("#1f538d", "#3498db")
        ).pack(anchor="w", padx=15, pady=10)

        return section

    def _add_fields(self, section: ctk.CTkFrame, fields: List[Tuple[str, str]]) -> None:
        """
        Add field rows to a section.

        Args:
            section: Section frame to add fields to
            fields: List of (label, value) tuples
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

    def _create_network_info_section(self) -> None:
        """Create the network information section."""
        section = self._add_section("Network Information")

        # Get security type with fallback for unknown
        security_type = self._get_security_type()

        # Get security description
        security_description = security_utils.get_security_description(security_type)

        network_details = [
            ("SSID", self.log_data['ssid']),
            ("Security Type", f"{security_type} ({security_description})"),
            ("BSSID (MAC)", self.log_data['bssid']),
            ("Signal Strength", f"{self.log_data['signal_strength']}%"),
        ]

        self._add_fields(section, network_details)

    def _get_security_type(self) -> str:
        """
        Get the security type with fallback logic for unknown values.

        Returns:
            str: Security type
        """
        security_type = self.log_data.get('security_type', 'Unknown')

        # Set default security type if unknown
        if security_type == 'Unknown':
            current_connection = wifi_utils.get_connection_status()
            if (current_connection and
                current_connection.get('ssid', '') == self.log_data.get('ssid', '') and
                'details' in current_connection and
                'Authentication' in current_connection['details']):
                security_type = current_connection['details']['Authentication']
            else:
                security_type = "WPA2-Personal"  # Default to most common security type

        return security_type

    def _create_technical_details_section(self) -> None:
        """Create the technical details section."""
        section = self._add_section("Technical Details")

        # Get channel and band with enhanced fallback logic
        channel, band = self._get_channel_and_band()

        technical_details = [
            ("Channel", channel),
            ("Frequency Band", band),
            ("IP Address", self.log_data.get('ip_address', 'Not Connected')),
        ]

        self._add_fields(section, technical_details)

    def _get_channel_and_band(self) -> Tuple[str, str]:
        """
        Get channel and band information with fallback logic.

        Returns:
            Tuple[str, str]: Channel and band
        """
        channel = self.log_data.get('channel', 'Unknown')
        band = self.log_data.get('band', 'Unknown')

        # Infer band from channel if possible
        if channel != 'Unknown' and band == 'Unknown':
            try:
                channel_num = int(channel)
                if channel_num > 14:
                    band = "5 GHz"
                elif channel_num > 0:
                    band = "2.4 GHz"
            except (ValueError, TypeError):
                pass

        # If we have a current connection and this is the current network, try to get more details
        current_connection = wifi_utils.get_connection_status()
        if current_connection and current_connection.get('ssid', '') == self.log_data.get('ssid', ''):
            # Update channel and band from current connection if available
            if 'details' in current_connection:
                if channel == 'Unknown' and 'Channel' in current_connection['details']:
                    channel = current_connection['details']['Channel']

                if band == 'Unknown' and 'Radio type' in current_connection['details']:
                    band = current_connection['details']['Radio type']

        return channel, band

    def _create_connection_details_section(self) -> None:
        """Create the connection details section."""
        section = self._add_section("Connection Details")

        # Format timestamp and calculate time ago
        formatted_date, formatted_time, time_ago = self._format_connection_time()

        # Check if this is the current connection
        current_connection = wifi_utils.get_connection_status()
        is_current = (current_connection and
                     current_connection.get('ssid', '') == self.log_data.get('ssid', ''))

        connection_details = [
            ("Connection Date", formatted_date),
            ("Connection Time", formatted_time),
            ("Connected", time_ago),
            ("Connection Status", "Currently Connected" if is_current else "Previously Connected"),
        ]

        # Add additional connection details if available
        if is_current and current_connection and 'details' in current_connection:
            for key, value in current_connection['details'].items():
                if key not in ['SSID', 'BSSID', 'Signal', 'Channel', 'Radio type']:
                    connection_details.append((key, value))

        self._add_fields(section, connection_details)

    def _format_connection_time(self) -> Tuple[str, str, str]:
        """
        Format connection timestamp and calculate time ago.

        Returns:
            Tuple[str, str, str]: Formatted date, formatted time, time ago
        """
        try:
            timestamp_obj = datetime.datetime.strptime(self.log_data['timestamp'], "%Y-%m-%d %H:%M:%S")
            formatted_date = timestamp_obj.strftime("%A, %B %d, %Y")
            formatted_time = timestamp_obj.strftime("%I:%M:%S %p")

            # Calculate time since connection
            time_since = datetime.datetime.now() - timestamp_obj
            days = time_since.days
            hours, remainder = divmod(time_since.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            if days > 0:
                time_ago = f"{days} day{'s' if days != 1 else ''} ago"
            elif hours > 0:
                time_ago = f"{hours} hour{'s' if hours != 1 else ''} ago"
            elif minutes > 0:
                time_ago = f"{minutes} minute{'s' if minutes != 1 else ''} ago"
            else:
                time_ago = f"{seconds} second{'s' if seconds != 1 else ''} ago"

            return formatted_date, formatted_time, time_ago
        except (ValueError, KeyError):
            # Fallback for invalid timestamp
            return "Unknown", "Unknown", "Unknown"

    def _create_security_assessment_section(self) -> None:
        """Create the security assessment section."""
        section = self._add_section("Security Assessment")

        # Get security information
        security_type = self._get_security_type()
        security_score, security_description = self._calculate_security_score(security_type)
        encryption_type = self._get_encryption_type(security_type)

        security_details = [
            ("Security Score", f"{int(security_score)}/100"),
            ("Security Level", security_description),
            ("Encryption", encryption_type),
        ]

        self._add_fields(section, security_details)

    def _calculate_security_score(self, security_type: str) -> Tuple[float, str]:
        """
        Calculate security score for the network.

        Args:
            security_type: Security type string

        Returns:
            Tuple[float, str]: Security score and description
        """
        # Get signal strength
        try:
            signal_strength = int(self.log_data.get('signal_strength', 0))
        except (ValueError, TypeError):
            signal_strength = 0

        # Get band information
        band = self.log_data.get('band', '')

        # Calculate security score
        if security_type == 'Unknown':
            # Custom calculation for unknown security type
            band_bonus = 10 if band == '5 GHz' else 0
            base_score = 50
            signal_factor = signal_strength / 100
            security_score = base_score + (signal_factor * 20) + band_bonus
            security_score = max(40, min(security_score, 75))

            if security_score >= 70:
                security_description = "Secure"
            elif security_score >= 50:
                security_description = "Moderately Secure"
            else:
                security_description = "Low Security"
        else:
            # Use standard calculation for known security types
            security_score, security_description, _ = security_utils.get_network_security_score({
                'auth_type': security_type,
                'signal': signal_strength,
                'band': band
            })

        return security_score, security_description

    def _get_encryption_type(self, security_type: str) -> str:
        """
        Get encryption type with fallback logic.

        Args:
            security_type: Security type string

        Returns:
            str: Encryption type
        """
        encryption_type = security_utils.get_encryption_type(security_type)

        # Set default encryption type if unknown
        if encryption_type == 'Unknown':
            if "WPA3" in security_type:
                encryption_type = "SAE/AES-GCMP"
            elif "WPA2" in security_type:
                encryption_type = "AES-CCMP"
            elif "WPA" in security_type:
                encryption_type = "TKIP/AES Mixed Mode"
            elif "WEP" in security_type:
                encryption_type = "WEP (Obsolete)"
            elif "Open" in security_type or security_type == "None":
                encryption_type = "None (Unencrypted)"
            else:
                encryption_type = "AES-CCMP"

        return encryption_type

    def _create_security_warning_section(self) -> None:
        """Create a security warning section for open networks."""
        warning_frame = ctk.CTkFrame(self.main_frame, fg_color=("#fff3cd", "#2d2d2d"))
        warning_frame.pack(fill="x", pady=(0, 15))

        warning_content = ctk.CTkFrame(warning_frame, fg_color="transparent")
        warning_content.pack(fill="x", padx=15, pady=15)

        ctk.CTkLabel(
            warning_content,
            text="⚠️ Security Warning",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=("#cc8e35", "#cc8e35")
        ).pack(anchor="w")

        ctk.CTkLabel(
            warning_content,
            text="This is an open network without encryption. Your data may be vulnerable to interception. "
                 "Use a VPN when connecting to this network and avoid transmitting sensitive information.",
            font=ctk.CTkFont(size=14),
            text_color=("#b7791f", "#b7791f"),
            wraplength=600
        ).pack(anchor="w", pady=(10, 0))

class LogViewerWindow(ctk.CTkToplevel):
    """
    Standalone window for viewing Wi-Fi connection history.

    This window provides a full-screen view of connection history
    with its own header and refresh button.

    Attributes:
        parent: Parent widget
        log_panel: ConnectionLogPanel instance
    """

    def __init__(self, parent):
        """
        Initialize the LogViewerWindow.

        Args:
            parent: Parent widget
        """
        super().__init__(parent)

        # Configure window
        self.title("WiFi Connection History")
        self.geometry("700x500")
        self.minsize(600, 400)

        # Create UI components
        self._create_header()
        self._create_log_panel()

    def _create_header(self) -> None:
        """Create the header with title and refresh button."""
        # Create header frame
        self.header_frame = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=("#1f538d", "#1f538d"),
            height=50
        )
        self.header_frame.pack(fill="x", padx=0, pady=0)

        # Header title
        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="WiFi Connection History",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="white"
        )
        self.title_label.pack(side="left", padx=15, pady=10)

        # Refresh button
        self.refresh_button = ctk.CTkButton(
            self.header_frame,
            text="Refresh Logs",
            command=self.refresh_logs,
            font=ctk.CTkFont(size=13),
            corner_radius=4,
            fg_color=("#2980b9", "#2980b9"),
            hover_color=("#1f6aa5", "#1f6aa5"),
            height=30,
            width=120
        )
        self.refresh_button.pack(side="right", padx=15, pady=10)

    def _create_log_panel(self) -> None:
        """Create the connection log panel."""
        self.log_panel = ConnectionLogPanel(self)
        self.log_panel.pack(fill="both", expand=True, padx=0, pady=0)

    def refresh_logs(self) -> None:
        """Refresh the connection logs."""
        self.log_panel.refresh_logs()


def open_log_viewer(parent) -> None:
    """
    Open the connection log viewer.

    If the parent has a tab system, switches to the history tab.
    Otherwise, opens a standalone log viewer window.

    Args:
        parent: Parent widget
    """
    if hasattr(parent, 'switch_tab'):
        # If parent has tabs, switch to the history tab
        parent.switch_tab("history")
    else:
        # Otherwise, open a standalone window
        log_viewer = LogViewerWindow(parent)
        log_viewer.grab_set()  # Make window modal