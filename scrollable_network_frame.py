"""
Scrollable Network Frame for Wi-Fi Threat Assessor.

This module provides a scrollable frame for displaying Wi-Fi networks
with detailed information and interactive elements. It handles the presentation
of network data in a tabular format with security indicators and interactive
elements for each network.
"""

from typing import List, Dict, Any, Optional

import customtkinter as ctk

import security_utils
from network_detail_window import NetworkDetailWindow
from ui_constants import COLORS


class ScrollableNetworkFrame(ctk.CTkScrollableFrame):
    """
    Scrollable frame for displaying Wi-Fi networks with detailed information.

    This class creates a scrollable table that displays network information including
    SSID, signal strength, frequency band, security type, security score, and BSSID.
    Each row includes an interactive button to view detailed network information.
    """

    def __init__(self, master: Any, **kwargs: Any) -> None:
        """
        Initialize the scrollable network frame.

        Args:
            master: Parent widget that will contain this frame
            **kwargs: Additional keyword arguments for CTkScrollableFrame
        """
        super().__init__(master, **kwargs)
        self.network_data: List[Dict] = []
        self.parent = master
        self._header_frame: Optional[ctk.CTkFrame] = None

        # Define column structure for the network table
        self.column_widths = [
            40,     # Indicator column
            200,    # SSID column
            120,    # Signal column
            120,    # Band column
            170,    # Security column
            130,    # Score column
            200,    # BSSID column
            90      # Info button column
        ]

        self.column_names = [
            "",         # Indicator
            "SSID",     # Network name
            "Signal",   # Signal strength
            "Band",     # Frequency band
            "Security", # Security type
            "Score",    # Security score
            "BSSID",    # MAC address
            "Info"      # Info button
        ]

        # Create main container for the table
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=0, pady=0)
        self.main_container.grid_columnconfigure(0, weight=1)

        self._create_header()

        self.table_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.table_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

    def _create_header(self) -> None:
        """Create the header row with column names."""
        # Create header frame with blue background
        self._header_frame = ctk.CTkFrame(
            self.main_container,
            fg_color=COLORS["primary_light"],
            corner_radius=4,
            height=46
        )
        self._header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(0, 12))
        self._header_frame.grid_propagate(False)

        # Configure column widths
        for i, width in enumerate(self.column_widths):
            if i == len(self.column_widths) - 1:
                self._header_frame.grid_columnconfigure(i, weight=1, minsize=width)
            else:
                self._header_frame.grid_columnconfigure(i, weight=0, minsize=width)

        # Create header labels
        for i, name in enumerate(self.column_names):
            # Determine text alignment based on column index
            if i == 1:  # SSID column - left aligned
                anchor = "w"
                sticky = "w"
            elif i == 0 or i == 7:  # Indicator and Info columns - center aligned
                anchor = "center"
                sticky = "ns"
            else:  # All other columns - right aligned
                anchor = "e"
                sticky = "e"

            # Create the header label
            label = ctk.CTkLabel(
                self._header_frame,
                text=name,
                font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
                text_color="white",
                anchor=anchor
            )

            # Determine padding based on column index
            if i == 0:
                padx_value = 10
            elif i == 1:
                padx_value = 5
            else:
                padx_value = 15

            # Place the label in the grid
            label.grid(row=0, column=i, padx=padx_value, pady=10, sticky=sticky)

    def show_network_details(self, network: Dict) -> None:
        """
        Open a detailed view window for the selected network.

        Args:
            network: Dictionary containing network information
        """
        NetworkDetailWindow(self.parent, network)

    def update_networks(self, networks: List[Dict]) -> None:
        """
        Update the network table with new network data.

        Args:
            networks: List of dictionaries containing network information
        """
        # Clear existing network rows
        for widget in self.table_frame.winfo_children():
            widget.destroy()

        # Store network data for later reference
        self.network_data = networks

        # Ensure table width matches header width
        self.table_frame.configure(width=self._header_frame.winfo_width())

        # Create a row for each network
        for i, network in enumerate(networks):
            self._create_network_row(network, i)

    def _create_network_row(self, network: Dict, row_index: int) -> None:
        """
        Create a row in the network table for a single network.

        Args:
            network: Dictionary containing network information
            row_index: Index of the row (used for alternating row colors)
        """
        # Determine row background color (alternating colors for better readability)
        bg_color = ("gray90", "#1e2f3d") if row_index % 2 == 0 else ("gray95", "#2d3436")

        # Create the row frame
        row_frame = ctk.CTkFrame(
            self.table_frame,
            fg_color=bg_color,
            corner_radius=4,
            height=42
        )
        row_frame.pack(fill="x", padx=0, pady=2)
        row_frame.pack_propagate(False)

        # Configure column widths
        for i, width in enumerate(self.column_widths):
            if i == len(self.column_widths) - 1:
                row_frame.grid_columnconfigure(i, weight=1, minsize=width)
            else:
                row_frame.grid_columnconfigure(i, weight=0, minsize=width)

        # Create security indicator
        security_color = security_utils.get_security_color(network['auth_type'])
        indicator = ctk.CTkFrame(
            row_frame,
            width=20,
            height=28,
            fg_color=security_color,
            corner_radius=4
        )
        indicator.grid(row=0, column=0, padx=10, pady=7, sticky="ns")

        # Create SSID label with truncation for long names
        ssid_text = network['ssid']
        if len(ssid_text) > 25:
            ssid_text = ssid_text[:22] + "..."

        ssid_label = ctk.CTkLabel(
            row_frame,
            text=ssid_text,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            anchor="w"
        )
        ssid_label.grid(row=0, column=1, padx=5, pady=7, sticky="w")

        # Create signal strength label
        signal_value = network['signal']
        signal_label = ctk.CTkLabel(
            row_frame,
            text=f"{signal_value}%",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            anchor="e"
        )
        signal_label.grid(row=0, column=2, padx=15, pady=7, sticky="e")

        # Determine frequency band from band or channel information
        band = network.get('band', 'Unknown')
        if band == 'Unknown':
            channel = network.get('channel', 0)
            if channel > 0:
                if channel > 14:
                    band = "5 GHz"
                else:
                    band = "2.4 GHz"

        # Format band display (shorten "GHz" to "G" for cleaner display)
        band_display = band.replace(" GHz", "G") if "GHz" in band else band

        # Create band label
        band_label = ctk.CTkLabel(
            row_frame,
            text=band_display,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            anchor="e"
        )
        band_label.grid(row=0, column=3, padx=15, pady=7, sticky="e")

        # Create security type label
        security_text = network['auth_type']
        security_label = ctk.CTkLabel(
            row_frame,
            text=security_text,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            anchor="e"
        )
        security_label.grid(row=0, column=4, padx=15, pady=7, sticky="e")

        # Calculate and display security score
        score = round(security_utils.get_network_security_score(network)[0])
        score_label = ctk.CTkLabel(
            row_frame,
            text=f"{score}/100",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            anchor="e"
        )
        score_label.grid(row=0, column=5, padx=15, pady=7, sticky="e")

        # Create BSSID label (using monospace font for better readability)
        bssid_label = ctk.CTkLabel(
            row_frame,
            text=network['bssid'],
            font=ctk.CTkFont(family="Consolas", size=13),
            anchor="e"
        )
        bssid_label.grid(row=0, column=6, padx=15, pady=7, sticky="e")

        # Create info button to open network details
        info_button = ctk.CTkButton(
            row_frame,
            text="Info",
            command=lambda n=network: self.show_network_details(n),
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=COLORS["primary_light"],
            hover_color=COLORS["primary_hover"],
            corner_radius=4,
            border_width=0,
            width=75,
            height=28
        )
        info_button.grid(row=0, column=7, padx=15, pady=7, sticky="ns")

        # Add hover effect to row
        def on_enter(_):
            row_frame.configure(fg_color=("#e8f0f8", "#1e2f3d"))

        def on_leave(_):
            row_frame.configure(fg_color=bg_color)

        row_frame.bind("<Enter>", on_enter)
        row_frame.bind("<Leave>", on_leave)

    def update_display(self) -> None:
        """
        Refresh the current network display without fetching new data.

        This method is useful when the UI needs to be refreshed after
        settings changes or window resizing.
        """
        if hasattr(self, 'network_data') and self.network_data:
            self.update_networks(self.network_data)
