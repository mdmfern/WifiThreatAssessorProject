"""
Speed Test Charts Generator for the Wi-Fi Threat Assessor application.

This module provides functionality to generate various charts and visualizations
for speed test results, including comparison charts, gauge charts for ping/latency,
and historical trend charts. These visualizations are used in the application's
PDF reports and UI components.
"""

import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from io import BytesIO
from typing import Dict, List, Optional, Any

# Set global matplotlib style for consistent appearance
plt.style.use('dark_background')
plt.rcParams['axes.facecolor'] = '#2b2b2b'
plt.rcParams['figure.facecolor'] = '#2b2b2b'
plt.rcParams['text.color'] = 'white'
plt.rcParams['axes.labelcolor'] = 'white'
plt.rcParams['xtick.color'] = 'white'
plt.rcParams['ytick.color'] = 'white'
plt.rcParams['grid.color'] = 'gray'
plt.rcParams['grid.alpha'] = 0.3
plt.rcParams['font.size'] = 10

# Color definitions
COLORS = {
    "download": "#3498db",  # Blue
    "upload": "#2ecc71",    # Green
    "ping": "#e74c3c",      # Red
    "excellent": "#2ecc71", # Green
    "good": "#27ae60",      # Dark Green
    "moderate": "#f1c40f",  # Yellow
    "fair": "#e67e22",      # Orange
    "poor": "#e74c3c"       # Red
}

class SpeedTestChartGenerator:
    """
    Class for generating charts and graphs for speed test results.

    This class provides static methods to create various visualizations for speed test data,
    including bar charts for speed comparisons, gauge charts for ping/latency measurements,
    and line charts for historical trend analysis. All charts are generated using matplotlib
    and returned as BytesIO objects that can be used in PDF reports or UI components.
    """

    @staticmethod
    def generate_speed_comparison_chart(test_data: Dict[str, Any]) -> BytesIO:
        """
        Generate a bar chart comparing download and upload speeds.

        Creates a horizontal bar chart that visually compares download and upload speeds
        from a speed test. The chart includes labeled bars with speed values in Mbps and
        uses consistent color coding (blue for download, green for upload).

        Args:
            test_data: Dictionary containing speed test results with keys 'download_speed'
                      and 'upload_speed' (values should be convertible to float)

        Returns:
            BytesIO object containing the chart image in PNG format
        """
        # Extract speed values
        download_speed = float(test_data.get('download_speed', 0))
        upload_speed = float(test_data.get('upload_speed', 0))

        # Create figure and axis
        fig, ax = plt.subplots(figsize=(6, 4))

        # Create bar chart
        bars = ax.bar(
            ['Download', 'Upload'],
            [download_speed, upload_speed],
            color=[COLORS["download"], COLORS["upload"]],
            width=0.6
        )

        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width()/2.,
                height + 5,
                f'{height:.1f} Mbps',
                ha='center',
                va='bottom',
                color='white',
                fontweight='bold'
            )

        # Set chart title and labels
        ax.set_title('Download vs Upload Speed', fontsize=14, pad=10)
        ax.set_ylabel('Speed (Mbps)', fontsize=12)

        # Set y-axis limit to accommodate the highest value plus some padding
        max_speed = max(download_speed, upload_speed)
        ax.set_ylim(0, max_speed * 1.2)  # 20% padding

        # Add grid lines for better readability
        ax.grid(axis='y', linestyle='--', alpha=0.7)

        # Tight layout to ensure everything fits
        plt.tight_layout()

        # Convert plot to image
        img_data = BytesIO()
        plt.savefig(img_data, format='png', dpi=100)
        img_data.seek(0)
        plt.close(fig)

        return img_data

    @staticmethod
    def generate_ping_gauge_chart(test_data: Dict[str, Any]) -> BytesIO:
        """
        Generate a gauge chart for ping/latency measurement.

        Creates a semi-circular gauge chart that visualizes ping/latency values with
        color coding based on quality thresholds. The chart includes the numeric ping value
        in milliseconds and a text rating (Excellent, Very Good, Good, etc.) that helps
        users interpret the results.

        Args:
            test_data: Dictionary containing speed test results with a 'ping' key
                      (value should be convertible to float)

        Returns:
            BytesIO object containing the chart image in PNG format
        """
        # Extract ping value
        ping = float(test_data.get('ping', 0))

        # Create figure and axis
        fig, ax = plt.subplots(figsize=(6, 3), subplot_kw={'projection': 'polar'})

        # Define gauge parameters
        gauge_max = 200  # Max ping to display (ms)

        # Normalize ping value to the range [0, 1]
        normalized_ping = min(ping / gauge_max, 1.0)

        # Define color based on ping value
        if ping < 20:
            color = COLORS["excellent"]
        elif ping < 40:
            color = COLORS["good"]
        elif ping < 100:
            color = COLORS["moderate"]
        elif ping < 150:
            color = COLORS["fair"]
        else:
            color = COLORS["poor"]

        # Plot the gauge
        theta = np.linspace(np.pi, 0, 100)
        ax.plot(theta, [1] * 100, color='gray', alpha=0.3, linewidth=8)

        # Plot the value arc
        value_theta = np.linspace(np.pi, np.pi * (1 - normalized_ping), 100)
        ax.plot(value_theta, [1] * len(value_theta), color=color, linewidth=8)

        # Add ping value text in the center
        ax.text(0, 0, f"{ping:.1f} ms", ha='center', va='center', fontsize=16, fontweight='bold')

        # Add rating text below the value
        if ping < 20:
            rating = "Excellent"
        elif ping < 40:
            rating = "Very Good"
        elif ping < 60:
            rating = "Good"
        elif ping < 100:
            rating = "Adequate"
        elif ping < 150:
            rating = "Fair"
        else:
            rating = "Poor"

        ax.text(0, -0.4, rating, ha='center', va='center', fontsize=12, color=color)

        # Customize the gauge appearance
        ax.set_rticks([])  # No radial ticks
        ax.set_xticks([])  # No angular ticks
        ax.spines['polar'].set_visible(False)  # Hide the outer circle

        # Set title
        ax.set_title('Ping / Latency', pad=15, fontsize=14)

        # Tight layout
        plt.tight_layout()

        # Convert plot to image
        img_data = BytesIO()
        plt.savefig(img_data, format='png', dpi=100)
        img_data.seek(0)
        plt.close(fig)

        return img_data

    @staticmethod
    def generate_historical_chart(speed_tests: List[Dict[str, Any]],
                                 metric: str = 'download_speed') -> Optional[BytesIO]:
        """
        Generate a line chart showing historical speed test results over time.

        Creates a time-series line chart that visualizes trends in network performance
        metrics (download speed, upload speed, or ping) across multiple speed tests.
        The chart includes data points, connecting lines, and properly formatted time
        axis labels.

        Args:
            speed_tests: List of dictionaries containing speed test results, each with
                        'timestamp' key (format: "%Y-%m-%d %H:%M:%S") and the specified
                        metric key with a numeric value
            metric: Which metric to plot - one of 'download_speed', 'upload_speed', or 'ping'
                   (default: 'download_speed')

        Returns:
            BytesIO object containing the chart image in PNG format, or None if there
            aren't enough valid data points (minimum 2 required)

        Note:
            For ping charts, the y-axis is inverted since lower ping values are better.
        """
        if len(speed_tests) < 2:
            return None  # Not enough data for a historical chart

        # Sort tests by timestamp
        try:
            sorted_tests = sorted(
                speed_tests,
                key=lambda x: datetime.strptime(x.get('timestamp', '1970-01-01 00:00:00'), "%Y-%m-%d %H:%M:%S")
            )
        except (ValueError, TypeError) as e:
            # If timestamp parsing fails, return None
            # This can happen if timestamps are in an unexpected format
            return None

        # Extract timestamps and values
        timestamps = []
        values = []

        for test in sorted_tests:
            try:
                timestamp = datetime.strptime(test.get('timestamp', ''), "%Y-%m-%d %H:%M:%S")
                value = float(test.get(metric, 0))

                timestamps.append(timestamp)
                values.append(value)
            except (ValueError, TypeError):
                continue

        if len(timestamps) < 2:
            return None  # Not enough valid data points

        # Create figure and axis
        fig, ax = plt.subplots(figsize=(7, 4))

        # Determine color and label based on metric
        if metric == 'download_speed':
            color = COLORS["download"]
            label = 'Download Speed (Mbps)'
            title = 'Download Speed History'
        elif metric == 'upload_speed':
            color = COLORS["upload"]
            label = 'Upload Speed (Mbps)'
            title = 'Upload Speed History'
        else:  # ping
            color = COLORS["ping"]
            label = 'Ping (ms)'
            title = 'Ping History'
            # For ping, lower is better, so invert the y-axis
            ax.invert_yaxis()

        # Plot the line
        ax.plot(timestamps, values, marker='o', linestyle='-', color=color, linewidth=2, markersize=6)

        # Format the x-axis to show dates nicely
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d %H:%M'))
        plt.xticks(rotation=45)

        # Add labels and title
        ax.set_xlabel('Date & Time')
        ax.set_ylabel(label)
        ax.set_title(title, fontsize=14, pad=10)

        # Add grid
        ax.grid(True, linestyle='--', alpha=0.7)

        # Tight layout
        plt.tight_layout()

        # Convert plot to image
        img_data = BytesIO()
        plt.savefig(img_data, format='png', dpi=100)
        img_data.seek(0)
        plt.close(fig)

        return img_data
