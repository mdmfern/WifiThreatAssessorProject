"""
Speed Test Report Generator for the Wi-Fi Threat Assessor application.

This module provides functionality to generate comprehensive PDF reports
for speed test results, including visualizations, ratings, and recommendations.
The reports can include single or multiple speed test results with historical analysis.
"""

import datetime
from pathlib import Path
import platform
import socket
from typing import Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image
)

from speed_test_charts import SpeedTestChartGenerator

# Constants for styling
FONT_NORMAL = 'Helvetica'
FONT_BOLD = 'Helvetica-Bold'
FONT_ITALIC = 'Helvetica-Oblique'
FONT_BOLD_ITALIC = 'Helvetica-BoldOblique'

# Color definitions
COLORS = {
    "primary": "#1f538d",
    "primary_light": "#3498db",
    "secondary": "#2ecc71",
    "text_primary": "#333333",
    "text_secondary": "#666666",
    "excellent": "#2ecc71",
    "good": "#27ae60",
    "moderate": "#f1c40f",
    "fair": "#e67e22",
    "poor": "#e74c3c"
}

class SpeedTestReportGenerator:
    """
    Generate comprehensive PDF reports for speed test results.

    This class creates professional PDF reports containing speed test results,
    including download/upload speeds, ping measurements, ratings, visualizations,
    and recommendations. Reports can include single or multiple test results with
    historical analysis and comparisons.

    The generated reports include:
    - A title page with device information
    - Historical charts for multiple tests
    - Detailed speed test results with ratings
    - Network information
    - Speed visualizations
    - Recommendations based on measured speeds
    - Usage guidance for the connection
    """

    def __init__(self, speed_tests: List[Dict[str, any]]):
        """
        Initialize the report generator with speed test data.

        Args:
            speed_tests: List of dictionaries containing speed test results.
                Each dictionary should contain at minimum:
                - 'download_speed': Download speed in Mbps
                - 'upload_speed': Upload speed in Mbps
                - 'ping': Ping/latency in ms
                - 'timestamp': Test time in format "%Y-%m-%d %H:%M:%S"
                - 'ssid': Network name
        """
        self.speed_tests = speed_tests
        self.styles = self._create_styles()
        self.device_info = self._get_device_info()

    def _create_styles(self) -> Dict[str, ParagraphStyle]:
        """
        Create and configure styles for the PDF report.

        Returns:
            Dictionary containing all paragraph and text styles used in the report
        """
        styles = getSampleStyleSheet()

        custom_styles = {
            'ReportTitle': ParagraphStyle(
                'ReportTitle',
                parent=styles['Heading1'],
                fontName=FONT_BOLD,
                fontSize=24,
                spaceAfter=24,
                spaceBefore=24,
                alignment=TA_CENTER,
                textColor=colors.HexColor(COLORS["primary"]),
                leading=30
            ),
            'ReportSubtitle': ParagraphStyle(
                'ReportSubtitle',
                parent=styles['Heading2'],
                fontName=FONT_NORMAL,
                fontSize=18,
                spaceAfter=18,
                alignment=TA_CENTER,
                textColor=colors.HexColor(COLORS["primary"]),
                leading=22
            ),
            'SectionTitle': ParagraphStyle(
                'SectionTitle',
                parent=styles['Heading2'],
                fontName=FONT_BOLD,
                fontSize=16,
                spaceAfter=12,
                spaceBefore=18,
                textColor=colors.HexColor(COLORS["primary"]),
                leading=20
            ),
            'SubsectionTitle': ParagraphStyle(
                'SubsectionTitle',
                parent=styles['Heading3'],
                fontName=FONT_BOLD,
                fontSize=14,
                spaceAfter=8,
                spaceBefore=12,
                textColor=colors.HexColor(COLORS["primary_light"]),
                leading=18
            ),
            'NormalText': ParagraphStyle(
                'NormalText',
                parent=styles['Normal'],
                fontName=FONT_NORMAL,
                fontSize=11,
                spaceAfter=8,
                leading=14
            ),
            'BoldText': ParagraphStyle(
                'BoldText',
                parent=styles['Normal'],
                fontName=FONT_BOLD,
                fontSize=11,
                spaceAfter=8,
                leading=14
            ),
            'ItalicText': ParagraphStyle(
                'ItalicText',
                parent=styles['Normal'],
                fontName=FONT_ITALIC,
                fontSize=11,
                spaceAfter=8,
                leading=14
            ),
            'Footer': ParagraphStyle(
                'Footer',
                parent=styles['Normal'],
                fontName=FONT_NORMAL,
                fontSize=9,
                textColor=colors.gray,
                alignment=TA_CENTER
            ),
            'TableHeader': ParagraphStyle(
                'TableHeader',
                parent=styles['Normal'],
                fontName=FONT_BOLD,
                fontSize=11,
                alignment=TA_CENTER
            ),
            'TableCell': ParagraphStyle(
                'TableCell',
                parent=styles['Normal'],
                fontName=FONT_NORMAL,
                fontSize=10
            )
        }

        for name, style in custom_styles.items():
            styles.add(style, name)

        return styles

    def _create_table_style(self, has_header: bool = False,
                           highlight_first_column: bool = False) -> TableStyle:
        """
        Create a consistent table style for the report.

        Args:
            has_header: Whether the table has a header row that should be styled differently
            highlight_first_column: Whether to highlight the first column with background color

        Returns:
            TableStyle object with consistent styling for tables in the report
        """
        style_commands = [
            # Basic grid and alignment
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]

        # Add header styling if needed
        if has_header:
            style_commands.extend([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ])

        # Add first column highlighting if needed
        if highlight_first_column:
            style_commands.extend([
                ('BACKGROUND', (0, 0 if not has_header else 1), (0, -1), colors.HexColor('#f5f9ff')),
                ('TEXTCOLOR', (0, 0 if not has_header else 1), (0, -1), colors.HexColor(COLORS["primary"])),
                ('FONTNAME', (0, 0 if not has_header else 1), (0, -1), FONT_BOLD),
                ('ALIGN', (0, 0 if not has_header else 1), (0, -1), 'LEFT'),
            ])

        return TableStyle(style_commands)

    def _get_device_info(self) -> Dict[str, str]:
        """
        Collect system information about the current device.

        Returns:
            Dictionary containing hostname, OS, processor, Python version, and system time
        """
        return {
            'hostname': socket.gethostname(),
            'os': f"{platform.system()} {platform.release()}",
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'system_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def _get_speed_rating(self, speed: float, is_download: bool = True) -> Tuple[str, str]:
        """
        Get a rating and color for a speed value.

        Args:
            speed: Speed value in Mbps
            is_download: True if this is a download speed, False for upload

        Returns:
            Tuple of (rating, color_hex) where rating is a descriptive string and
            color_hex is a hex color code for the rating
        """
        # Define thresholds and ratings based on whether it's download or upload
        thresholds = {
            'download': [
                (500, "Exceptional", COLORS["excellent"]),
                (250, "Excellent", COLORS["excellent"]),
                (100, "Very Good", COLORS["good"]),
                (50, "Good", COLORS["good"]),
                (25, "Adequate", COLORS["moderate"]),
                (10, "Fair", COLORS["fair"]),
                (0, "Poor", COLORS["poor"])
            ],
            'upload': [
                (200, "Exceptional", COLORS["excellent"]),
                (100, "Excellent", COLORS["excellent"]),
                (50, "Very Good", COLORS["good"]),
                (25, "Good", COLORS["good"]),
                (10, "Adequate", COLORS["moderate"]),
                (5, "Fair", COLORS["fair"]),
                (0, "Poor", COLORS["poor"])
            ]
        }

        # Select the appropriate thresholds
        speed_type = 'download' if is_download else 'upload'

        # Find the rating based on the speed
        for threshold, rating, color in thresholds[speed_type]:
            if speed >= threshold:
                return rating, color

        # This should never happen as the last threshold is 0
        return "Poor", COLORS["poor"]

    def _get_ping_rating(self, ping: float) -> Tuple[str, str]:
        """
        Get a rating and color for a ping value.

        Args:
            ping: Ping value in ms

        Returns:
            Tuple of (rating, color_hex) where rating is a descriptive string and
            color_hex is a hex color code for the rating
        """
        # Define thresholds for ping ratings (lower is better)
        thresholds = [
            (10, "Exceptional", COLORS["excellent"]),
            (20, "Excellent", COLORS["excellent"]),
            (40, "Very Good", COLORS["good"]),
            (60, "Good", COLORS["good"]),
            (100, "Adequate", COLORS["moderate"]),
            (150, "Fair", COLORS["fair"]),
            (float('inf'), "Poor", COLORS["poor"])
        ]

        # Find the rating based on the ping
        for threshold, rating, color in thresholds:
            if ping < threshold:
                return rating, color

        # This should never happen as the last threshold is infinity
        return "Poor", COLORS["poor"]

    def _get_recommendation(self, download_speed: float, upload_speed: float, ping: float) -> str:
        """
        Generate a recommendation based on speed test results.

        Args:
            download_speed: Download speed in Mbps
            upload_speed: Upload speed in Mbps
            ping: Ping in ms

        Returns:
            Recommendation string with personalized advice based on the measured speeds
        """
        # Define recommendation thresholds and messages
        recommendations = [
            {
                'condition': lambda d, u, p: d >= 100 and u >= 50 and p < 30,
                'message': (
                    "Your internet connection is excellent and suitable for all online activities, "
                    "including 4K streaming, large file transfers, video conferencing, and online gaming."
                )
            },
            {
                'condition': lambda d, u, p: d >= 50 and u >= 20 and p < 50,
                'message': (
                    "Your internet connection is good for most online activities, including HD streaming, "
                    "video calls, and casual gaming. Multiple devices can use the connection simultaneously."
                )
            },
            {
                'condition': lambda d, u, p: d >= 25 and u >= 10 and p < 100,
                'message': (
                    "Your internet connection is adequate for basic online activities like web browsing, "
                    "email, SD video streaming, and basic video calls. Multiple devices may experience "
                    "slowdowns during heavy usage."
                )
            },
            {
                'condition': lambda d, u, _: d >= 10 and u >= 3,
                'message': (
                    "Your internet connection is suitable for basic web browsing and email, but may "
                    "struggle with video streaming, video calls, or when multiple devices are connected. "
                    "Consider upgrading your plan if you regularly use these services."
                )
            }
        ]

        # Find the first matching recommendation
        for recommendation in recommendations:
            if recommendation['condition'](download_speed, upload_speed, ping):
                return recommendation['message']

        # Default recommendation for poor connections
        return (
            "Your internet connection is below recommended speeds for most online activities. "
            "You may experience difficulties with web browsing, streaming, and other online services. "
            "Consider contacting your ISP to troubleshoot or upgrade your connection."
        )

    def generate_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate a PDF report with speed test results.

        Creates a comprehensive PDF report containing speed test results, visualizations,
        ratings, and recommendations. If multiple test results are provided, includes
        historical analysis and comparisons.

        Args:
            output_path: Path where the PDF should be saved. If None, a default path is used
                         in the 'reports' directory with a timestamp-based filename.

        Returns:
            Path to the generated PDF file as a string
        """
        if not output_path:
            # Create reports directory if it doesn't exist
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            # Generate filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"speed_test_report_{timestamp}.pdf"
            output_path = reports_dir / filename

        # Create the PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
            title="Internet Speed Test Report",
            author="Wi-Fi Threat Assessor",
            subject="Network Speed Analysis"
        )

        # Create the story (content) for the PDF
        story = []

        # Add title page
        self._add_title_page(story)

        # Add historical charts if multiple tests are included
        if len(self.speed_tests) > 1:
            self._add_historical_charts(story)
            story.append(PageBreak())

        # Add individual speed test results
        for i, test_data in enumerate(self.speed_tests):
            if i > 0:
                story.append(PageBreak())
            self._add_speed_test_results(story, test_data)

        # Build the PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)

        return str(output_path)

    def _add_historical_charts(self, story: List) -> None:
        """
        Add historical charts comparing multiple speed tests to the report.

        Creates and adds line charts for download speed, upload speed, and ping
        history if multiple test results are available. Each chart shows trends
        over time to help identify patterns in network performance.

        Args:
            story: ReportLab story list to append content to
        """
        # Add section title
        section_title = Paragraph("Historical Speed Test Analysis", self.styles['SectionTitle'])
        story.append(section_title)

        # Add explanatory text
        intro_text = Paragraph(
            f"This section shows trends across {len(self.speed_tests)} speed tests. "
            f"These visualizations help identify patterns and changes in your network performance over time.",
            self.styles['NormalText']
        )
        story.append(intro_text)
        story.append(Spacer(1, 0.3*inch))

        # Chart metrics to generate
        chart_metrics = [
            {
                'metric': 'download_speed',
                'title': "Download Speed History",
                'description': "Shows how your download speeds have changed over time."
            },
            {
                'metric': 'upload_speed',
                'title': "Upload Speed History",
                'description': "Shows how your upload speeds have changed over time."
            },
            {
                'metric': 'ping',
                'title': "Ping History",
                'description': "Shows how your connection latency has changed over time."
            }
        ]

        # Generate and add each chart
        for chart_info in chart_metrics:
            chart = SpeedTestChartGenerator.generate_historical_chart(
                self.speed_tests, chart_info['metric']
            )

            if chart:
                # Add chart title
                title = Paragraph(chart_info['title'], self.styles['SubsectionTitle'])
                story.append(title)

                # Add chart description
                description = Paragraph(chart_info['description'], self.styles['NormalText'])
                story.append(description)

                # Add the chart image
                story.append(Image(chart, width=6*inch, height=3.5*inch))
                story.append(Spacer(1, 0.2*inch))

        # Add note about interpreting the charts
        story.append(Spacer(1, 0.3*inch))
        note_text = Paragraph(
            "Note: Higher values are better for download and upload speeds, while lower values are better for ping. "
            "Consistent speeds indicate a stable network connection, while significant variations may suggest "
            "network congestion or interference issues.",
            self.styles['ItalicText']
        )
        story.append(note_text)

    def _add_header_footer(self, canvas, doc) -> None:
        """
        Add header and footer to each page of the PDF report.

        This callback function is called by ReportLab during PDF generation
        for each page. It adds a consistent footer with page number and
        generation information.

        Args:
            canvas: ReportLab canvas object for drawing
            doc: ReportLab document object with page information
        """
        canvas.saveState()

        # Add footer with page number
        current_date = datetime.datetime.now().strftime('%Y-%m-%d')
        footer_text = f"Generated by Wi-Fi Threat Assessor on {current_date} | Page {doc.page}"

        canvas.setFont(FONT_NORMAL, 8)
        canvas.setFillColor(colors.gray)
        canvas.drawCentredString(letter[0]/2, 0.5*inch, footer_text)

        canvas.restoreState()

    def _add_title_page(self, story: List) -> None:
        """
        Add the title page to the report with summary information.

        Creates the report title, subtitle, test summary, and device information
        sections for the first page of the report. The content varies based on
        whether the report contains single or multiple test results.

        Args:
            story: ReportLab story list to append content to
        """
        # Add title
        title = Paragraph("Internet Speed Test Report", self.styles['ReportTitle'])
        story.append(title)

        # Add subtitle with date
        current_date = datetime.datetime.now().strftime('%B %d, %Y')
        subtitle = Paragraph(f"Generated on {current_date}", self.styles['ReportSubtitle'])
        story.append(subtitle)

        story.append(Spacer(1, 0.5*inch))

        # Add summary information based on number of tests
        self._add_summary_text(story)

        story.append(Spacer(1, 0.5*inch))

        # Add device information
        device_title = Paragraph("Device Information", self.styles['SectionTitle'])
        story.append(device_title)

        # Create device information table
        device_data = [
            ["Hostname", self.device_info.get('hostname', 'Unknown')],
            ["Operating System", self.device_info.get('os', 'Unknown')],
            ["Processor", self.device_info.get('processor', 'Unknown')],
            ["System Time", self.device_info.get('system_time', 'Unknown')]
        ]

        # Use the helper method to create a consistent table style
        device_table = Table(
            device_data,
            colWidths=[1.5*inch, 4.5*inch],
            style=self._create_table_style(highlight_first_column=True)
        )
        story.append(device_table)

        # Add note about speed test
        story.append(Spacer(1, 0.5*inch))
        note_text = Paragraph(
            "Note: Internet speeds can vary based on network conditions, server load, and other factors. "
            "For the most accurate assessment, perform multiple tests at different times of day.",
            self.styles['ItalicText']
        )
        story.append(note_text)

    def _add_summary_text(self, story: List) -> None:
        """
        Add summary text to the report based on the number of tests.

        Args:
            story: ReportLab story list to append content to
        """
        if len(self.speed_tests) > 1:
            summary_text = Paragraph(
                f"This report contains results from {len(self.speed_tests)} speed tests.",
                self.styles['NormalText']
            )
            story.append(summary_text)
        else:
            # Get the single test data
            test_data = self.speed_tests[0]

            # Format timestamp
            formatted_time = self._format_timestamp(test_data.get('timestamp', 'Unknown'))

            summary_text = Paragraph(
                f"This report contains the results of a speed test performed on {formatted_time} "
                f"for the network '{test_data.get('ssid', 'Unknown')}'.",
                self.styles['NormalText']
            )
            story.append(summary_text)

    def _format_timestamp(self, timestamp: str) -> str:
        """
        Format a timestamp string into a human-readable format.

        Args:
            timestamp: Timestamp string in format "%Y-%m-%d %H:%M:%S"

        Returns:
            Formatted timestamp string (e.g., "January 1, 2023 at 3:30 PM")
        """
        try:
            timestamp_obj = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            return timestamp_obj.strftime("%B %d, %Y at %I:%M %p")
        except (ValueError, TypeError):
            return timestamp

    def _add_speed_test_results(self, story: List, test_data: Dict) -> None:
        """
        Add detailed speed test results for a single test to the report.

        Creates sections for network information, speed measurements, visualizations,
        recommendations, and usage guidance based on the test results.

        Args:
            story: ReportLab story list to append content to
            test_data: Dictionary containing the speed test results
        """
        # Add section title
        self._add_test_section_title(story, test_data)

        # Add network information section
        self._add_network_information(story, test_data)

        # Add speed measurements section
        self._add_speed_measurements(story, test_data)

        # Add speed visualizations
        self._add_speed_visualizations(story, test_data)

        # Add recommendation
        self._add_recommendation_section(story, test_data)

        # Add usage guidance
        self._add_usage_guidance(story, test_data)

        # Add server information if available
        self._add_server_information(story, test_data)

    def _add_test_section_title(self, story: List, test_data: Dict) -> None:
        """
        Add the section title for a speed test result.

        Args:
            story: ReportLab story list to append content to
            test_data: Dictionary containing the speed test results
        """
        if len(self.speed_tests) > 1:
            # Format timestamp for section title
            formatted_time = self._format_timestamp(test_data.get('timestamp', 'Unknown'))
            section_title = Paragraph(
                f"Speed Test Results - {formatted_time}",
                self.styles['SectionTitle']
            )
        else:
            section_title = Paragraph("Speed Test Results", self.styles['SectionTitle'])

        story.append(section_title)

    def _add_network_information(self, story: List, test_data: Dict) -> None:
        """
        Add network information section to the report.

        Args:
            story: ReportLab story list to append content to
            test_data: Dictionary containing the speed test results
        """
        network_title = Paragraph("Network Information", self.styles['SubsectionTitle'])
        story.append(network_title)

        network_data = [
            ["Network Name (SSID)", test_data.get('ssid', 'Unknown')],
            ["Security Type", test_data.get('security_type', 'Unknown')],
            ["BSSID", test_data.get('bssid', 'Unknown')],
            ["IP Address", test_data.get('ip_address', 'Unknown')],
            ["Channel", test_data.get('channel', 'Unknown')],
            ["Band", test_data.get('band', 'Unknown')]
        ]

        network_table = Table(
            network_data,
            colWidths=[1.5*inch, 4.5*inch],
            style=self._create_table_style(highlight_first_column=True)
        )

        story.append(network_table)
        story.append(Spacer(1, 0.3*inch))

    def _add_speed_measurements(self, story: List, test_data: Dict) -> None:
        """
        Add speed measurements section to the report.

        Args:
            story: ReportLab story list to append content to
            test_data: Dictionary containing the speed test results
        """
        results_title = Paragraph("Speed Measurements", self.styles['SubsectionTitle'])
        story.append(results_title)

        # Get speed values
        download_speed = float(test_data.get('download_speed', 0))
        upload_speed = float(test_data.get('upload_speed', 0))
        ping = float(test_data.get('ping', 0))

        # Get ratings
        download_rating, download_color = self._get_speed_rating(download_speed, True)
        upload_rating, upload_color = self._get_speed_rating(upload_speed, False)
        ping_rating, ping_color = self._get_ping_rating(ping)

        # Create results table
        results_data = [
            ["Metric", "Value", "Rating"],
            ["Download Speed", f"{download_speed:.2f} Mbps", download_rating],
            ["Upload Speed", f"{upload_speed:.2f} Mbps", upload_rating],
            ["Ping", f"{ping:.1f} ms", ping_rating]
        ]

        # Create table style with custom rating colors
        base_style = self._create_table_style(has_header=True)
        rating_colors = TableStyle([
            ('TEXTCOLOR', (2, 1), (2, 1), colors.HexColor(download_color)),
            ('TEXTCOLOR', (2, 2), (2, 2), colors.HexColor(upload_color)),
            ('TEXTCOLOR', (2, 3), (2, 3), colors.HexColor(ping_color)),
            ('ALIGN', (1, 1), (2, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (0, -1), FONT_BOLD),
        ])

        # Combine the styles
        combined_style = TableStyle(base_style._cmds + rating_colors._cmds)

        results_table = Table(
            results_data,
            colWidths=[2*inch, 2*inch, 2*inch],
            style=combined_style
        )

        story.append(results_table)
        story.append(Spacer(1, 0.3*inch))

    def _add_speed_visualizations(self, story: List, test_data: Dict) -> None:
        """
        Add speed visualization charts to the report.

        Args:
            story: ReportLab story list to append content to
            test_data: Dictionary containing the speed test results
        """
        chart_title = Paragraph("Speed Visualization", self.styles['SubsectionTitle'])
        story.append(chart_title)

        # Generate and add the speed comparison chart
        speed_chart = SpeedTestChartGenerator.generate_speed_comparison_chart(test_data)
        story.append(Image(speed_chart, width=5*inch, height=3.33*inch))

        # Generate and add the ping gauge chart
        ping_chart = SpeedTestChartGenerator.generate_ping_gauge_chart(test_data)
        story.append(Image(ping_chart, width=5*inch, height=2.5*inch))

        story.append(Spacer(1, 0.2*inch))

    def _add_recommendation_section(self, story: List, test_data: Dict) -> None:
        """
        Add recommendation section to the report.

        Args:
            story: ReportLab story list to append content to
            test_data: Dictionary containing the speed test results
        """
        recommendation_title = Paragraph("Recommendation", self.styles['SubsectionTitle'])
        story.append(recommendation_title)

        download_speed = float(test_data.get('download_speed', 0))
        upload_speed = float(test_data.get('upload_speed', 0))
        ping = float(test_data.get('ping', 0))

        recommendation = self._get_recommendation(download_speed, upload_speed, ping)
        recommendation_text = Paragraph(recommendation, self.styles['NormalText'])
        story.append(recommendation_text)

    def _add_usage_guidance(self, story: List, test_data: Dict) -> None:
        """
        Add usage guidance section to the report.

        Args:
            story: ReportLab story list to append content to
            test_data: Dictionary containing the speed test results
        """
        story.append(Spacer(1, 0.3*inch))
        guidance_title = Paragraph("Usage Guidance", self.styles['SubsectionTitle'])
        story.append(guidance_title)

        download_speed = float(test_data.get('download_speed', 0))

        # Create guidance based on speeds
        guidance = self._get_usage_guidance(download_speed)

        # Add guidance as bullet points
        for item in guidance:
            bullet_text = Paragraph(item, self.styles['NormalText'])
            story.append(bullet_text)

    def _get_usage_guidance(self, download_speed: float) -> List[str]:
        """
        Get usage guidance based on download speed.

        Args:
            download_speed: Download speed in Mbps

        Returns:
            List of guidance strings
        """
        if download_speed >= 100:
            return [
                "✓ 4K video streaming on multiple devices",
                "✓ Large file downloads and uploads",
                "✓ Video conferencing with high-quality video",
                "✓ Online gaming with minimal latency",
                "✓ Smart home devices and IoT applications",
                "✓ Cloud backup and synchronization"
            ]
        elif download_speed >= 50:
            return [
                "✓ HD video streaming on multiple devices",
                "✓ Video conferencing with good quality",
                "✓ Online gaming with acceptable latency",
                "✓ Medium to large file downloads",
                "✓ Smart home devices and IoT applications",
                "✓ Cloud backup and synchronization"
            ]
        elif download_speed >= 25:
            return [
                "✓ HD video streaming on a single device",
                "✓ Standard video conferencing",
                "✓ Web browsing and email",
                "✓ Social media usage",
                "✓ Basic smart home functionality",
                "✗ May struggle with 4K streaming or multiple HD streams"
            ]
        else:
            return [
                "✓ Basic web browsing and email",
                "✓ Standard definition video streaming",
                "✓ Basic social media usage",
                "✗ May struggle with HD video streaming",
                "✗ Not recommended for video conferencing",
                "✗ Not suitable for online gaming or large file transfers"
            ]

    def _add_server_information(self, story: List, test_data: Dict) -> None:
        """
        Add server information to the report if available.

        Args:
            story: ReportLab story list to append content to
            test_data: Dictionary containing the speed test results
        """
        if 'server' in test_data and test_data['server'] != 'Unknown':
            story.append(Spacer(1, 0.3*inch))
            server_info = Paragraph(
                f"Test Server: {test_data.get('server', 'Unknown')}",
                self.styles['ItalicText']
            )
            story.append(server_info)
