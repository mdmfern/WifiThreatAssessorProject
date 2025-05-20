"""
Professional-grade PDF Report Generator for the Wi-Fi Threat Assessor application.
This module generates comprehensive security audit reports using ReportLab.
Enhanced with improved layout, styling, and visual elements for better readability.
"""

import os
import datetime
import socket
import uuid
import platform
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, ListFlowable, Image, Flowable, HRFlowable,
    ListItem, KeepTogether, NextPageTemplate
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus.doctemplate import BaseDocTemplate, PageTemplate, Frame
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus.doctemplate import BaseDocTemplate, PageTemplate, Frame

# Constants
FONT_NORMAL = 'Helvetica'
FONT_BOLD = 'Helvetica-Bold'
FONT_ITALIC = 'Helvetica-Oblique'
FONT_BOLD_ITALIC = 'Helvetica-BoldOblique'

# Color definitions
COLORS = {
    # Primary colors
    "primary": "#1f538d",
    "primary_light": "#3498db",
    "primary_dark": "#0c2d5c",
    "secondary": "#2ecc71",
    "text_primary": "#333333",
    "text_secondary": "#666666",
    "background": "#ffffff",
    "accent": "#e8f0f8",
    "border": "#d5e1ee",
    "cover_bg": "#f5f9ff",

    # Risk colors
    "critical": "#e74c3c",
    "high": "#e67e22",
    "moderate": "#f1c40f",
    "low": "#2ecc71",
    "info": "#3498db",

    # Security rating colors
    "score_very_secure": "#2ecc71",
    "score_secure": "#27ae60",
    "score_moderate": "#f1c40f",
    "score_low": "#e67e22",
    "score_insecure": "#e74c3c",

    # Signal strength colors
    "signal_excellent": "#2ecc71",
    "signal_good": "#27ae60",
    "signal_fair": "#f1c40f",
    "signal_poor": "#e67e22",
    "signal_weak": "#e74c3c",
}


class WifiSecurityReportDocument(BaseDocTemplate):
    """Custom document template with table of contents support and enhanced page styling."""

    def __init__(self, filename, **kwargs):
        self.allowSplitting = 0
        BaseDocTemplate.__init__(self, filename, **kwargs)

        # Store the report ID and other metadata for use in headers/footers
        self.report_id = kwargs.get('report_id', '')
        self.scan_date = kwargs.get('scan_date', datetime.datetime.now().strftime("%Y-%m-%d"))
        self.scan_time = kwargs.get('scan_time', datetime.datetime.now().strftime("%H:%M:%S"))

        # Store section titles and their bookmark names for TOC
        self.bookmarks = {
            "executive_summary": "1. Executive Summary",
            "device_info": "2. Device & Environment Information",
            "network_scan_results": "3. Network Scan Results",
            "security_distribution": "4. Security Type Distribution",
            "threat_detection": "5. Threat Detection Summary",
            "risk_score_breakdown": "6. Risk Score Breakdown",
            "security_recommendations": "7. Security Recommendations",
            "appendix": "8. Appendix"
        }

        # Track current section for bookmarking
        self.current_section = None

        # Create page templates
        self.page_width, self.page_height = letter

        # Frame for cover page (no header/footer)
        cover_frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            self.page_width - self.leftMargin - self.rightMargin,
            self.page_height - self.topMargin - self.bottomMargin,
            id='cover_frame'
        )

        # Frame for content pages (with header/footer)
        content_frame = Frame(
            self.leftMargin,
            self.bottomMargin + 0.6*inch,  # Make room for footer
            self.page_width - self.leftMargin - self.rightMargin,
            self.page_height - self.topMargin - self.bottomMargin - 0.8*inch,  # Make room for header
            id='content_frame'
        )

        # Create page templates
        self.addPageTemplates([
            PageTemplate(id='Cover', frames=cover_frame, onPage=self._draw_cover_page),
            PageTemplate(id='Content', frames=content_frame, onPage=self._draw_content_page, onPageEnd=self._on_page_end)
        ])

        # Initialize table of contents with improved styling
        self.toc = TableOfContents()
        self.toc.levelStyles = [
            ParagraphStyle(
                name='TOC1',
                fontSize=14,
                fontName=FONT_BOLD,
                leftIndent=0,
                firstLineIndent=0,
                spaceBefore=12,
                spaceAfter=6,
                textColor=colors.HexColor(COLORS["primary"])
            ),
            ParagraphStyle(
                name='TOC2',
                fontSize=12,
                fontName=FONT_NORMAL,
                leftIndent=20,
                firstLineIndent=0,
                spaceBefore=6,
                spaceAfter=4,
                textColor=colors.HexColor(COLORS["primary_light"])
            ),
            ParagraphStyle(
                name='TOC3',
                fontSize=10,
                fontName=FONT_NORMAL,
                leftIndent=40,
                firstLineIndent=0,
                spaceBefore=4,
                spaceAfter=2,
                textColor=colors.HexColor(COLORS["text_primary"])
            ),
        ]

    def _on_page_end(self, canvas, doc):
        """Handle bookmarking and outline entries at the end of each page."""
        if hasattr(doc, 'current_section') and doc.current_section:
            # Create bookmark for the current section
            bookmark_name = doc.current_section
            if bookmark_name in doc.bookmarks:
                # Add bookmark and outline entry
                canvas.bookmarkPage(bookmark_name)
                canvas.addOutlineEntry(doc.bookmarks[bookmark_name], bookmark_name, 0)

                # Reset current section to avoid duplicate bookmarks
                doc.current_section = None

    def _draw_cover_page(self, canvas, doc):
        """Draw elements for the cover page including a subtle background."""
        # Draw a subtle background color for the cover page
        canvas.setFillColor(colors.HexColor(COLORS["cover_bg"]))
        canvas.rect(0, 0, self.page_width, self.page_height, fill=1, stroke=0)

        # Add a decorative header bar
        canvas.setFillColor(colors.HexColor(COLORS["primary"]))
        canvas.rect(0, self.page_height - 1.5*inch, self.page_width, 1.5*inch, fill=1, stroke=0)

        # Add a decorative footer bar
        canvas.setFillColor(colors.HexColor(COLORS["primary_light"]))
        canvas.rect(0, 0, self.page_width, 0.5*inch, fill=1, stroke=0)

    def _draw_content_page(self, canvas, doc):
        """Draw enhanced header and footer for content pages."""
        canvas.saveState()

        # Draw header with improved styling
        if doc.page > 2:  # Skip TOC page
            # Header background
            canvas.setFillColor(colors.HexColor(COLORS["accent"]))
            canvas.rect(
                doc.leftMargin - 0.1*inch,
                self.page_height - doc.topMargin - 0.1*inch,
                self.page_width - doc.leftMargin - doc.rightMargin + 0.2*inch,
                0.4*inch,
                fill=1,
                stroke=0
            )

            # Header border
            canvas.setStrokeColor(colors.HexColor(COLORS["primary"]))
            canvas.setLineWidth(1)
            canvas.line(
                doc.leftMargin - 0.1*inch,
                self.page_height - doc.topMargin - 0.1*inch,
                self.page_width - doc.rightMargin + 0.1*inch,
                self.page_height - doc.topMargin - 0.1*inch
            )

            # Header text
            canvas.setFont(FONT_BOLD, 10)
            canvas.setFillColor(colors.HexColor(COLORS["primary"]))
            canvas.drawString(
                doc.leftMargin,
                self.page_height - doc.topMargin + 0.05*inch,
                "WiFi Security Audit Report"
            )

            # Add section title if available
            if hasattr(doc, 'section_title') and doc.section_title:
                section_width = canvas.stringWidth(doc.section_title, FONT_NORMAL, 9)
                canvas.setFont(FONT_NORMAL, 9)
                canvas.drawString(
                    (self.page_width - section_width) / 2,
                    self.page_height - doc.topMargin + 0.05*inch,
                    doc.section_title
                )

            # Add date on the right
            date_text = f"Scan Date: {self.scan_date}"
            date_width = canvas.stringWidth(date_text, FONT_NORMAL, 9)
            canvas.setFont(FONT_NORMAL, 9)
            canvas.drawString(
                self.page_width - doc.rightMargin - date_width,
                self.page_height - doc.topMargin + 0.05*inch,
                date_text
            )

        # Draw enhanced footer
        # Footer background
        canvas.setFillColor(colors.HexColor(COLORS["accent"]))
        canvas.rect(
            doc.leftMargin - 0.1*inch,
            doc.bottomMargin - 0.3*inch,
            self.page_width - doc.leftMargin - doc.rightMargin + 0.2*inch,
            0.4*inch,
            fill=1,
            stroke=0
        )

        # Footer border
        canvas.setStrokeColor(colors.HexColor(COLORS["primary"]))
        canvas.setLineWidth(1)
        canvas.line(
            doc.leftMargin - 0.1*inch,
            doc.bottomMargin + 0.1*inch,
            self.page_width - doc.rightMargin + 0.1*inch,
            doc.bottomMargin + 0.1*inch
        )

        # Footer text
        canvas.setFont(FONT_NORMAL, 9)
        canvas.setFillColor(colors.HexColor(COLORS["text_secondary"]))

        # Page number on the left
        page_text = f"Page {doc.page} of {canvas._pageNumber}"
        canvas.drawString(
            doc.leftMargin,
            doc.bottomMargin - 0.15*inch,
            page_text
        )

        # Report generation time in the center
        time_text = f"Generated: {self.scan_date} {self.scan_time}"
        time_width = canvas.stringWidth(time_text, FONT_NORMAL, 9)
        canvas.drawString(
            (self.page_width - time_width) / 2,
            doc.bottomMargin - 0.15*inch,
            time_text
        )

        # Report ID on the right
        report_id_text = f"Report ID: {self.report_id}"
        report_id_width = canvas.stringWidth(report_id_text, FONT_NORMAL, 9)
        canvas.drawString(
            self.page_width - doc.rightMargin - report_id_width,
            doc.bottomMargin - 0.15*inch,
            report_id_text
        )

        canvas.restoreState()


class SecurityReportGenerator:
    """Main class for generating comprehensive WiFi security audit reports."""

    def __init__(self, audit_data: Dict, networks: List[Dict], scan_duration: Optional[float] = None):
        """
        Initialize the report generator with audit data and network information.

        Args:
            audit_data: Dictionary containing security audit results
            networks: List of dictionaries containing network information
            scan_duration: Optional duration of the network scan in seconds
        """
        self.audit_data = audit_data
        self.networks = networks
        self.scan_duration = scan_duration
        self.styles = self._create_styles()
        self.device_info = self._get_device_info()
        self.report_id = self._generate_report_id()

    def _create_styles(self) -> Dict:
        """Create styles for the PDF report."""
        styles = getSampleStyleSheet()

        # Create a copy of the styles to avoid modifying the original
        custom_styles = {}

        # Define custom styles
        custom_styles['Title'] = ParagraphStyle(
            'Title',
            parent=styles['Title'],
            fontName=FONT_BOLD,
            fontSize=30,
            leading=36,
            alignment=TA_CENTER,
            textColor=colors.HexColor(COLORS["primary"]),
            spaceAfter=24
        )

        custom_styles['Subtitle'] = ParagraphStyle(
            'Subtitle',
            parent=styles['Heading2'],
            fontName=FONT_NORMAL,
            fontSize=18,
            leading=22,
            alignment=TA_CENTER,
            textColor=colors.HexColor(COLORS["primary_light"]),
            spaceAfter=36
        )

        custom_styles['Heading1'] = ParagraphStyle(
            'Heading1',
            parent=styles['Heading1'],
            fontName=FONT_BOLD,
            fontSize=18,
            leading=22,
            textColor=colors.HexColor(COLORS["primary"]),
            spaceBefore=12,
            spaceAfter=6
        )

        custom_styles['Heading2'] = ParagraphStyle(
            'Heading2',
            parent=styles['Heading2'],
            fontName=FONT_BOLD,
            fontSize=16,
            leading=20,
            textColor=colors.HexColor(COLORS["primary_light"]),
            spaceBefore=10,
            spaceAfter=6
        )

        custom_styles['Heading3'] = ParagraphStyle(
            'Heading3',
            parent=styles['Heading3'],
            fontName=FONT_BOLD,
            fontSize=14,
            leading=18,
            textColor=colors.HexColor(COLORS["text_primary"]),
            spaceBefore=8,
            spaceAfter=4
        )

        custom_styles['Normal'] = ParagraphStyle(
            'Normal',
            parent=styles['Normal'],
            fontName=FONT_NORMAL,
            fontSize=12,
            leading=16,
            textColor=colors.HexColor(COLORS["text_primary"])
        )

        custom_styles['BodyText'] = ParagraphStyle(
            'BodyText',
            parent=styles['Normal'],
            fontName=FONT_NORMAL,
            fontSize=12,
            leading=16,
            spaceBefore=6,
            spaceAfter=6
        )

        custom_styles['TableHeader'] = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName=FONT_BOLD,
            fontSize=12,
            textColor=colors.white,
            alignment=TA_LEFT
        )

        custom_styles['TableCell'] = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName=FONT_NORMAL,
            fontSize=11,
            alignment=TA_LEFT
        )

        custom_styles['Critical'] = ParagraphStyle(
            'Critical',
            parent=styles['Normal'],
            fontName=FONT_BOLD,
            fontSize=12,
            textColor=colors.HexColor(COLORS["critical"])
        )

        custom_styles['High'] = ParagraphStyle(
            'High',
            parent=styles['Normal'],
            fontName=FONT_BOLD,
            fontSize=12,
            textColor=colors.HexColor(COLORS["high"])
        )

        custom_styles['Moderate'] = ParagraphStyle(
            'Moderate',
            parent=styles['Normal'],
            fontName=FONT_BOLD,
            fontSize=12,
            textColor=colors.HexColor(COLORS["moderate"])
        )

        custom_styles['Low'] = ParagraphStyle(
            'Low',
            parent=styles['Normal'],
            fontName=FONT_NORMAL,
            fontSize=12,
            textColor=colors.HexColor(COLORS["low"])
        )

        custom_styles['Info'] = ParagraphStyle(
            'Info',
            parent=styles['Normal'],
            fontName=FONT_ITALIC,
            fontSize=12,
            textColor=colors.HexColor(COLORS["info"])
        )

        custom_styles['Footer'] = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontName=FONT_NORMAL,
            fontSize=9,
            textColor=colors.gray
        )

        custom_styles['Caption'] = ParagraphStyle(
            'Caption',
            parent=styles['Normal'],
            fontName=FONT_ITALIC,
            fontSize=10,
            textColor=colors.HexColor(COLORS["text_secondary"]),
            alignment=TA_CENTER,
            spaceBefore=4,
            spaceAfter=12
        )

        # Create a dictionary to hold all styles
        all_styles = {}

        # Add default styles
        for name, style in styles.byName.items():
            all_styles[name] = style

        # Override with custom styles
        for name, style in custom_styles.items():
            all_styles[name] = style

        return all_styles

    def _get_device_info(self) -> Dict:
        """Get information about the device running the application."""
        device_info = {
            'hostname': socket.gethostname(),
            'os': platform.system() + ' ' + platform.release(),
            'mac_address': self._get_mac_address(),
            'ip_address': self._get_ip_address(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'system_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        return device_info

    def _get_mac_address(self) -> str:
        """Get the MAC address of the device."""
        try:
            mac = uuid.getnode()
            return ':'.join(['{:02x}'.format((mac >> elements) & 0xff) for elements in range(0, 8*6, 8)][::-1])
        except Exception:
            return "Unknown"

    def _get_ip_address(self) -> str:
        """Get the IP address of the device."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "Unknown"

    def _generate_report_id(self) -> str:
        """Generate a unique report ID."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        hostname = socket.gethostname()
        random_component = uuid.uuid4().hex[:8]

        hash_input = f"{timestamp}_{hostname}_{random_component}"
        report_id = hashlib.sha256(hash_input.encode()).hexdigest()[:16].upper()

        return report_id

    def generate_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate the PDF report.

        Args:
            output_path: Path where the PDF should be saved. If None, a default path is used.

        Returns:
            Path to the generated PDF file
        """
        if not output_path:
            # Create reports directory if it doesn't exist
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            # Generate filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wifi_security_report_{timestamp}.pdf"
            output_path = reports_dir / filename

        # Create buffer for PDF
        buffer = io.BytesIO()

        # Create the document
        doc = WifiSecurityReportDocument(
            buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
            title="WiFi Security Audit Report",
            author="WiFi Threat Assessor",
            subject="Network Security Analysis",
            creator="WiFi Threat Assessor",
            report_id=self.report_id
        )

        # Create the story (content) for the PDF
        story = []

        # Add cover page (using Cover template)
        story.append(NextPageTemplate('Cover'))
        self._add_cover_page(story)

        # Switch to Content template for the rest of the document
        story.append(NextPageTemplate('Content'))
        story.append(PageBreak())

        # Add table of contents
        self._add_table_of_contents(story, doc)

        # Add content sections with document for bookmarking
        self._add_executive_summary(story, doc)
        self._add_device_info(story, doc)
        self._add_network_scan_results(story, doc)
        self._add_security_distribution(story, doc)
        self._add_threat_detection(story, doc)
        self._add_risk_score_breakdown(story, doc)
        self._add_security_recommendations(story, doc)
        self._add_appendix(story, doc)

        # Build the PDF
        try:
            doc.multiBuild(story)
        except Exception as e:
            raise Exception(f"Error building PDF document: {str(e)}") from e

        # Save the PDF to the output path
        with open(output_path, 'wb') as f:
            f.write(buffer.getvalue())

        return str(output_path)

    def _add_cover_page(self, story: List) -> None:
        """Add the cover page to the report with enhanced visual elements."""
        # Add spacer at the top (for the colored header bar)
        story.append(Spacer(1, 1.5*inch))

        # Add title with enhanced styling
        title = Paragraph("WiFi Security Audit Report", self.styles['Title'])
        story.append(title)

        # Add subtitle
        subtitle = Paragraph("Generated by WiFi Threat Assessor", self.styles['Subtitle'])
        story.append(subtitle)

        # Add timestamp with improved formatting
        timestamp = datetime.datetime.now().strftime("%B %d, %Y – %H:%M:%S")
        date_style = ParagraphStyle(
            'DateStyle',
            parent=self.styles['Normal'],
            alignment=TA_CENTER,
            spaceBefore=6,
            spaceAfter=6
        )
        date_text = Paragraph(timestamp, date_style)
        story.append(date_text)

        # Add report ID with improved styling
        report_id_style = ParagraphStyle(
            'ReportIDStyle',
            parent=self.styles['Normal'],
            alignment=TA_CENTER,
            spaceBefore=0,
            spaceAfter=24
        )
        report_id_text = Paragraph(f"Report ID: {self.report_id}", report_id_style)
        story.append(report_id_text)

        # Add horizontal line
        story.append(HRFlowable(
            width="80%",
            thickness=1,
            color=colors.HexColor(COLORS["primary_light"]),
            spaceBefore=0,
            spaceAfter=24,
            hAlign='CENTER'
        ))

        # Add risk score visualization if available
        risk_score = self.audit_data.get('overall_risk_score', 0)
        if risk_score == 0 and 'risk_assessment' in self.audit_data:
            risk_score = self.audit_data['risk_assessment'].get('overall_risk_score', 0)

        if isinstance(risk_score, (int, float)):
            risk_score = round(float(risk_score), 1)

            # Create a container for risk score information to keep it together
            risk_elements = []

            # Create a table for the risk score box
            # Determine risk level based on score - align with security_audit.py logic
            if risk_score >= 80:
                risk_level = "Secure"
                risk_color = COLORS["score_very_secure"]
            elif risk_score >= 60:
                risk_level = "Moderately Secure"
                risk_color = COLORS["score_secure"]
            elif risk_score >= 40:
                risk_level = "Moderate Risk"
                risk_color = COLORS["score_moderate"]
            elif risk_score >= 20:
                risk_level = "High Risk"
                risk_color = COLORS["score_low"]
            else:
                risk_level = "Critical Risk"
                risk_color = COLORS["critical"]

            # Create a visual score box
            score_data = [
                ["Overall Security Score"],
                [f"{risk_score}/100"],
                [risk_level]
            ]

            score_table = Table(
                score_data,
                colWidths=[3*inch],
                rowHeights=[0.4*inch, 0.8*inch, 0.4*inch]
            )

            # Style the score table
            score_table.setStyle(TableStyle([
                # Border and background
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(risk_color)),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(risk_color)),
                ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor(COLORS["accent"])),

                # Text styling
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor(risk_color)),
                ('TEXTCOLOR', (0, 2), (-1, 2), colors.HexColor(COLORS["text_primary"])),

                # Alignment
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),

                # Font styling
                ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
                ('FONTNAME', (0, 1), (-1, 1), FONT_BOLD),
                ('FONTNAME', (0, 2), (-1, 2), FONT_BOLD),

                # Font sizes
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('FONTSIZE', (0, 1), (-1, 1), 36),
                ('FONTSIZE', (0, 2), (-1, 2), 14),
            ]))

            risk_elements.append(score_table)

            # Add a brief explanation of the score
            score_explanation = f"""
            <para alignment="center" spaceBefore="12" spaceAfter="12">
            This score represents the overall security assessment of your WiFi environment.
            </para>
            """
            risk_elements.append(Paragraph(score_explanation, self.styles['Caption']))

            # Create a visual indicator for the score (simple bar)
            bar_width = 5*inch
            bar_data = [[" ", " ", " ", " ", " "]]
            bar_table = Table(bar_data, colWidths=[bar_width/5]*5, rowHeights=[0.2*inch])

            # Style the bar with fixed segments
            bar_table.setStyle(TableStyle([
                # Background gradient (5 segments)
                ('BACKGROUND', (0, 0), (0, 0), colors.HexColor(COLORS["score_insecure"])),
                ('BACKGROUND', (1, 0), (1, 0), colors.HexColor(COLORS["score_low"])),
                ('BACKGROUND', (2, 0), (2, 0), colors.HexColor(COLORS["score_moderate"])),
                ('BACKGROUND', (3, 0), (3, 0), colors.HexColor(COLORS["score_secure"])),
                ('BACKGROUND', (4, 0), (4, 0), colors.HexColor(COLORS["score_very_secure"])),

                # Border
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(COLORS["text_secondary"])),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ]))

            risk_elements.append(bar_table)

            # Add scale labels
            scale_data = [["0", "20", "40", "60", "80", "100"]]
            scale_table = Table(scale_data, colWidths=[bar_width/5]*5 + [bar_width/10], rowHeights=[0.2*inch])
            scale_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), FONT_NORMAL),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor(COLORS["text_secondary"])),
            ]))

            risk_elements.append(scale_table)

            # Add scale labels
            label_data = [["Critical", "High Risk", "Moderate", "Secure", "Very Secure"]]
            label_table = Table(label_data, colWidths=[bar_width/5]*5, rowHeights=[0.2*inch])
            label_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), FONT_ITALIC),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.HexColor(COLORS["score_insecure"])),
                ('TEXTCOLOR', (1, 0), (1, 0), colors.HexColor(COLORS["score_low"])),
                ('TEXTCOLOR', (2, 0), (2, 0), colors.HexColor(COLORS["score_moderate"])),
                ('TEXTCOLOR', (3, 0), (3, 0), colors.HexColor(COLORS["score_secure"])),
                ('TEXTCOLOR', (4, 0), (4, 0), colors.HexColor(COLORS["score_very_secure"])),
            ]))

            risk_elements.append(label_table)

            # Add spacer
            risk_elements.append(Spacer(1, 0.5*inch))

            # Use KeepTogether to ensure risk score information stays on the cover page
            story.append(KeepTogether(risk_elements))

    def _add_table_of_contents(self, story: List, doc: WifiSecurityReportDocument) -> None:
        """Add the table of contents to the report."""
        # Add heading
        toc_title = Paragraph("Table of Contents", self.styles['Heading1'])
        story.append(toc_title)

        # Add spacer
        story.append(Spacer(1, 0.1*inch))

        # Create a manual TOC with direct links to sections
        toc_entries = [
            ("1. Executive Summary", "executive_summary"),
            ("2. Device & Environment Information", "device_info"),
            ("3. Network Scan Results", "network_scan"),
            ("4. Security Distribution", "security_distribution"),
            ("5. Threat Detection", "threat_detection"),
            ("6. Risk Score Breakdown", "risk_score"),
            ("7. Security Recommendations", "security_recommendations"),
            ("8. Appendix", "appendix")
        ]

        # Create TOC entries with proper styling
        # We'll use plain text instead of links to avoid bookmark issues
        for title, key in toc_entries:
            # Create paragraph without link
            toc_entry = Paragraph(
                title,
                self.styles['TOC1'] if 'TOC1' in self.styles else self.styles['Heading2']
            )
            story.append(toc_entry)
            story.append(Spacer(1, 0.1*inch))

        # We'll still include the automatic TOC for the multiBuild process
        # but it will be hidden (we'll use our manual TOC for display)
        doc.toc.dotsMinLevel = 0  # Ensure dots are shown for all levels

        # Add page break
        story.append(PageBreak())

    def _add_executive_summary(self, story: List, doc: WifiSecurityReportDocument = None) -> None:
        """Add the executive summary section to the report with enhanced visual elements."""
        # Add section heading with bookmark for TOC
        section_title = Paragraph("1. Executive Summary", self.styles['Heading1'])
        story.append(section_title)

        # Set current section for bookmarking
        if doc:
            doc.current_section = "executive_summary"

        # Add horizontal line after heading
        story.append(HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor(COLORS["primary_light"]),
            spaceBefore=0,
            spaceAfter=12,
            hAlign='CENTER'
        ))

        # Get summary data
        total_networks = self.audit_data.get('total_networks', 0)
        risk_assessment = self.audit_data.get('risk_assessment', {})
        high_risk_count = len(risk_assessment.get('high_risk_networks', []))
        weak_security_count = len(risk_assessment.get('weak_security_networks', []))
        strong_security_count = len(risk_assessment.get('strong_security_networks', []))
        overall_score = self.audit_data.get('overall_risk_score', 0)

        # Create introduction text
        intro_text = f"""
        This report provides a comprehensive security assessment of {total_networks} WiFi networks detected in your vicinity.
        The assessment evaluates security configurations, encryption standards, and potential vulnerabilities to provide
        an overall security rating and actionable recommendations.
        """
        intro_para = Paragraph(intro_text, self.styles['BodyText'])
        story.append(intro_para)

        # Add spacer
        story.append(Spacer(1, 0.2*inch))

        # Create a summary box with key findings

        # Determine overall risk level and color - align with cover page and security_audit.py
        if overall_score >= 80:
            risk_level = "Secure"
            risk_color = COLORS["score_very_secure"]
        elif overall_score >= 60:
            risk_level = "Moderately Secure"
            risk_color = COLORS["score_secure"]
        elif overall_score >= 40:
            risk_level = "Moderate Risk"
            risk_color = COLORS["score_moderate"]
        elif overall_score >= 20:
            risk_level = "High Risk"
            risk_color = COLORS["score_low"]
        else:
            risk_level = "Critical Risk"
            risk_color = COLORS["critical"]

        # Create a table for the summary box with proper formatting
        summary_title = "EXECUTIVE SUMMARY"

        # Create paragraphs for each cell to enable proper formatting
        title_para = Paragraph(summary_title, self.styles['TableHeader'])
        score_para = Paragraph(f"Overall Security Score: {overall_score}/100 ({risk_level})", self.styles['TableCell'])
        dist_title_para = Paragraph("Network Security Distribution", self.styles['TableHeader'])

        # Create a row with three columns for network distribution
        high_risk_para = Paragraph(f"• {high_risk_count} High Risk Networks", self.styles['TableCell'])
        moderate_risk_para = Paragraph(f"• {weak_security_count} Moderate Risk Networks", self.styles['TableCell'])
        secure_para = Paragraph(f"• {strong_security_count} Secure Networks", self.styles['TableCell'])

        summary_data = [
            [title_para],
            [score_para],
            [dist_title_para],
            [high_risk_para, moderate_risk_para, secure_para]
        ]

        # Calculate column widths for the distribution row
        col_width = 6*inch
        dist_col_width = col_width / 3

        # Create a nested table for the distribution row
        dist_table = Table(
            [[high_risk_para, moderate_risk_para, secure_para]],
            colWidths=[dist_col_width, dist_col_width, dist_col_width]
        )

        # Style the distribution table
        dist_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
        ]))

        # Main summary table with the nested distribution table
        summary_data = [
            [title_para],
            [score_para],
            [dist_title_para],
            [dist_table]
        ]

        summary_table = Table(
            summary_data,
            colWidths=[col_width],
            rowHeights=[0.3*inch, 0.4*inch, 0.3*inch, 0.6*inch]
        )

        # Style the summary table
        summary_table.setStyle(TableStyle([
            # Border and background
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(COLORS["primary"])),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor(COLORS["accent"])),
            ('LINEBELOW', (0, 1), (-1, 1), 1, colors.HexColor(COLORS["border"])),
            ('LINEBELOW', (0, 2), (-1, 2), 1, colors.HexColor(COLORS["border"])),

            # Text styling
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, 1), colors.HexColor(risk_color)),
            ('TEXTCOLOR', (0, 2), (-1, 2), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 3), (-1, 3), colors.HexColor(COLORS["text_primary"])),

            # Alignment
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('ALIGN', (0, 1), (-1, 1), 'CENTER'),
            ('ALIGN', (0, 2), (-1, 2), 'CENTER'),
            ('ALIGN', (0, 3), (-1, 3), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),

            # Font styling
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTNAME', (0, 1), (-1, 1), FONT_BOLD),
            ('FONTNAME', (0, 2), (-1, 2), FONT_BOLD),
            ('FONTNAME', (0, 3), (-1, 3), FONT_NORMAL),

            # Font sizes
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('FONTSIZE', (0, 1), (-1, 1), 14),
            ('FONTSIZE', (0, 2), (-1, 2), 12),
            ('FONTSIZE', (0, 3), (-1, 3), 11),
        ]))

        story.append(summary_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Create a visual representation of network security distribution
        if total_networks > 0:
            # Calculate percentages
            high_risk_percent = (high_risk_count / total_networks) * 100
            weak_security_percent = (weak_security_count / total_networks) * 100
            strong_security_percent = (strong_security_count / total_networks) * 100

            # Create a title for the chart
            chart_title = Paragraph("Network Security Distribution", self.styles['Heading3'])
            story.append(chart_title)

            # Create a simple bar chart with proper text wrapping
            # Create header cells
            level_header = Paragraph("<b>Security Level</b>", self.styles['TableHeader'])
            count_header = Paragraph("<b>Count</b>", self.styles['TableHeader'])
            percent_header = Paragraph("<b>Percentage</b>", self.styles['TableHeader'])

            # Create data cells
            high_risk_cell = Paragraph("High Risk", self.styles['TableCell'])
            moderate_risk_cell = Paragraph("Moderate Risk", self.styles['TableCell'])
            secure_cell = Paragraph("Secure", self.styles['TableCell'])

            high_count_cell = Paragraph(str(high_risk_count), self.styles['TableCell'])
            moderate_count_cell = Paragraph(str(weak_security_count), self.styles['TableCell'])
            secure_count_cell = Paragraph(str(strong_security_count), self.styles['TableCell'])

            high_percent_cell = Paragraph(f"{high_risk_percent:.1f}%", self.styles['TableCell'])
            moderate_percent_cell = Paragraph(f"{weak_security_percent:.1f}%", self.styles['TableCell'])
            secure_percent_cell = Paragraph(f"{strong_security_percent:.1f}%", self.styles['TableCell'])

            chart_data = [
                [level_header, count_header, percent_header],
                [high_risk_cell, high_count_cell, high_percent_cell],
                [moderate_risk_cell, moderate_count_cell, moderate_percent_cell],
                [secure_cell, secure_count_cell, secure_percent_cell]
            ]

            # Calculate column widths
            chart_table = Table(
                chart_data,
                colWidths=[2*inch, 1.5*inch, 2.5*inch],
                rowHeights=[0.4*inch, 0.4*inch, 0.4*inch, 0.4*inch]
            )

            # Style the chart table
            chart_table.setStyle(TableStyle([
                # Header styling
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),

                # Data styling
                ('FONTNAME', (0, 1), (-1, -1), FONT_NORMAL),
                ('ALIGN', (1, 1), (2, -1), 'CENTER'),
                ('ALIGN', (0, 1), (0, -1), 'LEFT'),

                # Grid
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),

                # Row colors with security level colors
                ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor(COLORS["score_insecure"] + "40")),  # 40 = 25% opacity
                ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor(COLORS["score_moderate"] + "40")),
                ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor(COLORS["score_very_secure"] + "40")),

                # Add text color to security level cells to make them more prominent
                ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor(COLORS["score_insecure"])),
                ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor(COLORS["score_moderate"])),
                ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor(COLORS["score_very_secure"])),
                ('FONTNAME', (0, 1), (0, 3), FONT_BOLD),
            ]))

            # No visual bars needed since we removed the Visual Representation column

            story.append(chart_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add key recommendations preview
        recommendations = self.audit_data.get('recommendations', [])
        if recommendations:
            # Get top 3 recommendations
            top_recommendations = recommendations[:min(3, len(recommendations))]

            # Create a title for the recommendations
            rec_title = Paragraph("Key Recommendations Preview", self.styles['Heading3'])
            story.append(rec_title)

            # Create a list of recommendations
            for i, rec in enumerate(top_recommendations):
                priority = rec.get('priority', '').capitalize()
                issue = rec.get('issue', 'Unknown Issue')

                # Create a style based on priority
                priority_style = self.styles['Normal']
                if priority.lower() == 'high':
                    priority_style = self.styles['Critical']
                elif priority.lower() == 'medium':
                    priority_style = self.styles['Moderate']
                else:
                    priority_style = self.styles['Low']

                # Add the recommendation
                rec_text = f"<b>{i+1}. {issue}</b> ({priority} Priority)"
                rec_para = Paragraph(rec_text, priority_style)
                story.append(rec_para)
                story.append(Spacer(1, 0.1*inch))

            # Add a note about the full recommendations section
            note_text = """
            <i>See Section 7 for complete recommendations and implementation guidance.</i>
            """
            note_para = Paragraph(note_text, self.styles['Caption'])
            story.append(note_para)

            # Add extra spacing to ensure clear separation between sections
            story.append(Spacer(1, 0.5*inch))

        # Add page break
        story.append(PageBreak())
    def _add_appendix(self, story: List, doc: WifiSecurityReportDocument = None) -> None:
        """Add the appendix section to the report."""
        # Add section heading with bookmark for TOC
        section_title = Paragraph("8. Appendix", self.styles['Heading1'])
        story.append(section_title)

        # Set current section for bookmarking
        if doc:
            doc.current_section = "appendix"

        # Add scan metadata section
        metadata_title = Paragraph("8.1 Scan Metadata", self.styles['Heading2'])
        story.append(metadata_title)

        # Create metadata table
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_duration = f"{self.scan_duration:.2f} seconds" if self.scan_duration else "Unknown"
        total_networks = len(self.networks)

        metadata_data = [
            ["Scan Date and Time", scan_time],
            ["Scan Duration", scan_duration],
            ["Total Networks Detected", str(total_networks)],
            ["Report ID", self.report_id],
            ["Report Generation Time", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]

        # Create table
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])

        # Style the table
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor(COLORS["primary_light"])),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), FONT_BOLD),
            ('FONTSIZE', (0, 0), (0, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        story.append(metadata_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add glossary section
        glossary_title = Paragraph("8.2 Glossary", self.styles['Heading2'])
        story.append(glossary_title)

        # Create glossary in point form
        glossary_terms = [
            ("<b>SSID:</b> Service Set Identifier - The name of a WiFi network"),
            ("<b>BSSID:</b> Basic Service Set Identifier - The MAC address of the access point"),
            ("<b>WPA/WPA2/WPA3:</b> WiFi Protected Access - Security protocols for WiFi networks"),
            ("<b>WEP:</b> Wired Equivalent Privacy - An outdated and insecure WiFi security protocol"),
            ("<b>Enterprise:</b> Authentication method that uses a RADIUS server for individual user credentials"),
            ("<b>Signal Strength:</b> Measure of the power level of the WiFi signal (higher is better)"),
            ("<b>Channel:</b> The frequency channel used by the WiFi network"),
            ("<b>Band:</b> The frequency band used by the WiFi network (2.4 GHz or 5 GHz)"),
            ("<b>Security Score:</b> A measure of the overall security of a WiFi network (higher is better)"),
            ("<b>MAC Address:</b> Media Access Control Address - A unique identifier assigned to network interfaces"),
            ("<b>Encryption:</b> The process of encoding data to prevent unauthorized access"),
            ("<b>Vulnerability:</b> A weakness that can be exploited by attackers to gain unauthorized access"),
            ("<b>VPN:</b> Virtual Private Network - Encrypts your internet connection for privacy and security"),
            ("<b>Router:</b> A device that forwards data packets between computer networks"),
            ("<b>Access Point:</b> A device that allows wireless devices to connect to a wired network")
        ]

        # Add glossary terms as bullet points
        for term in glossary_terms:
            term_para = Paragraph(f"• {term}", self.styles['BodyText'])
            story.append(term_para)
            story.append(Spacer(1, 0.05*inch))  # Small space between items

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add disclaimer section
        disclaimer_title = Paragraph("8.3 Disclaimer", self.styles['Heading2'])
        story.append(disclaimer_title)

        disclaimer_text = """
        <b>Disclaimer:</b> This report is provided for informational purposes only and represents a point-in-time assessment
        of the WiFi networks detected during the scan. The security assessments and recommendations are based on
        industry best practices and the information available at the time of the scan.

        The WiFi Threat Assessor application does not guarantee the security of any network and is not responsible
        for any security breaches or data loss that may occur. The user is solely responsible for implementing
        appropriate security measures based on their specific requirements and risk tolerance.

        This report should not be considered a comprehensive security audit and does not replace the need for
        professional security assessments for critical environments.
        """

        disclaimer_para = Paragraph(disclaimer_text, self.styles['BodyText'])
        story.append(disclaimer_para)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add contact information section
        contact_title = Paragraph("8.4 Contact Information", self.styles['Heading2'])
        story.append(contact_title)

        contact_intro = """
        For questions, feedback, or support regarding this report or the WiFi Threat Assessor application,
        please contact:
        """

        contact_intro_para = Paragraph(contact_intro, self.styles['BodyText'])
        story.append(contact_intro_para)

        # Add spacer
        story.append(Spacer(1, 0.1*inch))

        # Create contact information as bullet points
        contact_items = [
            Paragraph("• <b>Support Team:</b> WiFi Threat Assessor Support", self.styles['BodyText']),
            Paragraph("• <b>Email:</b> support@wifithreatassessor.com", self.styles['BodyText']),
            Paragraph("• <b>Website:</b> https://www.wifithreatassessor.com", self.styles['BodyText']),
            Paragraph("• <b>Support Hours:</b> Monday – Friday, 9:00 AM – 5:00 PM EST", self.styles['BodyText'])
        ]

        # Add each contact item with proper spacing
        for item in contact_items:
            story.append(item)
            story.append(Spacer(1, 0.05*inch))

        # Add spacer
        story.append(Spacer(1, 0.1*inch))

        # Add thank you message
        thank_you = "Thank you for using WiFi Threat Assessor to improve your network security!"
        thank_you_para = Paragraph(thank_you, self.styles['BodyText'])
        story.append(thank_you_para)
    def _add_device_info(self, story: List, doc: WifiSecurityReportDocument = None) -> None:
        """Add the device and environment information section to the report with enhanced layout."""
        # Add section heading with bookmark for TOC
        section_title = Paragraph("2. Device & Environment Information", self.styles['Heading1'])
        story.append(section_title)

        # Set current section for bookmarking
        if doc:
            doc.current_section = "device_info"

        # Add horizontal line after heading
        story.append(HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor(COLORS["primary_light"]),
            spaceBefore=0,
            spaceAfter=12,
            hAlign='CENTER'
        ))

        # Add introduction text
        intro_text = """
        This section provides information about the device used to perform the scan and the environment in which
        the scan was conducted. This information is useful for understanding the context of the security assessment.
        """
        intro_para = Paragraph(intro_text, self.styles['BodyText'])
        story.append(intro_para)

        # Add spacer
        story.append(Spacer(1, 0.2*inch))

        # Create a two-column layout for device info
        # Left column: Device Information
        # Right column: Scan Information

        # Get connected network info if available
        connected_ssid = "Unknown"
        connected_auth = "Unknown"
        connected_signal = 0

        for network in self.networks:
            # Check if this is the connected network (usually the one with the highest signal)
            if network.get('connected', False) or (network.get('signal', 0) > connected_signal):
                connected_ssid = network.get('ssid', 'Unknown')
                connected_auth = network.get('auth_type', 'Unknown')
                connected_signal = network.get('signal', 0)
                # If we found a network marked as connected, break
                if network.get('connected', False):
                    break

        # Format signal strength as a qualitative value
        signal_quality = "Unknown"
        signal_color = COLORS["text_primary"]

        if isinstance(connected_signal, (int, float)):
            if connected_signal >= 80:
                signal_quality = "Excellent"
                signal_color = COLORS["signal_excellent"]
            elif connected_signal >= 60:
                signal_quality = "Good"
                signal_color = COLORS["signal_good"]
            elif connected_signal >= 40:
                signal_quality = "Fair"
                signal_color = COLORS["signal_fair"]
            elif connected_signal >= 20:
                signal_quality = "Poor"
                signal_color = COLORS["signal_poor"]
            else:
                signal_quality = "Weak"
                signal_color = COLORS["signal_weak"]

        # Create device info table with enhanced styling
        device_data = [
            ["Device Information", "Value"],
            ["Hostname", self.device_info.get('hostname', 'Unknown')],
            ["Operating System", self.device_info.get('os', 'Unknown')],
            ["IP Address", self.device_info.get('ip_address', 'Unknown')],
            ["MAC Address", self.device_info.get('mac_address', 'Unknown')],
            ["Processor", self.device_info.get('processor', 'Unknown')],
            ["Python Version", self.device_info.get('python_version', 'Unknown')],
            ["System Time", self.device_info.get('system_time', 'Unknown')]
        ]

        # Create table with improved styling
        device_table = Table(device_data, colWidths=[2*inch, 4*inch])

        # Style the table with enhanced visual elements
        device_table.setStyle(TableStyle([
            # Header row styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, 0), 12),

            # Data rows styling
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor(COLORS["primary_light"])),
            ('TEXTCOLOR', (0, 1), (0, -1), colors.white),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (0, -1), FONT_BOLD),
            ('FONTSIZE', (0, 1), (0, -1), 10),

            # Value column styling
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            ('FONTNAME', (1, 1), (1, -1), FONT_NORMAL),
            ('FONTSIZE', (1, 1), (1, -1), 10),

            # Cell padding
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),

            # Grid styling
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),

            # Alternating row colors for better readability
            ('ROWBACKGROUNDS', (1, 1), (1, -1), [colors.white, colors.HexColor(COLORS["accent"])])
        ]))

        # Create scan info table
        scan_data = [
            ["Scan Information", "Value"],
            ["Scan Date", datetime.datetime.now().strftime("%B %d, %Y")],
            ["Scan Time", datetime.datetime.now().strftime("%H:%M:%S")],
            ["Scan Duration", f"{self.scan_duration:.2f} seconds" if self.scan_duration else "Unknown"],
            ["Networks Detected", str(self.audit_data.get('total_networks', 0))],
            ["Connected SSID", connected_ssid],
            ["Authentication Type", connected_auth],
            ["Signal Strength", f"{connected_signal}% ({signal_quality})"]
        ]

        # Create table with improved styling
        scan_table = Table(scan_data, colWidths=[2*inch, 4*inch])

        # Style the scan table with enhanced visual elements
        scan_table.setStyle(TableStyle([
            # Header row styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, 0), 12),

            # Data rows styling
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor(COLORS["secondary"])),
            ('TEXTCOLOR', (0, 1), (0, -1), colors.white),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (0, -1), FONT_BOLD),
            ('FONTSIZE', (0, 1), (0, -1), 10),

            # Value column styling
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            ('FONTNAME', (1, 1), (1, -1), FONT_NORMAL),
            ('FONTSIZE', (1, 1), (1, -1), 10),

            # Special styling for signal strength
            ('TEXTCOLOR', (1, 7), (1, 7), colors.HexColor(signal_color)),
            ('FONTNAME', (1, 7), (1, 7), FONT_BOLD),

            # Cell padding
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),

            # Grid styling
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),

            # Alternating row colors for better readability
            ('ROWBACKGROUNDS', (1, 1), (1, -1), [colors.white, colors.HexColor(COLORS["accent"])])
        ]))

        # Add tables to story
        story.append(Paragraph("Device Information", self.styles['Heading2']))
        story.append(device_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add scan information table
        story.append(Paragraph("Scan Information", self.styles['Heading2']))
        story.append(scan_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add note about environment
        note_text = """
        <b>Note:</b> The security assessment is based on the WiFi networks detected at the time of the scan.
        Network conditions and available networks may change over time. Regular scans are recommended to
        maintain an up-to-date security posture.
        """
        note_para = Paragraph(note_text, self.styles['BodyText'])
        story.append(note_para)

        # Add page break
        story.append(PageBreak())

    def _add_network_scan_results(self, story: List, doc: WifiSecurityReportDocument = None) -> None:
        """Add the network scan results section to the report."""
        # Add section heading with bookmark for TOC
        section_title = Paragraph("3. Network Scan Results", self.styles['Heading1'])
        story.append(section_title)

        # Set current section for bookmarking
        if doc:
            doc.current_section = "network_scan_results"

        # Add network overview section
        overview_title = Paragraph("3.1 Network Overview", self.styles['Heading2'])
        story.append(overview_title)

        # Create overview text
        overview_text = f"""
        The scan detected {len(self.networks)} WiFi networks in range. The table below provides
        a summary of all networks, sorted by security score (lowest to highest).
        """

        overview_para = Paragraph(overview_text, self.styles['BodyText'])
        story.append(overview_para)

        # Add spacer
        story.append(Spacer(1, 0.2*inch))

        # Create network overview table
        table_header = [
            "Network Name", "Security Type", "Signal", "Channel", "Band", "Security Score"
        ]

        table_data = [table_header]

        # Sort networks by security score (lowest to highest)
        sorted_networks = sorted(
            self.networks,
            key=lambda n: self._get_network_security_score(n)[0] if 'auth_type' in n else 0
        )

        for network in sorted_networks:
            ssid = network.get('ssid', 'Hidden Network')
            security = network.get('auth_type', 'Unknown')
            signal = f"{network.get('signal_strength', 0)}%" if 'signal_strength' in network else f"{network.get('signal', 0)}%"
            channel = str(network.get('channel', 'Unknown'))
            band = network.get('band', 'Unknown')

            score, _, _ = self._get_network_security_score(network) if 'auth_type' in network else (0, 'Unknown', '#FF0000')

            table_data.append([
                ssid,
                security,
                signal,
                channel,
                band,
                f"{int(score)}/100"
            ])

        # Create table
        col_widths = [1.5*inch, 1.3*inch, 0.7*inch, 0.7*inch, 0.7*inch, 1.0*inch]
        network_table = Table(table_data, colWidths=col_widths)

        # Style the table
        network_table.setStyle(TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),

            # Data styling
            ('FONTNAME', (0, 1), (-1, -1), FONT_NORMAL),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            ('ALIGN', (2, 1), (5, -1), 'CENTER'),

            # Borders and padding
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),

            # Alternating row colors
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor(COLORS["accent"])])
        ]))

        story.append(network_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add detailed network analysis section
        detailed_title = Paragraph("3.2 Detailed Network Analysis", self.styles['Heading2'])
        story.append(detailed_title)

        # Add detailed analysis for each network
        for i, network in enumerate(sorted_networks):
            self._add_network_detail(story, network, i+1)

        # Add page break
        story.append(PageBreak())
    def _add_network_detail(self, story: List, network: Dict, index: int) -> None:
        """Add detailed analysis for a single network."""
        ssid = network.get('ssid', 'Hidden Network')

        # Add network title
        network_title = Paragraph(f"3.2.{index} {ssid}", self.styles['Heading3'])
        story.append(network_title)

        # Get network details
        bssid = network.get('bssid', 'Unknown')
        security = network.get('auth_type', 'Unknown')
        signal = network.get('signal_strength', 0) if 'signal_strength' in network else network.get('signal', 0)
        channel = network.get('channel', 'Unknown')
        band = network.get('band', 'Unknown')

        # Get security score
        score, description, color = self._get_network_security_score(network) if 'auth_type' in network else (0, 'Unknown', '#FF0000')

        # Create network details table
        details_data = [
            ["BSSID", bssid],
            ["Security Type", security],
            ["Signal Strength", f"{signal}%"],
            ["Channel", channel],
            ["Band", band],
            ["Security Score", f"{int(score)}/100"],
            ["Security Rating", description]
        ]

        # Create table
        details_table = Table(details_data, colWidths=[1.5*inch, 4.5*inch])

        # Style the table
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor(COLORS["primary_light"])),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), FONT_BOLD),
            ('FONTSIZE', (0, 0), (0, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        story.append(details_table)

        # Add spacer
        story.append(Spacer(1, 0.2*inch))

        # Add security assessment
        security_text = self._get_security_assessment(network, score)
        security_para = Paragraph(security_text, self.styles['BodyText'])
        story.append(security_para)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

    def _get_security_assessment(self, network: Dict, score: float) -> str:
        """Generate a security assessment text for a network."""
        ssid = network.get('ssid', 'Hidden Network')
        security = network.get('auth_type', 'Unknown')

        if score >= 80:
            return f"""
            <b>Security Assessment:</b> The network "{ssid}" is using {security} security, which provides strong protection.
            This network has a high security score and is well-configured for protecting your data.
            It uses modern encryption standards and is less vulnerable to common WiFi attacks.
            """
        elif score >= 60:
            return f"""
            <b>Security Assessment:</b> The network "{ssid}" is using {security} security, which provides good protection.
            While this network has a decent security configuration, there may be room for improvement.
            Consider implementing additional security measures for sensitive data transmission.
            """
        elif score >= 40:
            return f"""
            <b>Security Assessment:</b> The network "{ssid}" is using {security} security, which provides moderate protection.
            This network has several security vulnerabilities that could potentially be exploited.
            It is recommended to upgrade the security configuration or use a VPN when connecting to this network.
            """
        elif score >= 20:
            return f"""
            <b>Security Assessment:</b> The network "{ssid}" is using {security} security, which provides weak protection.
            This network has significant security vulnerabilities and is at high risk of attacks.
            Avoid connecting to this network for any sensitive activities or use strong additional encryption (VPN).
            """
        else:
            return f"""
            <b>Security Assessment:</b> The network "{ssid}" is using {security} security, which provides minimal to no protection.
            This network is extremely vulnerable to attacks and should be avoided.
            If you must connect to this network, use a VPN and avoid any sensitive activities.
            """

    def _get_network_security_score(self, network: Dict) -> Tuple[float, str, str]:
        """Calculate security score for a network."""
        score = 0
        auth_type = network.get('auth_type', '').lower()

        # Base score based on authentication type
        if "wpa3" in auth_type:
            score += 40
        elif "wpa2" in auth_type:
            score += 30
        elif "wpa" in auth_type and "wpa2" not in auth_type and "wpa3" not in auth_type:
            score += 20
        elif "wep" in auth_type:
            score += 10

        # Bonus for enterprise security
        if "enterprise" in auth_type:
            score += 20

        # Bonus for 5GHz band (less crowded, typically better security)
        if network.get('band') == "5 GHz":
            score += 10

        # Factor in signal strength (better signal = less chance of dropping connection and reconnecting to rogue networks)
        signal_strength = network.get('signal', 0)
        if isinstance(signal_strength, (int, float)):
            score += (signal_strength / 100) * 30
        else:
            # Default middle value if signal strength is unknown
            score += 15

        # Determine security description and color based on score
        if score >= 80:
            description = "Very Secure"
            color = COLORS["score_very_secure"]
        elif score >= 60:
            description = "Secure"
            color = COLORS["score_secure"]
        elif score >= 40:
            description = "Moderately Secure"
            color = COLORS["score_moderate"]
        elif score >= 20:
            description = "Low Security"
            color = COLORS["score_low"]
        else:
            description = "Insecure"
            color = COLORS["score_insecure"]

        return (score, description, color)

    def _add_security_distribution(self, story: List, doc: WifiSecurityReportDocument = None) -> None:
        """Add the security type distribution section to the report."""
        # Add section heading with bookmark for TOC
        section_title = Paragraph("4. Security Type Distribution", self.styles['Heading1'])
        story.append(section_title)

        # Set current section for bookmarking
        if doc:
            doc.current_section = "security_distribution"

        # Add description
        description_text = """
        This section shows the distribution of security types among the detected networks.
        The security type (WPA3, WPA2, WPA, WEP, or Open) is a key factor in determining
        the overall security of a WiFi network.
        """
        description = Paragraph(description_text, self.styles['BodyText'])
        story.append(description)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Count security types
        security_types = [network.get('auth_type', 'Unknown').lower() for network in self.networks]

        # Categorize security types
        categories = {
            'WPA3': 0,
            'WPA2': 0,
            'WPA': 0,
            'WEP': 0,
            'Open': 0,
            'Unknown': 0
        }

        for security in security_types:
            if not security or security == 'unknown':
                categories['Unknown'] += 1
            elif 'open' in security or security == 'none':
                categories['Open'] += 1
            elif 'wep' in security:
                categories['WEP'] += 1
            elif 'wpa3' in security:
                categories['WPA3'] += 1
            elif 'wpa2' in security:
                categories['WPA2'] += 1
            elif 'wpa' in security:
                categories['WPA'] += 1
            else:
                categories['Unknown'] += 1

        # Create security distribution table
        table_data = [
            ["Security Type", "Count", "Percentage", "Security Level"]
        ]

        total = sum(categories.values())

        for security_type, count in categories.items():
            if count > 0:
                percentage = (count / total) * 100

                # Determine security level
                if security_type == 'WPA3':
                    security_level = "Very High"
                    color = COLORS["score_very_secure"]
                elif security_type == 'WPA2':
                    security_level = "High"
                    color = COLORS["score_secure"]
                elif security_type == 'WPA':
                    security_level = "Moderate"
                    color = COLORS["score_moderate"]
                elif security_type == 'WEP':
                    security_level = "Low"
                    color = COLORS["score_low"]
                elif security_type == 'Open':
                    security_level = "None"
                    color = COLORS["score_insecure"]
                else:
                    security_level = "Unknown"
                    color = COLORS["text_secondary"]

                table_data.append([
                    security_type,
                    str(count),
                    f"{percentage:.1f}%",
                    security_level
                ])

        # Create table
        security_table = Table(table_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 2*inch])

        # Style the table
        security_table.setStyle(TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),

            # Data styling
            ('FONTNAME', (0, 1), (-1, -1), FONT_NORMAL),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (2, -1), 'CENTER'),
            ('ALIGN', (3, 1), (3, -1), 'LEFT'),

            # Borders and padding
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),

            # Alternating row colors
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor(COLORS["accent"])])
        ]))

        story.append(security_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add security distribution explanation in point form
        # Add title first
        explanation_title = Paragraph("<b>Security Type Explanation:</b>", self.styles['Heading3'])
        story.append(explanation_title)

        # Add spacer
        story.append(Spacer(1, 0.1*inch))

        # Create list of security type explanations as separate bullet points
        security_explanations = [
            "<b>WPA3:</b> The latest and most secure WiFi security protocol, offering enhanced encryption and protection against brute force attacks.",
            "<b>WPA2:</b> A widely used security protocol that provides strong encryption when properly configured.",
            "<b>WPA:</b> An older security protocol with known vulnerabilities. It's better than WEP but less secure than WPA2/WPA3.",
            "<b>WEP:</b> A deprecated security protocol with serious vulnerabilities. Networks using WEP can be easily compromised.",
            "<b>Open:</b> Networks with no encryption. All data transmitted over these networks can be intercepted."
        ]

        # Add each explanation as a separate bullet point
        for explanation in security_explanations:
            bullet_para = Paragraph(f"• {explanation}", self.styles['BodyText'])
            story.append(bullet_para)
            story.append(Spacer(1, 0.05*inch))  # Small space between items

        # Add page break
        story.append(PageBreak())
    def _add_threat_detection(self, story: List, doc: WifiSecurityReportDocument = None) -> None:
        """Add the threat detection summary section to the report."""
        # Add section heading with bookmark for TOC
        section_title = Paragraph("5. Threat Detection Summary", self.styles['Heading1'])
        story.append(section_title)

        # Set current section for bookmarking
        if doc:
            doc.current_section = "threat_detection"

        # Add description
        description_text = """
        This section summarizes potential threats detected in your WiFi environment.
        The threats are categorized by severity level and include recommendations for mitigation.
        """
        description = Paragraph(description_text, self.styles['BodyText'])
        story.append(description)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Get threat data from audit data
        risk_assessment = self.audit_data.get('risk_assessment', {})
        high_risk_networks = risk_assessment.get('high_risk_networks', [])
        weak_security_networks = risk_assessment.get('weak_security_networks', [])

        # Create threat summary table with proper text wrapping
        # Create header cells
        threat_header = Paragraph("<b>Threat Level</b>", self.styles['TableHeader'])
        count_header = Paragraph("<b>Count</b>", self.styles['TableHeader'])
        desc_header = Paragraph("<b>Description</b>", self.styles['TableHeader'])

        table_data = [
            [threat_header, count_header, desc_header]
        ]

        # Add threat data
        if high_risk_networks:
            threat_cell = Paragraph("Critical", self.styles['TableCell'])
            count_cell = Paragraph(str(len(high_risk_networks)), self.styles['TableCell'])
            desc_cell = Paragraph("Networks with severe security vulnerabilities that pose immediate risk", self.styles['TableCell'])

            table_data.append([threat_cell, count_cell, desc_cell])

        if weak_security_networks:
            threat_cell = Paragraph("Moderate", self.styles['TableCell'])
            count_cell = Paragraph(str(len(weak_security_networks)), self.styles['TableCell'])
            desc_cell = Paragraph("Networks with security configurations that could be improved", self.styles['TableCell'])

            table_data.append([threat_cell, count_cell, desc_cell])

        # Add other potential threats
        open_networks = sum(1 for n in self.networks if 'auth_type' in n and ('open' in n['auth_type'].lower() or n['auth_type'].lower() == 'none'))
        wep_networks = sum(1 for n in self.networks if 'auth_type' in n and 'wep' in n['auth_type'].lower())

        if open_networks > 0:
            threat_cell = Paragraph("Critical", self.styles['TableCell'])
            count_cell = Paragraph(str(open_networks), self.styles['TableCell'])
            desc_cell = Paragraph("Open networks with no encryption (vulnerable to eavesdropping)", self.styles['TableCell'])

            table_data.append([threat_cell, count_cell, desc_cell])

        if wep_networks > 0:
            threat_cell = Paragraph("High", self.styles['TableCell'])
            count_cell = Paragraph(str(wep_networks), self.styles['TableCell'])
            desc_cell = Paragraph("Networks using deprecated WEP encryption (easily crackable)", self.styles['TableCell'])

            table_data.append([threat_cell, count_cell, desc_cell])

        # If no threats detected, add a "No threats" row
        if len(table_data) == 1:
            threat_cell = Paragraph("None", self.styles['TableCell'])
            count_cell = Paragraph("0", self.styles['TableCell'])
            desc_cell = Paragraph("No significant threats detected in the scanned networks", self.styles['TableCell'])

            table_data.append([threat_cell, count_cell, desc_cell])

        # Create table with fixed row heights for better layout
        row_heights = [0.4*inch]  # Header row

        # Add generous row heights for all data rows
        for i in range(1, len(table_data)):
            row_heights.append(0.5*inch)

        threat_table = Table(
            table_data,
            colWidths=[1.2*inch, 0.8*inch, 4*inch],
            rowHeights=row_heights
        )

        # Style the table
        threat_table.setStyle(TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),

            # Data styling
            ('FONTNAME', (0, 1), (-1, -1), FONT_NORMAL),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            ('ALIGN', (2, 1), (2, -1), 'LEFT'),

            # Borders and padding
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),

            # Alternating row colors
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor(COLORS["accent"])])
        ]))

        story.append(threat_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add detailed threat information
        if high_risk_networks or weak_security_networks or open_networks or wep_networks:
            threat_detail_title = Paragraph("Detailed Threat Information", self.styles['Heading2'])
            story.append(threat_detail_title)

            # Add information about high-risk networks
            if high_risk_networks:
                high_risk_title = Paragraph("Critical Risk Networks", self.styles['Heading3'])
                story.append(high_risk_title)

                high_risk_text = """
                The following networks have critical security vulnerabilities and should be avoided:
                """
                story.append(Paragraph(high_risk_text, self.styles['BodyText']))

                # Create list of high-risk networks
                high_risk_list = []
                for network in high_risk_networks:
                    ssid = network.get('ssid', 'Unknown')
                    score = network.get('score', 0)
                    high_risk_list.append(f"<b>{ssid}</b> (Security Score: {score}/100)")

                # Add list to story
                for item in high_risk_list:
                    story.append(Paragraph(f"• {item}", self.styles['BodyText']))

                story.append(Spacer(1, 0.2*inch))

            # Add information about open networks
            if open_networks > 0:
                open_networks_title = Paragraph("Open Networks (No Encryption)", self.styles['Heading3'])
                story.append(open_networks_title)

                open_networks_text = """
                Open networks do not use encryption, making all transmitted data vulnerable to interception.
                Avoid connecting to these networks for any sensitive activities. If you must connect,
                use a VPN to encrypt your traffic.
                """
                story.append(Paragraph(open_networks_text, self.styles['BodyText']))

                # Add list of open networks if available
                open_network_list = []
                for network in self.networks:
                    if 'auth_type' in network and ('open' in network['auth_type'].lower() or network['auth_type'].lower() == 'none'):
                        ssid = network.get('ssid', 'Unknown')
                        open_network_list.append(f"<b>{ssid}</b>")

                if open_network_list:
                    story.append(Spacer(1, 0.1*inch))
                    story.append(Paragraph("Detected open networks:", self.styles['BodyText']))

                    # Add list to story
                    for item in open_network_list[:5]:  # Limit to 5 networks to avoid overwhelming the report
                        story.append(Paragraph(f"• {item}", self.styles['BodyText']))

                    if len(open_network_list) > 5:
                        story.append(Paragraph(f"• ... and {len(open_network_list) - 5} more", self.styles['BodyText']))

                story.append(Spacer(1, 0.2*inch))

            # Add information about WEP networks
            if wep_networks > 0:
                wep_networks_title = Paragraph("WEP Networks (Deprecated Encryption)", self.styles['Heading3'])
                story.append(wep_networks_title)

                wep_networks_text = """
                WEP (Wired Equivalent Privacy) is a deprecated security protocol with known vulnerabilities.
                Networks using WEP encryption can be easily compromised, often in minutes using readily available tools.
                Avoid connecting to these networks and upgrade to WPA2 or WPA3 if you control these networks.
                """
                story.append(Paragraph(wep_networks_text, self.styles['BodyText']))

                # Add list of WEP networks if available
                wep_network_list = []
                for network in self.networks:
                    if 'auth_type' in network and 'wep' in network['auth_type'].lower():
                        ssid = network.get('ssid', 'Unknown')
                        wep_network_list.append(f"<b>{ssid}</b>")

                if wep_network_list:
                    story.append(Spacer(1, 0.1*inch))
                    story.append(Paragraph("Detected WEP networks:", self.styles['BodyText']))

                    # Add list to story
                    for item in wep_network_list:
                        story.append(Paragraph(f"• {item}", self.styles['BodyText']))

                story.append(Spacer(1, 0.2*inch))

            # Add information about weak security networks
            if weak_security_networks:
                weak_security_title = Paragraph("Networks with Weak Security", self.styles['Heading3'])
                story.append(weak_security_title)

                weak_security_text = """
                The following networks have security configurations that could be improved.
                While not as vulnerable as open or WEP networks, these networks may have configuration
                issues or use older protocols that have known vulnerabilities.
                """
                story.append(Paragraph(weak_security_text, self.styles['BodyText']))

                # Create list of weak security networks
                weak_security_list = []
                for network in weak_security_networks:
                    ssid = network.get('ssid', 'Unknown')
                    auth_type = network.get('auth_type', 'Unknown')
                    weak_security_list.append(f"<b>{ssid}</b> (Security Type: {auth_type})")

                # Add list to story
                for item in weak_security_list:
                    story.append(Paragraph(f"• {item}", self.styles['BodyText']))

                story.append(Spacer(1, 0.2*inch))

            # Add common attack vectors section
            attack_vectors_title = Paragraph("Common Attack Vectors", self.styles['Heading3'])
            story.append(attack_vectors_title)

            attack_vectors_text = """
            Based on the detected network environment, the following attack vectors are possible:
            """
            story.append(Paragraph(attack_vectors_text, self.styles['BodyText']))

            # Create list of attack vectors
            attack_vectors = []

            if open_networks > 0:
                attack_vectors.append("<b>Packet Sniffing</b> - Attackers can capture and analyze unencrypted network traffic on open networks")
                attack_vectors.append("<b>Man-in-the-Middle Attacks</b> - Attackers can intercept and potentially modify communications between devices")

            if wep_networks > 0:
                attack_vectors.append("<b>WEP Cracking</b> - Attackers can break WEP encryption in minutes using readily available tools")

            if any('wpa' in network.get('auth_type', '').lower() for network in self.networks):
                attack_vectors.append("<b>Dictionary Attacks</b> - Weak passwords on WPA/WPA2 networks can be cracked using dictionary attacks")

            attack_vectors.append("<b>Evil Twin Attacks</b> - Attackers can create fake networks with the same name as legitimate networks")
            attack_vectors.append("<b>Rogue Access Points</b> - Unauthorized access points can be used to gain access to a network")

            # Add list to story
            for item in attack_vectors:
                story.append(Paragraph(f"• {item}", self.styles['BodyText']))

            story.append(Spacer(1, 0.2*inch))

        # Add page break
        story.append(PageBreak())

    def _add_risk_score_breakdown(self, story: List, doc: WifiSecurityReportDocument = None) -> None:
        """Add the risk score breakdown section to the report with enhanced visual elements."""
        # Add section heading with bookmark for TOC
        section_title = Paragraph("6. Risk Score Breakdown", self.styles['Heading1'])
        story.append(section_title)

        # Set current section for bookmarking
        if doc:
            doc.current_section = "risk_score_breakdown"

        # Add horizontal line after heading
        story.append(HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor(COLORS["primary_light"]),
            spaceBefore=0,
            spaceAfter=12,
            hAlign='CENTER'
        ))

        # Add description
        description_text = """
        This section explains how the overall risk score is calculated and provides a breakdown
        of the factors that contribute to the score. The risk score is based on the security
        configuration of each network, with higher scores indicating better security.
        """
        description = Paragraph(description_text, self.styles['BodyText'])
        story.append(description)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add scoring formula explanation with enhanced visual elements
        formula_title = Paragraph("Scoring Formula", self.styles['Heading2'])
        story.append(formula_title)

        # Create a table for the scoring formula with wrapped text
        factor_col = Paragraph("<b>Factor</b>", self.styles['TableHeader'])
        points_col = Paragraph("<b>Points</b>", self.styles['TableHeader'])
        desc_col = Paragraph("<b>Description</b>", self.styles['TableHeader'])

        # Create paragraphs for each cell to enable text wrapping
        auth_type = Paragraph("Authentication Type", self.styles['TableCell'])
        auth_desc = Paragraph("Security protocol used by the network", self.styles['TableCell'])

        wpa3 = Paragraph("WPA3", self.styles['TableCell'])
        wpa3_points = Paragraph("40", self.styles['TableCell'])
        wpa3_desc = Paragraph("Latest and most secure WiFi security protocol", self.styles['TableCell'])

        wpa2 = Paragraph("WPA2", self.styles['TableCell'])
        wpa2_points = Paragraph("30", self.styles['TableCell'])
        wpa2_desc = Paragraph("Strong security protocol with good encryption", self.styles['TableCell'])

        wpa = Paragraph("WPA", self.styles['TableCell'])
        wpa_points = Paragraph("20", self.styles['TableCell'])
        wpa_desc = Paragraph("Older protocol with known vulnerabilities", self.styles['TableCell'])

        wep = Paragraph("WEP", self.styles['TableCell'])
        wep_points = Paragraph("10", self.styles['TableCell'])
        wep_desc = Paragraph("Deprecated protocol with serious security flaws", self.styles['TableCell'])

        open_net = Paragraph("Open", self.styles['TableCell'])
        open_points = Paragraph("0", self.styles['TableCell'])
        open_desc = Paragraph("No encryption, all data is transmitted in clear text", self.styles['TableCell'])

        enterprise = Paragraph("Enterprise Security", self.styles['TableCell'])
        enterprise_points = Paragraph("+20", self.styles['TableCell'])
        enterprise_desc = Paragraph("Uses RADIUS server for individual user authentication", self.styles['TableCell'])

        freq_band = Paragraph("Frequency Band", self.styles['TableCell'])
        freq_points = Paragraph("+10", self.styles['TableCell'])
        freq_desc = Paragraph("5 GHz networks (less interference, typically better security)", self.styles['TableCell'])

        signal = Paragraph("Signal Strength", self.styles['TableCell'])
        signal_points = Paragraph("0-30", self.styles['TableCell'])
        signal_desc = Paragraph("Based on signal quality (stronger = better security)", self.styles['TableCell'])

        formula_data = [
            [factor_col, points_col, desc_col],
            [auth_type, "", auth_desc],
            [wpa3, wpa3_points, wpa3_desc],
            [wpa2, wpa2_points, wpa2_desc],
            [wpa, wpa_points, wpa_desc],
            [wep, wep_points, wep_desc],
            [open_net, open_points, open_desc],
            [enterprise, enterprise_points, enterprise_desc],
            [freq_band, freq_points, freq_desc],
            [signal, signal_points, signal_desc]
        ]

        # Create table with improved styling and proper column widths to prevent overflow
        formula_table = Table(
            formula_data,
            colWidths=[1.5*inch, 0.8*inch, 3.7*inch],
            rowHeights=[0.4*inch] * len(formula_data)
        )

        # Style the table with enhanced visual elements
        formula_table.setStyle(TableStyle([
            # Header row styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, 0), 12),

            # Category row styling
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor(COLORS["primary_light"])),
            ('TEXTCOLOR', (0, 1), (-1, 1), colors.white),
            ('FONTNAME', (0, 1), (-1, 1), FONT_BOLD),
            ('SPAN', (0, 1), (0, 1)),
            ('SPAN', (1, 1), (1, 1)),
            ('SPAN', (2, 1), (2, 1)),

            # Authentication type rows
            ('BACKGROUND', (0, 2), (0, 6), colors.HexColor(COLORS["accent"])),
            ('LEFTPADDING', (0, 2), (0, 6), 20),  # Indent for sub-items

            # Special rows styling
            ('BACKGROUND', (0, 7), (-1, 7), colors.HexColor(COLORS["secondary"] + "40")),  # 40 = 25% opacity
            ('BACKGROUND', (0, 8), (-1, 8), colors.HexColor(COLORS["secondary"] + "40")),
            ('BACKGROUND', (0, 9), (-1, 9), colors.HexColor(COLORS["secondary"] + "40")),
            ('FONTNAME', (0, 7), (0, 9), FONT_BOLD),

            # Points column styling
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (1, 2), (1, -1), FONT_BOLD),

            # Description column styling
            ('ALIGN', (2, 0), (2, -1), 'LEFT'),

            # Cell padding
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),

            # Grid styling
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        story.append(formula_table)

        # Add explanation of overall score calculation
        overall_text = """
        <b>Overall Environment Risk Score Calculation:</b>
        The overall risk score is calculated as the weighted average of all network scores, with higher weight given to networks with stronger signal strength. This reflects the fact that you are more likely to connect to networks with stronger signals.
        """
        overall_para = Paragraph(overall_text, self.styles['BodyText'])
        story.append(Spacer(1, 0.2*inch))
        story.append(overall_para)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Calculate risk score distribution
        score_ranges = [
            (0, 20, 'Critical Risk', COLORS["score_insecure"]),
            (20, 40, 'High Risk', COLORS["score_low"]),
            (40, 60, 'Moderate Risk', COLORS["score_moderate"]),
            (60, 80, 'Low Risk', COLORS["score_secure"]),
            (80, 100, 'Secure', COLORS["score_very_secure"])
        ]

        # Count networks in each range
        range_counts = [0] * len(score_ranges)

        for network in self.networks:
            if 'auth_type' in network:
                score, _, _ = self._get_network_security_score(network)

                for i, (min_score, max_score, _, _) in enumerate(score_ranges):
                    if min_score <= score < max_score or (i == len(score_ranges) - 1 and score == max_score):
                        range_counts[i] += 1
                        break

        # Add risk distribution title
        distribution_title = Paragraph("Network Risk Distribution", self.styles['Heading2'])
        story.append(distribution_title)

        # Create risk distribution table with enhanced visual elements
        table_data = [
            ["Risk Level", "Score Range", "Count", "Percentage"]
        ]

        total_networks = sum(range_counts)

        for i, (min_score, max_score, label, color_hex) in enumerate(score_ranges):
            count = range_counts[i]
            percentage = (count / total_networks * 100) if total_networks > 0 else 0

            table_data.append([
                label,
                f"{min_score}-{max_score}",
                str(count),
                f"{percentage:.1f}%"
            ])

        # Create table with improved styling
        risk_table = Table(table_data, colWidths=[1.5*inch, 1.2*inch, 1*inch, 1.3*inch])

        # Style the table with enhanced visual elements
        base_style = [
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),

            # Data styling
            ('FONTNAME', (0, 1), (-1, -1), FONT_NORMAL),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (3, -1), 'CENTER'),

            # Borders and padding
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]

        # Add row colors based on risk level
        for i, (_, _, _, color_hex) in enumerate(score_ranges):
            base_style.append(('BACKGROUND', (0, i+1), (0, i+1), colors.HexColor(color_hex)))
            base_style.append(('TEXTCOLOR', (0, i+1), (0, i+1), colors.white))
            base_style.append(('FONTNAME', (0, i+1), (0, i+1), FONT_BOLD))

        risk_table.setStyle(TableStyle(base_style))

        story.append(risk_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add risk score interpretation with enhanced visual elements
        interpretation_title = Paragraph("Risk Score Interpretation", self.styles['Heading2'])
        story.append(interpretation_title)

        # Create a table for risk score interpretation with wrapped text
        # Create header cells
        score_header = Paragraph("<b>Score Range</b>", self.styles['TableHeader'])
        risk_header = Paragraph("<b>Risk Level</b>", self.styles['TableHeader'])
        desc_header = Paragraph("<b>Description</b>", self.styles['TableHeader'])

        # Create description cells with proper wrapping
        secure_desc = Paragraph("Strong encryption (WPA2/WPA3) with proper configuration. Excellent protection for sensitive data.", self.styles['TableCell'])
        low_desc = Paragraph("Good encryption with minor configuration issues. Good protection for most activities.", self.styles['TableCell'])
        moderate_desc = Paragraph("Significant security concerns. May use older protocols or have configuration issues.", self.styles['TableCell'])
        high_desc = Paragraph("Serious vulnerabilities. Weak encryption or major configuration issues.", self.styles['TableCell'])
        critical_desc = Paragraph("Minimal to no security. May use no encryption (open) or outdated protocols (WEP).", self.styles['TableCell'])

        # Create score range and risk level cells
        score_secure = Paragraph("80-100", self.styles['TableCell'])
        score_low = Paragraph("60-80", self.styles['TableCell'])
        score_moderate = Paragraph("40-60", self.styles['TableCell'])
        score_high = Paragraph("20-40", self.styles['TableCell'])
        score_critical = Paragraph("0-20", self.styles['TableCell'])

        risk_secure = Paragraph("Secure", self.styles['TableCell'])
        risk_low = Paragraph("Low Risk", self.styles['TableCell'])
        risk_moderate = Paragraph("Moderate Risk", self.styles['TableCell'])
        risk_high = Paragraph("High Risk", self.styles['TableCell'])
        risk_critical = Paragraph("Critical Risk", self.styles['TableCell'])

        interpretation_data = [
            [score_header, risk_header, desc_header],
            [score_secure, risk_secure, secure_desc],
            [score_low, risk_low, low_desc],
            [score_moderate, risk_moderate, moderate_desc],
            [score_high, risk_high, high_desc],
            [score_critical, risk_critical, critical_desc]
        ]

        # Create table with improved styling and row heights to accommodate wrapped text
        interpretation_table = Table(
            interpretation_data,
            colWidths=[1*inch, 1.2*inch, 3.8*inch],
            rowHeights=[0.4*inch, 0.5*inch, 0.5*inch, 0.5*inch, 0.5*inch, 0.5*inch]
        )

        # Style the table with enhanced visual elements
        interpretation_table.setStyle(TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, 0), 11),

            # Row styling based on risk level
            ('BACKGROUND', (1, 1), (1, 1), colors.HexColor(COLORS["score_very_secure"])),
            ('BACKGROUND', (1, 2), (1, 2), colors.HexColor(COLORS["score_secure"])),
            ('BACKGROUND', (1, 3), (1, 3), colors.HexColor(COLORS["score_moderate"])),
            ('BACKGROUND', (1, 4), (1, 4), colors.HexColor(COLORS["score_low"])),
            ('BACKGROUND', (1, 5), (1, 5), colors.HexColor(COLORS["score_insecure"])),

            # Text styling for risk level column
            ('TEXTCOLOR', (1, 1), (1, -1), colors.white),
            ('FONTNAME', (1, 1), (1, -1), FONT_BOLD),

            # Score range column styling
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (0, -1), FONT_BOLD),

            # Description column styling
            ('ALIGN', (2, 0), (2, -1), 'LEFT'),

            # Cell padding
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),

            # Grid styling
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        story.append(interpretation_table)

        # Add security recommendations preview
        story.append(Spacer(1, 0.3*inch))
        rec_title = Paragraph("Security Improvement Recommendations", self.styles['Heading2'])
        story.append(rec_title)

        # Add introduction text
        intro_text = "Based on the risk score analysis, consider implementing the following security improvements:"
        intro_para = Paragraph(intro_text, self.styles['BodyText'])
        story.append(intro_para)

        # Add spacer
        story.append(Spacer(1, 0.1*inch))

        # Create recommendation items as separate bullet points for better formatting
        recommendations = [
            "<b>Upgrade to WPA3</b> where possible for maximum security",
            "<b>Replace WEP networks</b> immediately with WPA2 or WPA3",
            "<b>Avoid connecting to open networks</b> without using a VPN",
            "<b>Use enterprise authentication</b> for business networks",
            "<b>Implement strong, unique passwords</b> for all networks"
        ]

        # Add each recommendation as a separate paragraph with bullet point
        for recommendation in recommendations:
            rec_para = Paragraph(f"• {recommendation}", self.styles['BodyText'])
            story.append(rec_para)
            story.append(Spacer(1, 0.05*inch))  # Small space between items

        # Add spacer
        story.append(Spacer(1, 0.1*inch))

        # Add note about detailed recommendations
        note_text = "See Section 7 for detailed security recommendations and implementation guidance."
        note_para = Paragraph(note_text, self.styles['BodyText'])
        story.append(note_para)

        # Add page break
        story.append(PageBreak())
    def _add_security_recommendations(self, story: List, doc: WifiSecurityReportDocument = None) -> None:
        """Add the security recommendations section to the report with enhanced visual elements."""
        # Add section heading with bookmark for TOC
        section_title = Paragraph("7. Security Recommendations", self.styles['Heading1'])
        story.append(section_title)

        # Set current section for bookmarking
        if doc:
            doc.current_section = "security_recommendations"

        # Add horizontal line after heading
        story.append(HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor(COLORS["primary_light"]),
            spaceBefore=0,
            spaceAfter=12,
            hAlign='CENTER'
        ))

        # Add description
        description_text = """
        This section provides actionable recommendations to improve your WiFi security posture.
        The recommendations are categorized by priority level and include implementation difficulty.
        Each recommendation includes specific steps you can take to enhance your network security.
        """
        description = Paragraph(description_text, self.styles['BodyText'])
        story.append(description)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Get recommendations from audit data
        recommendations = self.audit_data.get('recommendations', [])

        # Create a table for all recommendations with visual indicators
        # Create header cells with proper formatting
        priority_header = Paragraph("<b>Priority</b>", self.styles['TableHeader'])
        rec_header = Paragraph("<b>Recommendation</b>", self.styles['TableHeader'])
        diff_header = Paragraph("<b>Difficulty</b>", self.styles['TableHeader'])
        desc_header = Paragraph("<b>Description</b>", self.styles['TableHeader'])

        table_data = [
            [priority_header, rec_header, diff_header, desc_header]
        ]

        # Define difficulty levels and their corresponding visual indicators
        difficulty_levels = {
            "easy": "●",
            "medium": "●●",
            "advanced": "●●●"
        }

        # Filter and add critical recommendations
        critical_recommendations = [r for r in recommendations if r.get('priority', '').lower() == 'high']

        # Add critical recommendations to table
        for rec in critical_recommendations:
            issue = rec.get('issue', 'Unknown Issue')
            description = rec.get('recommendation', 'No recommendation available')

            # Determine difficulty (default to medium if not specified)
            difficulty_text = rec.get('difficulty', 'medium').lower()
            difficulty_indicator = difficulty_levels.get(difficulty_text, "●●")

            # Create paragraph objects for proper text wrapping
            priority_cell = Paragraph("Critical", self.styles['TableCell'])
            issue_cell = Paragraph(issue, self.styles['TableCell'])
            difficulty_cell = Paragraph(difficulty_indicator, self.styles['TableCell'])
            description_cell = Paragraph(description, self.styles['TableCell'])

            table_data.append([
                priority_cell,
                issue_cell,
                difficulty_cell,
                description_cell
            ])

        # Add medium priority recommendations
        medium_recommendations = [r for r in recommendations if r.get('priority', '').lower() == 'medium']

        for rec in medium_recommendations:
            issue = rec.get('issue', 'Unknown Issue')
            description = rec.get('recommendation', 'No recommendation available')

            # Determine difficulty (default to medium if not specified)
            difficulty_text = rec.get('difficulty', 'medium').lower()
            difficulty_indicator = difficulty_levels.get(difficulty_text, "●●")

            # Create paragraph objects for proper text wrapping
            priority_cell = Paragraph("Medium", self.styles['TableCell'])
            issue_cell = Paragraph(issue, self.styles['TableCell'])
            difficulty_cell = Paragraph(difficulty_indicator, self.styles['TableCell'])
            description_cell = Paragraph(description, self.styles['TableCell'])

            table_data.append([
                priority_cell,
                issue_cell,
                difficulty_cell,
                description_cell
            ])

        # Add low priority recommendations
        low_recommendations = [r for r in recommendations if r.get('priority', '').lower() == 'low']

        for rec in low_recommendations:
            issue = rec.get('issue', 'Unknown Issue')
            description = rec.get('recommendation', 'No recommendation available')

            # Determine difficulty (default to easy if not specified)
            difficulty_text = rec.get('difficulty', 'easy').lower()
            difficulty_indicator = difficulty_levels.get(difficulty_text, "●")

            # Create paragraph objects for proper text wrapping
            priority_cell = Paragraph("Low", self.styles['TableCell'])
            issue_cell = Paragraph(issue, self.styles['TableCell'])
            difficulty_cell = Paragraph(difficulty_indicator, self.styles['TableCell'])
            description_cell = Paragraph(description, self.styles['TableCell'])

            table_data.append([
                priority_cell,
                issue_cell,
                difficulty_cell,
                description_cell
            ])

        # If no recommendations were found in the audit data, add default recommendations
        if len(table_data) == 1:  # Only header row exists
            default_recommendations = [
                # Critical recommendations
                ("Critical", "Replace WEP Networks", "medium", "Replace any networks using WEP encryption with WPA2 or WPA3. WEP can be easily cracked and provides minimal security."),
                ("Critical", "Secure Open Networks", "easy", "Add password protection to any open networks. Open networks allow anyone to intercept your data."),

                # Medium recommendations
                ("Medium", "Use WPA3 Where Possible", "medium", "Upgrade to WPA3 for maximum security. WPA3 provides stronger encryption and protection against brute force attacks."),
                ("Medium", "Change Default Credentials", "easy", "Change default router credentials (username, password, SSID) to strong, unique values."),
                ("Medium", "Enable Automatic Updates", "easy", "Configure your router to automatically install firmware updates to protect against known vulnerabilities."),
                ("Medium", "Use Strong Passwords", "easy", "Implement strong, unique passwords for all WiFi networks (minimum 12 characters with a mix of letters, numbers, and symbols)."),

                # Low recommendations
                ("Low", "Implement Network Segmentation", "advanced", "Separate your network into multiple segments (e.g., main network, guest network, IoT devices network) to limit the impact of a potential breach."),
                ("Low", "Enable MAC Address Filtering", "medium", "Configure your router to only allow connections from specific devices based on their MAC addresses. Note that this can be circumvented but adds an additional layer of security."),
                ("Low", "Disable WPS", "easy", "WiFi Protected Setup (WPS) can be vulnerable to brute force attacks. Disable this feature if it's not needed."),
                ("Low", "Use a VPN", "medium", "Consider using a VPN service for additional encryption and privacy protection, especially when connecting to public WiFi networks.")
            ]

            for priority, issue, difficulty, description in default_recommendations:
                difficulty_indicator = difficulty_levels.get(difficulty, "●●")

                # Create paragraph objects for proper text wrapping
                priority_cell = Paragraph(priority, self.styles['TableCell'])
                issue_cell = Paragraph(issue, self.styles['TableCell'])
                difficulty_cell = Paragraph(difficulty_indicator, self.styles['TableCell'])
                description_cell = Paragraph(description, self.styles['TableCell'])

                table_data.append([
                    priority_cell,
                    issue_cell,
                    difficulty_cell,
                    description_cell
                ])

        # Create the recommendations table with improved styling and proper column widths to prevent overflow
        col_widths = [0.8*inch, 1.5*inch, 0.7*inch, 3*inch]

        # Use fixed row heights that are generous enough for all content
        # Since we're using Paragraph objects, we can't easily determine the length of the text
        row_heights = [0.4*inch]  # Header row

        # Add generous row heights for all data rows to ensure text fits
        for i in range(1, len(table_data)):
            row_heights.append(0.8*inch)  # Use a consistent generous height for all rows

        recommendations_table = Table(
            table_data,
            colWidths=col_widths,
            rowHeights=row_heights,
            repeatRows=1
        )

        # Style the table with enhanced visual elements
        base_style = [
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),

            # Column styling
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # Center priority column
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),    # Left-align recommendation column
            ('ALIGN', (2, 1), (2, -1), 'CENTER'),  # Center difficulty column
            ('ALIGN', (3, 1), (3, -1), 'LEFT'),    # Left-align description column

            # Borders and padding
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),

            # Font styling
            ('FONTNAME', (1, 1), (1, -1), FONT_BOLD),  # Bold recommendation titles
        ]

        # Add row styling based on priority
        for i in range(1, len(table_data)):
            # Extract the text from the Paragraph object
            priority_text = table_data[i][0].text
            # Remove HTML tags if present and convert to lowercase
            priority_text = priority_text.replace("<b>", "").replace("</b>", "").lower()

            if "critical" in priority_text:
                base_style.append(('BACKGROUND', (0, i), (0, i), colors.HexColor(COLORS["critical"])))
                base_style.append(('TEXTCOLOR', (0, i), (0, i), colors.white))
                base_style.append(('FONTNAME', (0, i), (0, i), FONT_BOLD))
                base_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor(COLORS["critical"] + "20")))  # 20 = 12.5% opacity
            elif "medium" in priority_text:
                base_style.append(('BACKGROUND', (0, i), (0, i), colors.HexColor(COLORS["moderate"])))
                base_style.append(('TEXTCOLOR', (0, i), (0, i), colors.white))
                base_style.append(('FONTNAME', (0, i), (0, i), FONT_BOLD))
                base_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor(COLORS["moderate"] + "20")))  # 20 = 12.5% opacity
            else:  # Low priority
                base_style.append(('BACKGROUND', (0, i), (0, i), colors.HexColor(COLORS["info"])))
                base_style.append(('TEXTCOLOR', (0, i), (0, i), colors.white))
                base_style.append(('FONTNAME', (0, i), (0, i), FONT_BOLD))
                base_style.append(('BACKGROUND', (0, i), (-1, i), colors.HexColor(COLORS["info"] + "20")))  # 20 = 12.5% opacity

            # Style difficulty indicators
            difficulty_text = table_data[i][2].text
            difficulty_text = difficulty_text.replace("<b>", "").replace("</b>", "")

            if "●" == difficulty_text:  # Easy
                base_style.append(('TEXTCOLOR', (2, i), (2, i), colors.HexColor(COLORS["low"])))
                base_style.append(('FONTNAME', (2, i), (2, i), FONT_BOLD))
                base_style.append(('FONTSIZE', (2, i), (2, i), 14))
            elif "●●" == difficulty_text:  # Medium
                base_style.append(('TEXTCOLOR', (2, i), (2, i), colors.HexColor(COLORS["moderate"])))
                base_style.append(('FONTNAME', (2, i), (2, i), FONT_BOLD))
                base_style.append(('FONTSIZE', (2, i), (2, i), 14))
            else:  # Advanced
                base_style.append(('TEXTCOLOR', (2, i), (2, i), colors.HexColor(COLORS["high"])))
                base_style.append(('FONTNAME', (2, i), (2, i), FONT_BOLD))
                base_style.append(('FONTSIZE', (2, i), (2, i), 14))

        recommendations_table.setStyle(TableStyle(base_style))

        # Add the recommendations table to the story
        story.append(recommendations_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add difficulty legend with updated title
        legend_title = Paragraph("Difficulty To Implement Score", self.styles['Heading3'])
        story.append(legend_title)

        # Create paragraphs for each cell to enable text wrapping
        legend_data_wrapped = [
            [
                Paragraph("<b>Indicator</b>", self.styles['TableHeader']),
                Paragraph("<b>Difficulty Level</b>", self.styles['TableHeader']),
                Paragraph("<b>Description</b>", self.styles['TableHeader'])
            ],
            [
                Paragraph("●", self.styles['TableCell']),
                Paragraph("Easy", self.styles['TableCell']),
                Paragraph("Can be implemented quickly with basic technical knowledge", self.styles['TableCell'])
            ],
            [
                Paragraph("●●", self.styles['TableCell']),
                Paragraph("Medium", self.styles['TableCell']),
                Paragraph("Requires moderate technical knowledge and time to implement", self.styles['TableCell'])
            ],
            [
                Paragraph("●●●", self.styles['TableCell']),
                Paragraph("Advanced", self.styles['TableCell']),
                Paragraph("Requires advanced technical knowledge or professional assistance", self.styles['TableCell'])
            ]
        ]

        # Create table with proper column widths and row heights to prevent overflow
        legend_table = Table(
            legend_data_wrapped,
            colWidths=[0.8*inch, 1.5*inch, 3.7*inch],
            rowHeights=[0.4*inch, 0.4*inch, 0.4*inch, 0.4*inch]
        )

        legend_table.setStyle(TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(COLORS["primary_light"])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),

            # Indicator column styling
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),
            ('FONTSIZE', (0, 1), (0, -1), 14),
            ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor(COLORS["low"])),
            ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor(COLORS["moderate"])),
            ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor(COLORS["high"])),
            ('FONTNAME', (0, 1), (0, -1), FONT_BOLD),

            # Difficulty level column styling
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            ('FONTNAME', (1, 1), (1, -1), FONT_BOLD),

            # Description column styling
            ('ALIGN', (2, 1), (2, -1), 'LEFT'),

            # Borders and padding
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(COLORS["border"])),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),

            # Alternating row colors
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor(COLORS["accent"])),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor(COLORS["accent"])),
        ]))

        story.append(legend_table)

        # Add spacer
        story.append(Spacer(1, 0.3*inch))

        # Add implementation guidance with enhanced visual elements
        guidance_title = Paragraph("Implementation Guidance", self.styles['Heading3'])
        story.append(guidance_title)

        # Create a visually appealing guidance box
        guidance_data = [
            ["When implementing these recommendations, consider the following:"],
            ["• Prioritize critical issues first to address the most significant vulnerabilities."],
            ["• Test changes in a controlled environment before deploying them widely."],
            ["• Document all changes made to your network configuration for future reference."],
            ["• Regularly review and update your security measures as new threats emerge."],
            ["• Consider professional assistance for complex security implementations."]
        ]

        guidance_table = Table(guidance_data, colWidths=[6*inch])

        guidance_table.setStyle(TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor(COLORS["primary_light"])),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('FONTNAME', (0, 0), (0, 0), FONT_BOLD),
            ('ALIGN', (0, 0), (0, 0), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (0, 0), 8),
            ('TOPPADDING', (0, 0), (0, 0), 8),

            # List item styling
            ('FONTNAME', (0, 1), (0, -1), FONT_NORMAL),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('LEFTPADDING', (0, 1), (0, -1), 20),
            ('BOTTOMPADDING', (0, 1), (0, -1), 6),
            ('TOPPADDING', (0, 1), (0, -1), 6),

            # Box styling
            ('BOX', (0, 0), (0, -1), 1, colors.HexColor(COLORS["primary_light"])),

            # Alternating row colors
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor(COLORS["accent"])),
            ('BACKGROUND', (0, 3), (0, -1), colors.white),
            ('BACKGROUND', (0, 5), (0, -1), colors.HexColor(COLORS["accent"])),
        ]))

        story.append(guidance_table)

        # Add note about regular security audits
        story.append(Spacer(1, 0.3*inch))
        note_text = """
        <b>Note:</b> Regular security audits are essential for maintaining a strong security posture.
        It is recommended to perform a security audit at least quarterly, or whenever significant changes
        are made to your network infrastructure.
        """
        note_para = Paragraph(note_text, self.styles['BodyText'])
        story.append(note_para)

        # Add page break
        story.append(PageBreak())
