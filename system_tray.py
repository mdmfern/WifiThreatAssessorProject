"""
System Tray Application for Wi-Fi Threat Assessor.

This module provides system tray functionality for the Wi-Fi Threat Assessor application,
allowing users to access key features from the system tray icon even when the main
application window is closed.
"""

# Standard library imports
import os
import threading
import time

# Third-party imports
from PIL import Image, ImageDraw
import pystray

# Local application imports
import wifi_utils
import security_utils
from security_advisor import SecurityAdvisor
from ui_constants import COLORS


class SystemTrayApp:
    """
    System tray application for Wi-Fi Threat Assessor.

    Provides a system tray icon with menu options for accessing key features
    of the Wi-Fi Threat Assessor application.
    """

    def __init__(self, main_app):
        """
        Initialize the system tray application.

        Args:
            main_app: Main application instance to control
        """
        self.main_app = main_app
        self.icon = None
        self.running = False
        self.last_connection_check = 0
        self.connection_check_interval = 10
        self.icon_image = self._create_icon_image()
        self.setup_tray()

    def _create_icon_image(self):
        """
        Create the system tray icon image.

        First attempts to load the icon from the assets directory.
        If not found, generates a Wi-Fi-like icon programmatically.

        Returns:
            PIL.Image: The icon image
        """
        try:
            icon_path = os.path.join("assets", "tray_icon.png")
            if os.path.exists(icon_path):
                return Image.open(icon_path)
        except Exception:
            # Fall back to generating an icon programmatically
            pass

        # Create a transparent image
        size = 64
        image = Image.new('RGBA', (size, size), color=(0, 0, 0, 0))
        draw = ImageDraw.Draw(image)

        # Get primary color from UI constants
        primary_color = COLORS.get("primary", ("#1f538d", "#1f538d"))[0]
        if primary_color.startswith("#"):
            primary_color = primary_color[1:]

        # Convert hex color to RGB
        r, g, b = tuple(int(primary_color[i:i+2], 16) for i in (0, 2, 4))

        # Draw Wi-Fi-like arcs and center dot
        draw.arc((8, 8, size-8, size-8), 225, 315, fill=(r, g, b), width=4)
        draw.arc((16, 16, size-16, size-16), 225, 315, fill=(r, g, b), width=4)
        draw.arc((24, 24, size-24, size-24), 225, 315, fill=(r, g, b), width=4)
        draw.ellipse((28, 28, size-28, size-28), fill=(r, g, b))

        return image

    def setup_tray(self):
        """
        Set up the system tray icon and menu.

        Creates a menu with options for opening the main window, scanning networks,
        checking security status, comparing networks, toggling automated notifications,
        and exiting the application.
        """
        menu = (
            pystray.MenuItem('Open Wi-Fi Threat Assessor', self._show_window),
            pystray.MenuItem('Scan Networks', self._scan_networks),
            pystray.MenuItem('Security Status', self._show_security_status),
            pystray.MenuItem('Compare Networks', self._compare_networks),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Toggle Auto Notifications', self._toggle_auto_notifications),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Exit', self._exit_app)
        )

        self.icon = pystray.Icon(
            "wifi_threat_assessor",
            self.icon_image,
            "Wi-Fi Threat Assessor",
            menu
        )

    def run(self):
        """
        Start the system tray application in a separate thread.

        Creates a daemon thread to run the system tray icon, ensuring
        it doesn't prevent the application from exiting.
        """
        if not self.running:
            self.running = True
            tray_thread = threading.Thread(target=self._run_tray, daemon=True)
            tray_thread.start()

    def _run_tray(self):
        """
        Run the system tray icon and display initial notifications.

        This method is called in a separate thread to avoid blocking
        the main application thread.
        """
        try:
            # Start the system tray icon
            self.icon.run_detached()

            # Wait for the icon to be visible
            time.sleep(1.0)

            try:
                # Show initial notifications
                self.icon.notify(
                    "Application is running in the system tray\n"
                    "Right-click the icon to access options\n"
                    "If you can't see the icon, check the hidden icons area",
                    "Wi-Fi Threat Assessor"
                )

                # Show second notification after a delay
                time.sleep(2.0)
                self.icon.notify(
                    "To open the main window, right-click the system tray icon and select 'Open Wi-Fi Threat Assessor'",
                    "Wi-Fi Threat Assessor"
                )
            except Exception as e:
                # Silently handle notification errors
                pass

        except Exception:
            # Silently handle system tray errors
            pass

    def stop(self):
        """
        Stop the system tray application.

        Stops the system tray icon if it's running.
        """
        if self.running:
            self.running = False
            try:
                if self.icon:
                    self.icon.stop()
            except Exception:
                # Silently handle errors when stopping the system tray
                pass

    def _show_window(self, _icon, _item):
        """
        Show the main application window.

        Args:
            _icon: The system tray icon (unused)
            _item: The menu item that was clicked (unused)
        """
        # Show and focus the main window
        self.main_app.deiconify()
        self.main_app.update_idletasks()
        self.main_app.lift()
        self.main_app.focus_force()

        # Refresh networks if possible
        try:
            self.main_app.refresh_networks()
        except Exception:
            pass

    def _scan_networks(self, _icon, _item):
        """
        Start a network scan in a separate thread.

        Args:
            _icon: The system tray icon (unused)
            _item: The menu item that was clicked (unused)
        """
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        """
        Perform a network scan and display the results.

        Scans for available Wi-Fi networks, analyzes their security,
        and displays a notification with the results.
        """
        # Notify user that scan has started
        self.icon.notify(
            "Scanning for networks...\nThis may take a few seconds",
            "Wi-Fi Scan Started"
        )

        try:
            # Scan for networks with forced refresh
            networks = wifi_utils.scan_networks(force_refresh=True)

            if networks:
                # Sort networks by signal strength
                sorted_networks = sorted(networks, key=lambda x: x.get('signal', 0), reverse=True)
                network_count = len(networks)
                network_text = "network" if network_count == 1 else "networks"

                # Count secure and insecure networks
                secure_count = 0
                insecure_count = 0
                for network in networks:
                    score, _, _ = security_utils.get_network_security_score(network)
                    if score >= 60:
                        secure_count += 1
                    else:
                        insecure_count += 1

                # Get details of top networks by signal strength
                top_networks = []
                for network in sorted_networks[:3]:
                    ssid = network.get('ssid', 'Hidden Network')
                    signal = network.get('signal', 0)
                    auth = network.get('auth_type', 'Unknown')
                    score, desc, _ = security_utils.get_network_security_score(network)
                    top_networks.append(f"  - {ssid} ({signal}%) - {auth} - {desc}")

                # Build notification message
                message = f"Found {network_count} {network_text}\n"
                if top_networks:
                    message += "• Top networks by signal strength:\n"
                    message += "\n".join(top_networks) + "\n"
                message += f"• {secure_count} secure, {insecure_count} less secure"

                # Show notification with results
                self.icon.notify(message, "Wi-Fi Scan Complete")
            else:
                # No networks found
                self.icon.notify(
                    "No networks found",
                    "Wi-Fi Scan Complete"
                )

            # Update main application if visible
            if self.main_app.winfo_viewable():
                self.main_app.after(0, lambda: self.main_app._update_network_display(networks))

        except Exception as e:
            # Notify user of error
            self.icon.notify(
                f"Error scanning networks: {str(e)[:50]}",
                "Scan Error"
            )

    def _show_security_status(self, _icon, _item):
        """
        Show security status of the current Wi-Fi connection.

        Args:
            _icon: The system tray icon (unused)
            _item: The menu item that was clicked (unused)
        """
        # Notify user that check has started
        self.icon.notify(
            "Checking security status...",
            "Wi-Fi Security Check"
        )

        # Get current connection status
        connection = wifi_utils.get_connection_status()

        if connection:
            # Extract network data from connection
            network_data = {
                'auth_type': connection.get('details', {}).get('Authentication', 'Unknown'),
                'signal': connection.get('signal', 0),
                'band': connection.get('details', {}).get('Radio type', ''),
                'ssid': connection.get('ssid', '')
            }

            # Get security information
            security_score, security_description, _ = security_utils.get_network_security_score(network_data)
            encryption_type = security_utils.get_encryption_type(network_data.get('auth_type', ''))
            signal_strength = network_data.get('signal', 0)
            signal_quality = wifi_utils.format_signal_strength(signal_strength)

            # Determine risk level based on security score
            risk_level = "Low Risk"
            if security_score < 30:
                risk_level = "Critical Risk"
            elif security_score < 50:
                risk_level = "High Risk"
            elif security_score < 70:
                risk_level = "Moderate Risk"

            # Get security recommendation
            recommendation = ""
            risk_info = SecurityAdvisor.get_risk_info(network_data)
            if risk_info and 'remedies' in risk_info and len(risk_info['remedies']) > 0:
                recommendation = f"Recommendation: {risk_info['remedies'][0]}"
            else:
                recommendation = "Recommendation: Keep your device updated with security patches"

            # Format security information
            auth_type = connection.get('details', {}).get('Authentication', 'Unknown')
            cipher = connection.get('details', {}).get('Cipher', '')

            if auth_type != 'Unknown':
                if cipher:
                    security_line = f"Security: {auth_type} ({cipher})"
                else:
                    security_line = f"Security: {auth_type}"
            else:
                security_line = f"Security: {encryption_type}"

            # Build notification message
            message = (
                f"Connected to: {connection.get('ssid')}\n"
                f"{security_line}\n"
                f"Signal: {signal_strength}% ({signal_quality.split('(')[0].strip()})\n"
                f"Security Score: {security_score}/100 ({security_description})\n"
                f"Risk Level: {risk_level}\n"
                f"{recommendation}"
            )

            # Show notification with results
            self.icon.notify(message, "Wi-Fi Security Status")
        else:
            # Not connected to any network
            self.icon.notify(
                "Not connected to any Wi-Fi network",
                "Wi-Fi Security Status"
            )

    def _compare_networks(self, _icon, _item):
        """
        Compare the current Wi-Fi network with other available networks.

        Args:
            _icon: The system tray icon (unused)
            _item: The menu item that was clicked (unused)
        """
        # Notify user that comparison has started
        self.icon.notify(
            "Comparing networks...\nThis may take a few seconds",
            "Network Comparison"
        )

        try:
            # Get current connection
            current_connection = wifi_utils.get_connection_status()
            if not current_connection:
                self.icon.notify(
                    "Not connected to any Wi-Fi network",
                    "Network Comparison"
                )
                return

            # Scan for available networks
            networks = wifi_utils.scan_networks(force_refresh=True)
            if not networks:
                self.icon.notify(
                    "No other networks found for comparison",
                    "Network Comparison"
                )
                return

            # Find current network in scan results
            current_ssid = current_connection.get('ssid', '')
            current_network = None
            for network in networks:
                if network.get('ssid', '') == current_ssid:
                    current_network = network
                    break

            # If current network not found in scan results, create it from connection info
            if not current_network:
                current_network = {
                    'ssid': current_ssid,
                    'auth_type': current_connection.get('details', {}).get('Authentication', 'Unknown'),
                    'signal': current_connection.get('signal', 0),
                    'band': current_connection.get('details', {}).get('Radio type', '')
                }

            # Get security score for current network
            current_score, current_desc, _ = security_utils.get_network_security_score(current_network)

            # Score all networks
            scored_networks = []
            for network in networks:
                score, desc, _ = security_utils.get_network_security_score(network)
                scored_networks.append({
                    'ssid': network.get('ssid', 'Hidden Network'),
                    'score': score,
                    'description': desc,
                    'auth_type': network.get('auth_type', 'Unknown'),
                    'signal': network.get('signal', 0)
                })

            # Sort networks by security score (highest first)
            scored_networks.sort(key=lambda x: x['score'], reverse=True)

            # Find rank of current network
            current_rank = 1
            for i, network in enumerate(scored_networks):
                if network['ssid'] == current_ssid:
                    current_rank = i + 1
                    break

            # Find better alternatives (higher security score and good signal)
            better_alternatives = [n for n in scored_networks if n['score'] > current_score and n['signal'] >= 50]
            better_alternatives = better_alternatives[:2]  # Limit to top 2

            # Format security information for current network
            auth_type = current_network.get('auth_type', 'Unknown')
            encryption_type = security_utils.get_encryption_type(auth_type)

            if auth_type != 'Unknown':
                if encryption_type != 'Unknown' and encryption_type != auth_type:
                    security_info = f"Security: {auth_type} ({encryption_type})"
                else:
                    security_info = f"Security: {auth_type}"
            else:
                security_info = f"Security: {encryption_type}"

            # Build notification message
            message = f"Your network ({current_ssid}) ranks #{current_rank} out of {len(scored_networks)} for security.\n"
            message += f"{security_info}\n"
            message += f"Security score: {current_score}/100 ({current_desc})\n"

            # Add information about better alternatives if available
            if better_alternatives:
                message += "\nBetter alternatives nearby:\n"
                for alt in better_alternatives:
                    # Format security information for alternative network
                    alt_auth_type = alt.get('auth_type', 'Unknown')
                    alt_encryption = security_utils.get_encryption_type(alt_auth_type)

                    if alt_auth_type != 'Unknown':
                        if alt_encryption != 'Unknown' and alt_encryption != alt_auth_type:
                            alt_security = f"{alt_auth_type} ({alt_encryption})"
                        else:
                            alt_security = alt_auth_type
                    else:
                        alt_security = alt_encryption if alt_encryption != 'Unknown' else "Unknown"

                    # Format signal information
                    signal = alt.get('signal', 0)
                    signal_quality = wifi_utils.format_signal_strength(signal).split('(')[0].strip()

                    # Add alternative to message
                    message += f"- {alt['ssid']}: {alt_security}, {signal}% ({signal_quality}), Score {alt['score']}/100\n"
                message += "Consider switching for improved security."
            else:
                message += "\nNo better alternatives found nearby."

            # Show notification with results
            self.icon.notify(message, "Network Comparison")

        except Exception as e:
            # Notify user of error
            self.icon.notify(
                f"Error comparing networks: {str(e)[:50]}",
                "Comparison Error"
            )

    def _toggle_auto_notifications(self, _icon, _item):
        """
        Toggle automated notifications on or off.

        If automated notifications are enabled, disables them.
        If automated notifications are disabled or not initialized, enables them.

        Args:
            _icon: The system tray icon (unused)
            _item: The menu item that was clicked (unused)
        """
        try:
            # Check if automated notifications are already initialized
            if hasattr(self.main_app, 'automated_notifications') and self.main_app.automated_notifications:
                # Toggle existing automated notifications
                if self.main_app.automated_notifications.enabled:
                    # Disable notifications
                    self.main_app.automated_notifications.stop()
                    self.icon.notify(
                        "Automated notifications have been disabled",
                        "Notifications Disabled"
                    )
                else:
                    # Enable notifications
                    self.main_app.automated_notifications.start()
                    interval_minutes = int(self.main_app.automated_notifications.notification_interval / 60)
                    self.icon.notify(
                        f"Automated notifications have been enabled\n"
                        f"You will receive updates every {interval_minutes} minutes",
                        "Notifications Enabled"
                    )
            else:
                # Initialize automated notifications if not already initialized
                if not hasattr(self.main_app, 'automated_notifications') or self.main_app.automated_notifications is None:
                    # Import here to avoid circular imports
                    from automated_notifications import AutomatedNotificationSystem

                    # Create and start automated notifications
                    notification_interval = self.main_app.settings.get('notification_interval', 600)
                    self.main_app.automated_notifications = AutomatedNotificationSystem(
                        self.main_app,
                        self,
                        self.main_app.notification_manager,
                        notification_interval
                    )
                    self.main_app.automated_notifications.start()

                    # Notify user
                    interval_minutes = int(notification_interval / 60)
                    self.icon.notify(
                        f"Automated notifications have been enabled\n"
                        f"You will receive updates every {interval_minutes} minutes",
                        "Notifications Enabled"
                    )
        except Exception as e:
            # Notify user of error
            self.icon.notify(
                f"Error toggling notifications: {str(e)[:50]}",
                "Notification Error"
            )

    def _exit_app(self, icon, _item):
        """
        Exit the application.

        Stops the system tray icon and destroys the main application window.

        Args:
            icon: The system tray icon
            _item: The menu item that was clicked (unused)
        """
        # Stop the system tray icon
        icon.stop()

        # Destroy the main application window
        self.main_app.destroy()
