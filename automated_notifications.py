"""
Automated notification system for Wi-Fi Threat Assessor.

This module provides a system for sending automated notifications about Wi-Fi networks,
including connection status, new network detection, and security recommendations.
Notifications are sent periodically based on a configurable interval.
"""

import time
from typing import Dict, List, Optional

import wifi_utils
import security_utils

class AutomatedNotificationSystem:
    """
    System for sending automated network notifications.

    This class manages periodic notifications about Wi-Fi networks, including
    connection status, newly detected networks, and security recommendations.
    Notifications are only sent when the main application window is not visible
    to prevent notification spam.
    """

    def __init__(self, main_app, system_tray, notification_manager, notification_interval: int = 600):
        """
        Initialize the automated notification system.

        Args:
            main_app: Main application instance with Tkinter after() method
            system_tray: System tray instance for displaying notifications
            notification_manager: Notification manager for displaying in-app notifications
            notification_interval: Notification interval in seconds (default: 600 = 10 minutes)
        """
        self.main_app = main_app
        self.system_tray = system_tray
        self.notification_manager = notification_manager
        self.notification_interval = notification_interval
        self.timer_id = None
        self.last_networks = []
        self.last_notification_time = 0
        self.enabled = False

    def start(self) -> None:
        """
        Start the automated notification system.

        Enables the notification system and schedules the first notification.
        """
        self.enabled = True
        self._schedule_next_notification()

    def stop(self) -> None:
        """
        Stop the automated notification system.

        Disables the notification system and cancels any pending notifications.
        """
        self.enabled = False
        if self.timer_id:
            try:
                self.main_app.after_cancel(self.timer_id)
            except Exception:
                # Tkinter after_cancel can fail if the timer ID is no longer valid
                pass
            self.timer_id = None

    def set_interval(self, interval: int) -> None:
        """
        Set the notification interval in seconds.

        If the notification system is already running, it will be restarted
        with the new interval.

        Args:
            interval: New notification interval in seconds
        """
        self.notification_interval = interval
        # Restart the timer with the new interval
        if self.enabled:
            self.stop()
            self.start()

    def _schedule_next_notification(self) -> None:
        """
        Schedule the next notification.

        Uses the Tkinter after() method to schedule the next notification
        based on the current notification interval.
        """
        if self.enabled:
            self.timer_id = self.main_app.after(
                self.notification_interval * 1000,  # Convert to milliseconds
                self._send_notification
            )

    def _send_notification(self) -> None:
        """
        Send network notifications and reschedule.

        This method is called by the timer and checks if notifications
        should be sent based on the current application state.
        """
        if not self.enabled:
            return

        # Only send notifications if the main window is not visible
        # This prevents notification spam when the user is actively using the app
        if not self.main_app.winfo_viewable():
            # Run network scan and generate notifications
            self._check_and_notify()

        # Schedule the next notification
        self._schedule_next_notification()

    def _check_and_notify(self) -> None:
        """
        Check networks and send appropriate notifications.

        This method performs the following checks:
        1. Connected network status
        2. New networks detection
        3. Security recommendations

        Notifications are throttled to prevent sending too many in a short period.
        """
        try:
            # Throttle notifications - don't send more than one per minute
            current_time = time.time()
            if current_time - self.last_notification_time < 60:
                return

            # Get current connection
            connection = wifi_utils.get_connection_status()

            # Scan for networks
            current_networks = wifi_utils.scan_networks(force_refresh=True)

            # Track if we've sent any notifications this cycle
            notification_sent = False

            # 1. Connected Network Status
            if connection:
                self._notify_connection_status(connection)
                notification_sent = True

            # 2. New Networks Detection
            if self.last_networks and current_networks:
                new_networks = self._detect_new_networks(current_networks)
                if new_networks:
                    self._notify_new_networks(new_networks)
                    notification_sent = True

            # 3. Security Recommendations
            if connection and current_networks and len(current_networks) > 1:
                if self._check_security_recommendations(connection, current_networks):
                    notification_sent = True

            # Update last networks list
            self.last_networks = current_networks

            # Update last notification time if we sent any notifications
            if notification_sent:
                self.last_notification_time = current_time

        except Exception as e:
            print(f"Error in automated notification: {e}")

    def _notify_connection_status(self, connection: Dict) -> None:
        """
        Send notification about current connection status.

        Creates a notification with information about the currently connected
        network, including SSID, security type, signal strength, and security score.

        Args:
            connection: Dictionary containing connection information
        """
        try:
            ssid = connection.get('ssid', 'Unknown')

            # Get network data for security assessment
            network_data = {
                'auth_type': connection.get('details', {}).get('Authentication', 'Unknown'),
                'signal': connection.get('signal', 0),
                'band': connection.get('details', {}).get('Radio type', ''),
                'ssid': ssid
            }

            # Get security score and description
            security_score, security_description, _ = security_utils.get_network_security_score(network_data)

            # Get encryption type and build security info line
            auth_type = network_data.get('auth_type', 'Unknown')
            encryption_type = security_utils.get_encryption_type(auth_type)
            security_info = self._format_security_info(auth_type, encryption_type)

            # Get signal quality
            signal_strength = network_data.get('signal', 0)
            signal_quality = wifi_utils.format_signal_strength(signal_strength).split('(')[0].strip()

            # Build notification message
            title = "Wi-Fi Connection Status"
            message = (
                f"Connected to: {ssid}\n"
                f"Security: {security_info}\n"
                f"Signal: {signal_strength}% ({signal_quality})\n"
                f"Security Score: {security_score}/100 ({security_description})"
            )

            # Send notification
            self._send_system_notification(title, message)

        except Exception as e:
            print(f"Error in connection status notification: {e}")

    def _format_security_info(self, auth_type: str, encryption_type: str) -> str:
        """
        Format security information for display.

        Args:
            auth_type: Authentication type string
            encryption_type: Encryption type string

        Returns:
            Formatted security information string
        """
        if auth_type == 'Unknown' and encryption_type != 'Unknown':
            return encryption_type
        elif auth_type != 'Unknown' and encryption_type == 'Unknown':
            return auth_type
        elif auth_type != 'Unknown' and encryption_type != 'Unknown' and auth_type != encryption_type:
            return f"{auth_type} ({encryption_type})"
        else:
            return auth_type

    def _detect_new_networks(self, current_networks: List[Dict]) -> List[Dict]:
        """
        Detect new networks that weren't present in the last scan.

        Compares the current network list with the previously stored list
        to identify networks that have newly appeared.

        Args:
            current_networks: List of network dictionaries from the current scan

        Returns:
            List of network dictionaries representing newly discovered networks
        """
        if not self.last_networks:
            return []

        # Get SSIDs from last scan
        last_ssids = {network.get('ssid', '') for network in self.last_networks if network.get('ssid')}

        # Find networks with SSIDs not in the last scan
        new_networks = [
            network for network in current_networks
            if network.get('ssid') and network.get('ssid') not in last_ssids
        ]

        return new_networks

    def _notify_new_networks(self, new_networks: List[Dict]) -> None:
        """
        Send notification about newly discovered networks.

        Creates a notification with information about newly discovered networks,
        including their SSID, signal strength, authentication type, and security description.

        Args:
            new_networks: List of network dictionaries representing newly discovered networks
        """
        if not new_networks:
            return

        # Limit to top 3 networks by signal strength
        top_networks = sorted(new_networks, key=lambda x: x.get('signal', 0), reverse=True)[:3]

        # Build notification message
        network_count = len(new_networks)
        network_text = "network" if network_count == 1 else "networks"

        title = "New Wi-Fi Networks Detected"
        message = f"Discovered {network_count} new {network_text}:\n"

        for network in top_networks:
            ssid = network.get('ssid', 'Hidden Network')
            signal = network.get('signal', 0)
            auth_type = network.get('auth_type', 'Unknown')
            _, desc, _ = security_utils.get_network_security_score(network)
            message += f"• {ssid}: {signal}% signal, {auth_type}, {desc}\n"

        if network_count > 3:
            message += f"• And {network_count - 3} more...\n"

        # Send notification
        self._send_system_notification(title, message)

    def _check_security_recommendations(self, connection: Dict, networks: List[Dict]) -> bool:
        """
        Check for security recommendations and notify if needed.

        Analyzes the current network connection and available networks to determine
        if there are better security alternatives available. If better alternatives
        are found, a notification is sent with recommendations.

        Args:
            connection: Dictionary containing current connection information
            networks: List of network dictionaries from the current scan

        Returns:
            True if a recommendation notification was sent, False otherwise
        """
        try:
            current_ssid = connection.get('ssid', '')

            # Find current network in scan results
            current_network = self._find_network_by_ssid(networks, current_ssid)

            if not current_network:
                # Create network object from connection data
                current_network = {
                    'ssid': current_ssid,
                    'auth_type': connection.get('details', {}).get('Authentication', 'Unknown'),
                    'signal': connection.get('signal', 0),
                    'band': connection.get('details', {}).get('Radio type', '')
                }

            # Get security score for current network
            current_score, _, _ = security_utils.get_network_security_score(current_network)

            # Only show recommendations for networks with poor security
            if current_score >= 70:
                return False

            # Find better alternatives
            better_alternatives = self._find_better_alternatives(networks, current_ssid, current_score)

            # Sort by security score (highest first) and limit to top 2
            better_alternatives.sort(key=lambda x: x['score'], reverse=True)
            better_alternatives = better_alternatives[:2]

            if better_alternatives:
                self._send_security_recommendation(current_ssid, current_score, better_alternatives)
                return True

            return False

        except Exception as e:
            print(f"Error in security recommendation: {e}")
            return False

    def _find_network_by_ssid(self, networks: List[Dict], ssid: str) -> Optional[Dict]:
        """
        Find a network in the list by its SSID.

        Args:
            networks: List of network dictionaries
            ssid: SSID to search for

        Returns:
            Network dictionary if found, None otherwise
        """
        for network in networks:
            if network.get('ssid', '') == ssid:
                return network
        return None

    def _find_better_alternatives(self, networks: List[Dict], current_ssid: str, current_score: int) -> List[Dict]:
        """
        Find networks with better security than the current network.

        Args:
            networks: List of network dictionaries
            current_ssid: SSID of the current network
            current_score: Security score of the current network

        Returns:
            List of network dictionaries with better security
        """
        better_alternatives = []

        for network in networks:
            if network.get('ssid', '') == current_ssid:
                continue

            score, desc, _ = security_utils.get_network_security_score(network)
            signal = network.get('signal', 0)

            # Only consider networks with good signal and better security
            if score > current_score + 10 and signal >= 50:
                better_alternatives.append({
                    'ssid': network.get('ssid', 'Hidden Network'),
                    'score': score,
                    'description': desc,
                    'auth_type': network.get('auth_type', 'Unknown'),
                    'signal': signal
                })

        return better_alternatives

    def _send_security_recommendation(self, current_ssid: str, current_score: int, alternatives: List[Dict]) -> None:
        """
        Send a security recommendation notification.

        Args:
            current_ssid: SSID of the current network
            current_score: Security score of the current network
            alternatives: List of alternative networks with better security
        """
        # Build notification message
        title = "Security Recommendation"
        message = (
            f"Your current network ({current_ssid}) has a security score of {current_score}/100.\n"
            f"Better alternatives available:\n"
        )

        for alt in alternatives:
            message += f"• {alt['ssid']}: Score {alt['score']}/100 ({alt['description']})\n"

        message += "Consider switching for improved security."

        # Send notification
        self._send_system_notification(title, message)

    def _send_system_notification(self, title: str, message: str) -> None:
        """
        Send a system notification using the appropriate method.

        Attempts to send a notification using the system tray icon if available,
        otherwise falls back to the notification manager.

        Args:
            title: Notification title
            message: Notification message content
        """
        try:
            # Use system tray notification if available
            if self.system_tray and hasattr(self.system_tray, 'icon') and self.system_tray.icon:
                self.system_tray.icon.notify(message, title)
            # Fall back to notification manager
            elif self.notification_manager:
                self.notification_manager.show_notification(title, message, "info")
        except Exception as e:
            print(f"Error sending notification: {e}")
