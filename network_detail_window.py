"""
Network Detail Window for Wi-Fi Threat Assessor.

This module provides a detailed view of a selected Wi-Fi network,
including security assessment, technical details, and recommendations.
It displays comprehensive information about network security, potential
threats, and actionable recommendations for users.
"""

import customtkinter as ctk
from typing import Dict, List, Tuple, Any
import wifi_utils
import security_utils


class NetworkDetailWindow(ctk.CTkToplevel):
    """
    Detailed view window for a selected Wi-Fi network.

    This class creates a comprehensive window displaying detailed information about
    a Wi-Fi network, including basic information, technical details, security assessment,
    potential threats, connection status, and security recommendations.
    """

    def __init__(self, parent: Any, network: Dict[str, Any]):
        """
        Initialize the network detail window.

        Args:
            parent: Parent window that contains the network list
            network: Dictionary containing network information including ssid, bssid,
                    signal strength, authentication type, and other properties
        """
        super().__init__(parent)

        self.parent = parent
        self.network = network
        self.trusted = False

        self.title(f"Network Details: {network['ssid']}")
        self.geometry("800x700")
        self.minsize(700, 600)

        self.main_frame = ctk.CTkScrollableFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        header_frame = ctk.CTkFrame(self.main_frame, fg_color=("#1f538d", "#1f538d"))
        header_frame.pack(fill="x", pady=(0, 20))

        header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_content.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(
            header_content,
            text=network['ssid'],
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="white"
        ).pack(side="left", pady=5)

        self._create_basic_info_section()
        self._create_technical_details_section()
        self._create_security_assessment_section()
        self._create_threat_indicators_section()
        self._create_connection_status_section()
        self._create_recommendations_section()

    def _create_basic_info_section(self) -> None:
        """
        Create the basic information section of the network detail window.

        Displays fundamental network information including SSID, BSSID,
        signal strength (in percentage and dBm), and security type.
        """
        section = self._add_section("Basic Information")
        signal_percent = self.network['signal']
        signal_dbm = self._calculate_dbm_from_percent(signal_percent)

        basic_fields = [
            ("SSID", self.network['ssid'], False),
            ("BSSID", self.network['bssid'], False),
            ("Signal Strength", f"{signal_percent}% ({signal_dbm} dBm)", False),
            ("Security Type", str(self.network['auth_type']), False)
        ]

        self._add_fields(section, basic_fields)

    def _create_technical_details_section(self) -> None:
        """
        Create the technical details section of the network detail window.

        Displays technical information about the network including channel,
        frequency band, authentication method, encryption type, and network type.
        Uses security_utils to determine the encryption type based on authentication.
        """
        section = self._add_section("Technical Details")

        auth_type = self.network.get('auth_type', 'Unknown')
        auth_parts = auth_type.split() if ' ' in auth_type else [auth_type, 'Unknown']
        authentication = auth_parts[0]

        encryption = security_utils.get_encryption_type(auth_type)

        tech_fields = [
            ("Channel", self.network.get('channel', 'Unknown'), False),
            ("Frequency Band", self.network.get('band', 'Unknown'), False),
            ("Authentication", authentication, False),
            ("Encryption", encryption, False),
            ("Network Type", self.network.get('network_type', 'Infrastructure'), False)
        ]

        self._add_fields(section, tech_fields)

    def _create_security_assessment_section(self) -> None:
        """
        Create the security assessment section of the network detail window.

        Displays a security score (0-100) with color-coded risk level and a detailed
        description of what the score means in terms of network security. Uses the
        security_utils module to calculate the security score based on network properties.
        """
        section = self._add_section("Security Assessment")

        # Get security score, description and color from security_utils
        score, description, color = security_utils.get_network_security_score(self.network)

        # Create frame for score and risk level
        score_frame = ctk.CTkFrame(section, fg_color="transparent")
        score_frame.pack(fill="x", padx=15, pady=5)

        # Display security score with appropriate color
        score_label = ctk.CTkLabel(
            score_frame,
            text=f"Security Score: {score}/100",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=color
        )
        score_label.pack(side="left")

        # Display risk level description
        risk_label = ctk.CTkLabel(
            score_frame,
            text=description,
            font=ctk.CTkFont(size=16),
            text_color=color
        )
        risk_label.pack(side="right")

        # Create frame for detailed description
        description_frame = ctk.CTkFrame(section, fg_color="transparent")
        description_frame.pack(fill="x", padx=15, pady=10)

        # Get and display detailed score description
        score_description = self._get_score_description(score)
        description_label = ctk.CTkLabel(
            description_frame,
            text=score_description,
            font=ctk.CTkFont(size=13),
            wraplength=700,
            justify="left",
            anchor="w"
        )
        description_label.pack(fill="x", padx=0)

    def _get_score_description(self, score: int) -> str:
        """
        Get a detailed description of what a security score means.

        Args:
            score: Security score from 0-100

        Returns:
            A detailed explanation of the security implications of the score
        """
        if score >= 80:
            return ("This network has strong security measures in place. It likely uses modern encryption protocols "
                   "like WPA2 or WPA3, which provide robust protection for your data. The connection is secure for "
                   "most personal and business activities, including banking and sensitive communications.")
        elif score >= 60:
            return ("This network has adequate security but may have some minor vulnerabilities. It likely uses "
                   "WPA2 encryption, which is generally secure but could potentially be compromised by determined "
                   "attackers with specialized tools. Exercise normal caution when transmitting sensitive information.")
        elif score >= 40:
            return ("This network has moderate security concerns. It may use older security protocols or have "
                   "configuration issues that could make it vulnerable to certain types of attacks. Avoid "
                   "transmitting highly sensitive information and consider using a VPN for additional protection.")
        elif score >= 20:
            return ("This network has significant security weaknesses. It likely uses outdated security protocols "
                   "like WEP or has other serious vulnerabilities. Your data could be at risk of interception. "
                   "Avoid using this network for sensitive activities and use a VPN if you must connect.")
        else:
            return ("This network has critical security issues. It may be completely unencrypted (open) or use "
                   "severely compromised security methods. Any data transmitted can be easily intercepted by "
                   "attackers. Avoid using this network if possible, or use a VPN and limit your activities to "
                   "non-sensitive browsing.")

    def _create_threat_indicators_section(self) -> None:
        """
        Create the potential security threats section of the network detail window.

        Identifies and displays potential security threats associated with the network.
        Each threat includes a description, potential impact, and recommended mitigation
        actions. If no threats are detected, displays a message indicating this.
        """
        section = self._add_section("Potential Security Threats")
        threats = self._identify_threats()

        # Display message if no threats detected
        if not threats:
            ctk.CTkLabel(
                section,
                text="No specific threats detected for this network.",
                font=ctk.CTkFont(size=13),
                text_color=("gray50", "gray70")
            ).pack(anchor="w", padx=15, pady=10)
            return

        # Display header for threats section
        header_label = ctk.CTkLabel(
            section,
            text="The following security issues have been identified with this network:",
            font=ctk.CTkFont(size=13, weight="bold"),
            wraplength=700,
            justify="left"
        )
        header_label.pack(anchor="w", padx=15, pady=(5, 10))

        # Create a container for each threat with alternating background colors
        for i, (threat, description, impact, mitigation) in enumerate(threats):
            threat_container = ctk.CTkFrame(
                section,
                fg_color=("gray95", "gray17") if i % 2 == 0 else ("gray90", "gray20"),
                corner_radius=6
            )
            threat_container.pack(fill="x", padx=15, pady=5)

            # Threat title with warning icon
            title_frame = ctk.CTkFrame(threat_container, fg_color="transparent")
            title_frame.pack(fill="x", padx=10, pady=(10, 5))

            ctk.CTkLabel(
                title_frame,
                text=f"⚠️ {threat}",
                font=ctk.CTkFont(size=15, weight="bold"),
                text_color=("#e74c3c", "#ff6b6b")
            ).pack(anchor="w")

            # Threat details content
            content_frame = ctk.CTkFrame(threat_container, fg_color="transparent")
            content_frame.pack(fill="x", padx=10, pady=(0, 10))

            # Issue description
            ctk.CTkLabel(
                content_frame,
                text="Issue:",
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w"
            ).pack(anchor="w", padx=20)

            ctk.CTkLabel(
                content_frame,
                text=description,
                font=ctk.CTkFont(size=13),
                wraplength=650,
                justify="left"
            ).pack(anchor="w", padx=20, pady=(0, 5))

            # Potential impact
            ctk.CTkLabel(
                content_frame,
                text="Potential Impact:",
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w"
            ).pack(anchor="w", padx=20, pady=(5, 0))

            ctk.CTkLabel(
                content_frame,
                text=impact,
                font=ctk.CTkFont(size=13),
                wraplength=650,
                justify="left"
            ).pack(anchor="w", padx=20, pady=(0, 5))

            # Recommended action
            ctk.CTkLabel(
                content_frame,
                text="Recommended Action:",
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w"
            ).pack(anchor="w", padx=20, pady=(5, 0))

            ctk.CTkLabel(
                content_frame,
                text=mitigation,
                font=ctk.CTkFont(size=13),
                wraplength=650,
                justify="left"
            ).pack(anchor="w", padx=20, pady=(0, 5))

    def _create_connection_status_section(self) -> None:
        """
        Create the connection status section of the network detail window.

        Displays information about the current connection status to the network,
        including whether the device is currently connected, IP address (if connected),
        connection time, auto-connect status, and whether the network is hidden.
        Uses wifi_utils to get the current connection status.
        """
        section = self._add_section("Connection Status")

        # Get current connection information
        current_connection = wifi_utils.get_connection_status()

        # Check if currently connected to this network by comparing BSSIDs
        is_connected = (current_connection and
                        current_connection.get('bssid', '').lower() == self.network.get('bssid', '').lower())

        # Determine if network is hidden (no SSID or non-printable characters in SSID)
        is_hidden = not self.network.get('ssid') or any(ord(c) < 32 for c in self.network.get('ssid', ''))

        # Create list of status fields to display
        status_fields = [
            ("Connection Status",
             "Currently Connected" if is_connected else "Not Connected",
             False)
        ]

        # Add additional fields if connected to this network
        if is_connected and current_connection:
            status_fields.append(("IP Address", current_connection.get('ip_address', 'Unknown'), False))

            if 'details' in current_connection and 'Connection time' in current_connection['details']:
                status_fields.append(("Connected Since", current_connection['details']['Connection time'], False))

        # Add auto-connect and hidden network status
        status_fields.append(("Auto-Connect", "Unknown (Requires System API)", False))
        status_fields.append(("Hidden Network", "Yes" if is_hidden else "No", False))

        # Display all status fields
        self._add_fields(section, status_fields)

    def _create_recommendations_section(self) -> None:
        """
        Create the security recommendations section of the network detail window.

        Generates and displays security recommendations based on the network's
        properties and identified threats. Each recommendation includes a title
        and detailed description. If no specific recommendations are available,
        displays a message indicating this.
        """
        section = self._add_section("Security Recommendations")

        # Generate recommendations based on network properties
        recommendations = self._generate_recommendations()

        # Display message if no recommendations available
        if not recommendations:
            ctk.CTkLabel(
                section,
                text="No specific recommendations for this network.",
                font=ctk.CTkFont(size=13),
                text_color=("gray50", "gray70")
            ).pack(anchor="w", padx=15, pady=10)
            return

        # Display each recommendation with lightbulb icon
        for title, description in recommendations:
            rec_frame = ctk.CTkFrame(section, fg_color="transparent")
            rec_frame.pack(fill="x", padx=15, pady=5)

            # Recommendation title with lightbulb icon
            ctk.CTkLabel(
                rec_frame,
                text=f"💡 {title}",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color=("#3498db", "#3498db")
            ).pack(anchor="w")

            # Recommendation description
            ctk.CTkLabel(
                rec_frame,
                text=description,
                font=ctk.CTkFont(size=13),
                wraplength=700,
                justify="left"
            ).pack(anchor="w", padx=20, pady=(0, 5))

    def _add_section(self, title: str) -> ctk.CTkFrame:
        """
        Create a new section in the network detail window with a title and separator.

        Args:
            title: The title text for the section

        Returns:
            A CTkFrame containing the section header and ready for content
        """
        section = ctk.CTkFrame(self.main_frame)
        section.pack(fill="x", pady=10)

        # Create title frame
        title_frame = ctk.CTkFrame(section, fg_color="transparent")
        title_frame.pack(fill="x", padx=15, pady=(10, 5))

        # Add section title
        ctk.CTkLabel(
            title_frame,
            text=title,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=("#1f538d", "#3498db")
        ).pack(anchor="w")

        # Add separator line
        separator = ctk.CTkFrame(section, height=2, fg_color=("gray70", "gray30"))
        separator.pack(fill="x", padx=15, pady=(0, 10))

        return section

    def _add_fields(self, section: ctk.CTkFrame, fields: List[Tuple[str, str, bool]]) -> None:
        """
        Add a list of field name-value pairs to a section.

        Args:
            section: The section frame to add fields to
            fields: List of tuples containing (label, value, is_important)
                   Note: is_important is currently not used but kept for future use
        """
        for label, value, _is_important in fields:
            field_frame = ctk.CTkFrame(section, fg_color="transparent")
            field_frame.pack(fill="x", padx=15, pady=5)

            # Add field label
            ctk.CTkLabel(
                field_frame,
                text=f"{label}:",
                font=ctk.CTkFont(size=14, weight="bold"),
                width=150,
                anchor="w"
            ).pack(side="left")

            # Add field value
            value_label = ctk.CTkLabel(
                field_frame,
                text=str(value),
                font=ctk.CTkFont(size=14),
                anchor="w"
            )
            value_label.pack(side="left", fill="x", expand=True)

    def _calculate_dbm_from_percent(self, percent: int) -> str:
        """
        Convert signal strength percentage to dBm value.

        Args:
            percent: Signal strength as a percentage (0-100)

        Returns:
            String representation of the dBm value
        """
        dbm = -100 + (percent * 0.7)
        return f"{int(dbm)}"

    def _identify_threats(self) -> List[Tuple[str, str, str, str]]:
        """
        Identify potential security threats for the network.

        Analyzes the network's properties to identify security threats such as:
        - Unsecured networks (open/no encryption)
        - Weak encryption (WEP)
        - Outdated encryption (original WPA)
        - Weak signal strength
        - Channel congestion
        - Potential evil twin attacks (multiple networks with same SSID)

        Returns:
            List of tuples containing (threat_name, description, impact, mitigation)
            for each identified threat
        """
        threats = []
        auth_type = self.network.get('auth_type', '').lower()

        # Check for unsecured networks
        if 'open' in auth_type or auth_type == 'none':
            threats.append((
                "Unsecured Network",
                "This network has no encryption or password protection. It is completely open and accessible to anyone.",
                "All data transmitted over this network can be intercepted and read by anyone within range. This includes "
                "passwords, emails, messages, and any other information you send or receive. Attackers can easily "
                "capture your data using freely available tools.",
                "Avoid connecting to open networks whenever possible. If you must connect, use a VPN to encrypt your "
                "traffic, avoid accessing sensitive websites (banking, email, social media), and disconnect as soon as "
                "you're done. Consider using your mobile data instead if security is important."
            ))

        # Check for WEP encryption
        elif 'wep' in auth_type:
            threats.append((
                "Weak Encryption (WEP)",
                "This network uses WEP encryption, which is severely outdated and was officially deprecated in 2004.",
                "WEP encryption can be cracked in minutes using readily available tools. Once cracked, attackers can "
                "view all your network traffic, potentially capturing sensitive information like passwords and personal "
                "data. They may also be able to join the network and attack connected devices.",
                "Avoid using this network for any sensitive activities. If possible, connect to a different network with "
                "stronger security. If you own this network, upgrade your router immediately to use WPA2 or WPA3 encryption. "
                "If you must use this network, employ a VPN to add an additional layer of encryption."
            ))

        # Check for original WPA (without WPA2 or WPA3)
        elif 'wpa' in auth_type and 'wpa2' not in auth_type and 'wpa3' not in auth_type:
            threats.append((
                "Outdated Encryption (WPA)",
                "This network uses the original WPA protocol, which has been superseded by more secure versions.",
                "WPA has known vulnerabilities that can be exploited to decrypt network traffic. While not as easily "
                "broken as WEP, determined attackers with specialized tools can potentially compromise WPA security "
                "and access your data. This puts sensitive information at risk.",
                "Use a VPN when connecting to this network to add an extra layer of encryption. Avoid transmitting "
                "highly sensitive information if possible. If you own this network, upgrade your router firmware or "
                "hardware to support WPA2 or WPA3 encryption."
            ))

        # Check for weak signal strength
        if self.network.get('signal', 0) < 30:
            threats.append((
                "Weak Signal",
                "This network has a very low signal strength, indicating you're far from the access point or there are "
                "significant obstacles blocking the signal.",
                "Weak signals can cause frequent disconnections, slow speeds, and packet loss. From a security perspective, "
                "weak connections are more vulnerable to certain attacks like deauthentication, where attackers can more "
                "easily disrupt your connection. Your device may also automatically switch to less secure networks if the "
                "signal becomes too weak.",
                "Move closer to the access point or consider using a WiFi extender to improve signal quality. Be aware that "
                "your device might automatically connect to other networks if this signal drops further. Consider using a "
                "wired connection if available and security is important."
            ))

        # Check for channel congestion
        channel = self.network.get('channel')
        if channel and self._is_congested_channel(channel):
            threats.append((
                "Channel Congestion",
                f"This network is operating on channel {channel}, which is heavily used in your area.",
                "Channel congestion can lead to poor performance, intermittent connectivity, and increased susceptibility "
                "to interference. In congested environments, your connection may be less reliable and more vulnerable to "
                "certain types of attacks that exploit network instability.",
                "If you own this network, consider changing to a less congested channel in your router settings. Channels "
                "1, 6, and 11 on 2.4GHz are recommended as they don't overlap. For 5GHz networks, there are more non-overlapping "
                "channels available. Use a WiFi analyzer app to identify the least congested channels in your area."
            ))

        # Check for potential evil twin attacks
        if hasattr(self.parent, 'networks_frame') and hasattr(self.parent.networks_frame, 'network_data'):
            all_networks = self.parent.networks_frame.network_data
            current_ssid = self.network.get('ssid', '')
            current_bssid = self.network.get('bssid', '').lower()

            # Find networks with same SSID but different BSSID
            potential_twins = [
                n for n in all_networks
                if n.get('ssid', '') == current_ssid and n.get('bssid', '').lower() != current_bssid
            ]

            if potential_twins:
                threats.append((
                    "Potential Evil Twin Attack",
                    f"Detected {len(potential_twins)} other network(s) with the same name (SSID) but different identifiers (BSSID).",
                    "Evil Twin attacks involve attackers creating fake access points that mimic legitimate networks. If you "
                    "connect to a malicious twin, attackers can intercept all your network traffic, potentially capturing "
                    "passwords, personal information, and other sensitive data. They may also redirect you to fake websites "
                    "to steal your credentials.",
                    "Verify the network before connecting by checking with the network owner for the correct BSSID (MAC address). "
                    "Use HTTPS websites whenever possible, as they provide encryption even on compromised networks. Consider using "
                    "a VPN for an additional layer of security. Be suspicious if you're unexpectedly disconnected and prompted to "
                    "reconnect or re-enter credentials."
                ))

        return threats

    def _is_congested_channel(self, channel: str) -> bool:
        """
        Determine if a Wi-Fi channel is congested.

        A channel is considered congested if:
        1. There are 3 or more other networks using the same channel, or
        2. It's one of the commonly congested channels (1, 6, 11) on 2.4GHz

        Args:
            channel: The channel number to check

        Returns:
            True if the channel is congested, False otherwise
        """
        commonly_congested = [1, 6, 11]  # Common 2.4GHz channels that are often congested

        # Check if there are multiple networks on the same channel
        if hasattr(self.parent, 'networks_frame') and hasattr(self.parent.networks_frame, 'network_data'):
            all_networks = self.parent.networks_frame.network_data

            # Find networks on the same channel (excluding this network)
            networks_on_same_channel = [
                n for n in all_networks
                if n.get('channel') == channel and n.get('bssid', '').lower() != self.network.get('bssid', '').lower()
            ]

            # Consider congested if 3 or more networks on same channel
            if len(networks_on_same_channel) >= 3:
                return True

        # Also consider congested if it's one of the commonly congested channels
        return int(channel) in commonly_congested

    def _generate_recommendations(self) -> List[Tuple[str, str]]:
        """
        Generate security recommendations based on network properties.

        Creates a list of security recommendations tailored to the specific network,
        based on its authentication type, signal strength, and other properties.
        Includes general recommendations that apply to all networks, as well as
        specific recommendations for different security types and situations.

        Returns:
            List of tuples containing (recommendation_title, detailed_description)
        """
        recommendations = []
        auth_type = self.network.get('auth_type', '').lower()
        signal = self.network.get('signal', 0)

        # General recommendations for all networks
        recommendations.append(
            ("Keep Your Device Updated",
             "Regularly update your operating system, browsers, and security software to protect against known vulnerabilities.")
        )

        recommendations.append(
            ("Use HTTPS Websites",
             "Look for 'https://' and the padlock icon in your browser to ensure your connection to websites is encrypted, "
             "even if the network itself isn't secure.")
        )

        # Recommendations for open/unsecured networks
        if 'open' in auth_type or auth_type == 'none':
            recommendations.append(
                ("Use a VPN Service",
                 "When connecting to unsecured networks, always use a VPN (Virtual Private Network) to encrypt all your "
                 "internet traffic. This creates a secure tunnel for your data even on insecure networks.")
            )

            recommendations.append(
                ("Limit Sensitive Activities",
                 "Avoid accessing sensitive accounts (banking, email, social media) or transmitting personal information "
                 "when connected to open networks. Wait until you're on a secure network for these activities.")
            )

            recommendations.append(
                ("Disable File Sharing",
                 "Turn off file sharing and network discovery features on your device when connected to public networks "
                 "to prevent unauthorized access to your files.")
            )

            recommendations.append(
                ("Use Mobile Data Instead",
                 "If available, consider using your mobile data connection instead of an open WiFi network for better security.")
            )

        # Recommendations for WEP networks
        elif 'wep' in auth_type:
            recommendations.append(
                ("Avoid This Network",
                 "If possible, avoid connecting to networks using WEP encryption as they can be easily compromised. "
                 "Look for networks with WPA2 or WPA3 security instead.")
            )

            recommendations.append(
                ("Use a VPN",
                 "If you must connect to this network, use a VPN to add an additional layer of encryption to your traffic, "
                 "protecting your data from potential eavesdropping.")
            )

            # Additional recommendation if this appears to be user's home network
            if self._is_likely_home_network():
                recommendations.append(
                    ("Upgrade Router Security",
                     "If this is your home or business network, upgrade your router immediately to use WPA2 or WPA3 encryption. "
                     "WEP has been deprecated since 2004 and is not considered secure.")
                )

        # Recommendations for original WPA (without WPA2/WPA3)
        elif 'wpa' in auth_type and 'wpa2' not in auth_type and 'wpa3' not in auth_type:
            recommendations.append(
                ("Consider More Secure Networks",
                 "When possible, connect to networks using WPA2 or WPA3 encryption instead of the original WPA protocol, "
                 "which has known vulnerabilities.")
            )

            recommendations.append(
                ("Use a VPN for Sensitive Activities",
                 "Add an extra layer of protection by using a VPN when transmitting sensitive information over this network.")
            )

            # Additional recommendation if this appears to be user's home network
            if self._is_likely_home_network():
                recommendations.append(
                    ("Upgrade Router Firmware",
                     "If this is your network, check if your router supports WPA2 or WPA3 and upgrade the firmware or "
                     "settings. If your router only supports WPA, consider replacing it with a newer model.")
                )

        # Recommendations for weak signal
        if signal < 30:
            recommendations.append(
                ("Improve Signal Strength",
                 "Move closer to the access point or consider using a WiFi extender to improve connection quality. "
                 "Weak signals can lead to disconnections and make certain attacks easier.")
            )

        # Recommendations for potential evil twin situations
        if self._has_potential_evil_twins():
            recommendations.append(
                ("Verify Network Identity",
                 "Multiple networks with the same name were detected. Verify you're connecting to the legitimate network "
                 "by checking the BSSID (MAC address) with the network owner or by using the network only in locations "
                 "you trust.")
            )

        return recommendations

    def _is_likely_home_network(self) -> bool:
        """
        Determine if this network is likely to be the user's home network.

        Uses several heuristics to guess if this is a home network:
        1. Very strong signal strength (>80%)
        2. Currently connected to this network
        3. SSID contains common home network naming patterns

        Returns:
            True if the network is likely a home network, False otherwise
        """
        # Strong signal suggests proximity to the access point
        if self.network.get('signal', 0) > 80:
            return True

        # If currently connected, likely to be a trusted network
        current_connection = wifi_utils.get_connection_status()
        if current_connection and current_connection.get('bssid', '').lower() == self.network.get('bssid', '').lower():
            return True

        # Check for common home network naming patterns
        home_patterns = ['home', 'house', 'family', 'private', 'mynet', 'netgear', 'linksys', 'asus', 'tplink', 'dlink']
        ssid = self.network.get('ssid', '').lower()

        for pattern in home_patterns:
            if pattern in ssid:
                return True

        return False

    def _has_potential_evil_twins(self) -> bool:
        """
        Check if there are potential evil twin networks with the same SSID.

        An evil twin is a malicious network that mimics a legitimate network's SSID
        but has a different BSSID (MAC address). This method checks if there are
        any networks with the same SSID but different BSSIDs.

        Returns:
            True if potential evil twins are detected, False otherwise
        """
        if hasattr(self.parent, 'networks_frame') and hasattr(self.parent.networks_frame, 'network_data'):
            all_networks = self.parent.networks_frame.network_data
            current_ssid = self.network.get('ssid', '')
            current_bssid = self.network.get('bssid', '').lower()

            # Find networks with same SSID but different BSSID
            potential_twins = [
                n for n in all_networks
                if n.get('ssid', '') == current_ssid and n.get('bssid', '').lower() != current_bssid
            ]

            return len(potential_twins) > 0

        return False