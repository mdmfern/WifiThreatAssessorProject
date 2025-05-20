"""
Security advisor module for Wi-Fi Threat Assessor application.

This module provides security risk information and recommendations for different
types of Wi-Fi networks based on their authentication types.
"""

from typing import Dict, List, Optional
import security_utils
from ui_constants import COLORS


class SecurityAdvisor:
    """
    Provides security risk assessments and recommendations for Wi-Fi networks.

    This class contains static methods and data structures for evaluating
    security risks of different network types and generating appropriate
    security recommendations.
    """

    # Security risk information for different network types
    RISK_INFO = {
        # Open networks (no security)
        "open": {
            "risk_level": "High Risk",
            "title": "Open Network Security Warning",
            "risks": [
                "Man-in-the-middle attacks - Attackers can intercept your data",
                "Packet sniffing - Your unencrypted data can be captured",
                "Evil twin attacks - Fake networks can mimic this one",
                "Data theft - Passwords and personal information are vulnerable",
                "Malware distribution - Easier to inject malicious code"
            ],
            "remedies": [
                "Avoid connecting to open networks when possible",
                "Use a VPN to encrypt your traffic",
                "Disable file sharing and automatic connections",
                "Only visit HTTPS websites",
                "Don't access sensitive information",
                "Keep your firewall enabled",
                "Update security software regularly"
            ],
            "color": COLORS["security_open"]
        },

        # WEP networks (obsolete security)
        "wep": {
            "risk_level": "High Risk",
            "title": "WEP Security Warning",
            "risks": [
                "Easily crackable encryption - WEP can be broken in minutes",
                "Vulnerable to key recovery attacks",
                "No protection against packet forgery or replay attacks",
                "Outdated security standard from 1999",
                "No longer considered secure by security professionals"
            ],
            "remedies": [
                "Upgrade your router to use WPA2 or WPA3 encryption",
                "Replace hardware that only supports WEP",
                "Use a VPN for additional encryption",
                "Avoid transmitting sensitive information",
                "Consider using mobile data instead of connecting"
            ],
            "color": COLORS["security_wep"]
        },

        # WPA networks (basic security)
        "wpa": {
            "risk_level": "Medium Risk",
            "title": "WPA Security Notice",
            "risks": [
                "Vulnerable to TKIP attacks",
                "Susceptible to dictionary attacks on weak passwords",
                "Older implementation with known vulnerabilities",
                "Less secure than newer WPA2/WPA3 standards"
            ],
            "remedies": [
                "Upgrade to WPA2 or WPA3 if possible",
                "Use a strong, complex password",
                "Enable additional security features if available",
                "Keep your devices updated with security patches"
            ],
            "color": COLORS["security_wpa"]
        }
    }

    @staticmethod
    def get_risk_info(network_data: Dict) -> Optional[Dict]:
        """
        Determine security risk information for a given network.

        Args:
            network_data: Dictionary containing network information, must include 'auth_type'

        Returns:
            Dictionary with risk information or None if network is secure or data is invalid
        """
        if not network_data or 'auth_type' not in network_data:
            return None

        auth_type = network_data['auth_type'].lower()
        security_level = security_utils.assess_security_level(auth_type)

        # Return appropriate risk information based on security level and auth type
        if security_level == 0 or "open" in auth_type or auth_type == "none":
            return SecurityAdvisor.RISK_INFO["open"]
        elif security_level == 1 or "wep" in auth_type:
            return SecurityAdvisor.RISK_INFO["wep"]
        elif (security_level == 2 and "wpa" in auth_type and
              "wpa2" not in auth_type and "wpa3" not in auth_type):
            return SecurityAdvisor.RISK_INFO["wpa"]

        # No risk info for secure networks (WPA2/WPA3)
        return None

    @staticmethod
    def get_security_recommendations(network_data: Dict) -> List[str]:
        """
        Get security recommendations for a given network.

        Args:
            network_data: Dictionary containing network information

        Returns:
            List of security recommendation strings
        """
        risk_info = SecurityAdvisor.get_risk_info(network_data)
        if risk_info and "remedies" in risk_info:
            return risk_info["remedies"]

        # Default recommendations for secure networks
        return [
            "Keep your devices updated with security patches",
            "Use a strong, unique password for your WiFi network",
            "Enable additional security features like MAC filtering if available",
            "Regularly check connected devices for unauthorized access"
        ]