"""
Security audit module for Wi-Fi networks.

This module provides functionality to analyze Wi-Fi networks for security vulnerabilities,
generate risk assessments, and provide recommendations for improving network security.
"""

from typing import Dict, List, Any
import logging
import security_utils
from security_advisor import SecurityAdvisor
import common_utils
from ui_constants import COLORS

# Configure logging
logger = logging.getLogger(__name__)


class SecurityAudit:
    """
    Performs security audits on Wi-Fi networks.

    This class analyzes Wi-Fi networks to identify security vulnerabilities,
    assess risk levels, and generate recommendations for improving security.
    """

    def generate_network_audit(self, networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a comprehensive security audit for a list of Wi-Fi networks.

        Args:
            networks: List of network dictionaries containing network information
                     Each network should have at least 'auth_type' and 'ssid' keys

        Returns:
            Dictionary containing audit data including:
            - timestamp: When the audit was generated
            - total_networks: Number of networks analyzed
            - security_summary: Distribution of security types
            - risk_assessment: Analysis of network risks
            - recommendations: Security improvement suggestions
            - detailed_analysis: Per-network security analysis
            - overall_risk_score: Numerical score of environment security
        """
        if not networks:
            return {
                'timestamp': common_utils.format_timestamp(),
                'total_networks': 0,
                'security_summary': {},
                'risk_assessment': {
                    'high_risk_networks': [],
                    'weak_security_networks': [],
                    'strong_security_networks': [],
                    'risk_score': 0,
                    'risk_level': 'Unknown',
                    'risk_color': COLORS["text_primary"][0]
                },
                'recommendations': [],
                'detailed_analysis': [],
                'overall_risk_score': 0
            }

        # Get risk assessment data first to access the overall risk score
        risk_assessment = self._assess_risks(networks)

        audit_data = {
            'timestamp': common_utils.format_timestamp(),
            'total_networks': len(networks),
            'security_summary': self._analyze_security_distribution(networks),
            'risk_assessment': risk_assessment,
            'recommendations': self._generate_recommendations(networks),
            'detailed_analysis': self._analyze_networks(networks),
            'overall_risk_score': risk_assessment.get('risk_score', 0)
        }

        return audit_data

    def _analyze_security_distribution(self, networks: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Analyze the distribution of security types across networks.

        Args:
            networks: List of network dictionaries with 'auth_type' key

        Returns:
            Dictionary with counts of each security type (open, wep, wpa, wpa2, wpa3, enterprise)
        """
        security_counts = {
            'open': 0,
            'wep': 0,
            'wpa': 0,
            'wpa2': 0,
            'wpa3': 0,
            'enterprise': 0
        }

        for network in networks:
            auth_type = network.get('auth_type', '').lower()

            # Determine primary security type (mutually exclusive)
            if 'open' in auth_type or auth_type == 'none':
                security_counts['open'] += 1
            elif 'wep' in auth_type:
                security_counts['wep'] += 1
            elif 'wpa3' in auth_type:
                security_counts['wpa3'] += 1
            elif 'wpa2' in auth_type:
                security_counts['wpa2'] += 1
            elif 'wpa' in auth_type:
                security_counts['wpa'] += 1

            # Enterprise is counted separately as it can be combined with other types
            if 'enterprise' in auth_type:
                security_counts['enterprise'] += 1

        return security_counts

    def _assess_risks(self, networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assess security risks for a list of networks.

        Calculates security scores for each network and categorizes them into risk levels.
        Also calculates an overall risk score for the entire environment.

        Args:
            networks: List of network dictionaries with at least 'auth_type' key

        Returns:
            Dictionary containing:
            - high_risk_networks: List of networks with low security scores
            - weak_security_networks: List of networks with moderate security scores
            - strong_security_networks: List of networks with high security scores
            - risk_score: Average security score across all networks
            - risk_level: Textual description of the overall risk level
            - risk_color: Color code for the risk level
        """
        risks = {
            'high_risk_networks': [],
            'weak_security_networks': [],
            'strong_security_networks': [],
            'risk_score': 0,
            'risk_level': 'Unknown',
            'risk_color': COLORS["text_primary"][0]
        }

        if not networks:
            return risks

        total_score = 0
        valid_networks = 0

        for network in networks:
            try:
                if 'auth_type' not in network:
                    continue

                score, _, color = security_utils.get_network_security_score(network)
                if score > 0:
                    total_score += score
                    valid_networks += 1

                # Categorize network based on security score
                network_info = {
                    'ssid': network.get('ssid', 'Unknown'),
                    'score': score,
                    'color': color
                }

                if score < 30:
                    risks['high_risk_networks'].append(network_info)
                elif score < 60:
                    risks['weak_security_networks'].append(network_info)
                else:
                    risks['strong_security_networks'].append(network_info)
            except Exception as e:
                logger.error(f"Error assessing network: {e}")

        # Calculate average security score
        if valid_networks > 0:
            average_score = total_score / valid_networks
            risks['risk_score'] = round(average_score, 1)
        else:
            risks['risk_score'] = 0

        # Determine overall risk level based on average score
        if risks['risk_score'] >= 80:
            risks['risk_level'] = 'Low Risk Environment'
            risks['risk_color'] = COLORS["score_very_secure"]
        elif risks['risk_score'] >= 60:
            risks['risk_level'] = 'Moderate Risk Environment'
            risks['risk_color'] = COLORS["score_secure"]
        elif risks['risk_score'] >= 40:
            risks['risk_level'] = 'Elevated Risk Environment'
            risks['risk_color'] = COLORS["score_moderate"]
        elif risks['risk_score'] >= 20:
            risks['risk_level'] = 'High Risk Environment'
            risks['risk_color'] = COLORS["score_low"]
        else:
            risks['risk_level'] = 'Critical Risk Environment'
            risks['risk_color'] = COLORS["score_insecure"]

        return risks

    def _generate_recommendations(self, networks: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        Generate security recommendations based on network analysis.

        Analyzes networks for security issues and generates prioritized recommendations
        to improve overall security posture.

        Args:
            networks: List of network dictionaries with 'auth_type' key

        Returns:
            List of recommendation dictionaries, each containing:
            - priority: Importance level (High, Medium, Low)
            - issue: Description of the security issue
            - recommendation: Suggested action to address the issue
        """
        recommendations = []

        # Check for open networks
        open_networks = [n for n in networks if n.get('auth_type', '').lower() in ('open', 'none')
                         or 'open' in n.get('auth_type', '').lower()]
        if open_networks:
            recommendations.append({
                'priority': 'High',
                'issue': 'Open Networks Detected',
                'recommendation': 'Secure all open networks with WPA3 or WPA2 encryption'
            })

        # Check for WEP networks
        wep_networks = [n for n in networks if 'wep' in n.get('auth_type', '').lower()]
        if wep_networks:
            recommendations.append({
                'priority': 'High',
                'issue': 'Obsolete WEP Security',
                'recommendation': 'Upgrade WEP networks to WPA2 or WPA3'
            })

        # Check for non-enterprise networks
        if any('enterprise' not in n.get('auth_type', '').lower() for n in networks):
            recommendations.append({
                'priority': 'Medium',
                'issue': 'Personal Networks',
                'recommendation': 'Consider upgrading to Enterprise security for better management'
            })

        return recommendations

    def _analyze_networks(self, networks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform detailed security analysis on each network.

        Analyzes each network's security configuration, calculates security scores,
        identifies risks, and provides specific recommendations.

        Args:
            networks: List of network dictionaries with network information

        Returns:
            List of detailed analysis dictionaries for each network, containing:
            - Network identifiers (ssid, bssid)
            - Security metrics (score, level, color)
            - Network properties (auth_type, channel, band, signal_strength)
            - Security assessment (risks, recommendations, risk_level)
        """
        detailed_analysis = []

        for network in networks:
            try:
                # Get security score and risk information
                score, description, color = security_utils.get_network_security_score(network)
                risk_info = SecurityAdvisor.get_risk_info(network)

                # Get appropriate recommendations
                if risk_info and 'remedies' in risk_info:
                    recommendations = risk_info['remedies']
                else:
                    recommendations = SecurityAdvisor.get_security_recommendations(network)

                # Create detailed analysis entry
                analysis = {
                    'ssid': network.get('ssid', 'Unknown'),
                    'bssid': network.get('bssid', 'Unknown'),
                    'security_score': score,
                    'security_level': description,
                    'security_color': color,
                    'auth_type': network.get('auth_type', 'Unknown'),
                    'channel': network.get('channel', 'Unknown'),
                    'band': network.get('band', 'Unknown'),
                    'signal_strength': network.get('signal', 0),
                    'risks': risk_info.get('risks', []) if risk_info else [],
                    'recommendations': recommendations,
                    'risk_level': risk_info.get('risk_level', 'Low') if risk_info else 'Low'
                }

                detailed_analysis.append(analysis)
            except Exception as e:
                # Handle errors gracefully with minimal information
                logger.error(f"Error analyzing network {network.get('ssid', 'Unknown')}: {e}")
                detailed_analysis.append({
                    'ssid': network.get('ssid', 'Unknown'),
                    'security_score': 0,
                    'security_level': 'Unknown',
                    'auth_type': network.get('auth_type', 'Unknown'),
                    'error': str(e)
                })

        # Sort networks by security score (ascending - least secure first)
        detailed_analysis.sort(key=lambda x: x.get('security_score', 0))

        return detailed_analysis