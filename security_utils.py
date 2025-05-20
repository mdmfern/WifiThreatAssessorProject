"""
Security utilities for Wi-Fi Threat Assessor.

This module provides functions and classes for assessing the security level of Wi-Fi networks,
calculating security scores, and determining appropriate security colors and descriptions.
It includes caching mechanisms to improve performance when processing multiple networks.
"""

from typing import Dict, Optional, Tuple, Any
import time
import hashlib
from ui_constants import COLORS, SECURITY_LEVEL_DESCRIPTIONS, SECURITY_SCORE_DESCRIPTIONS


class SecurityScoreCache:
    """
    Cache for storing and retrieving network security scores.

    This class provides a caching mechanism to avoid recalculating security scores
    for networks that have been recently assessed. Scores are cached for a configurable
    duration (default: 300 seconds).
    """
    _cache: Dict[str, Tuple[float, Tuple[int, str, str]]] = {}
    _cache_duration: int = 300  # Cache duration in seconds

    @classmethod
    def get_cache_key(cls, network_data: Dict[str, Any]) -> str:
        """
        Generate a unique cache key for a network based on its properties.

        Args:
            network_data: Dictionary containing network information

        Returns:
            A unique hash string representing the network
        """
        key_parts = [
            network_data.get('ssid', ''),
            network_data.get('bssid', ''),
            network_data.get('auth_type', ''),
            str(network_data.get('signal', 0)),
            network_data.get('band', '')
        ]
        key_str = ":".join(key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()

    @classmethod
    def get_cached_score(cls, network_data: Dict[str, Any]) -> Optional[Tuple[int, str, str]]:
        """
        Retrieve a cached security score for a network if available and not expired.

        Args:
            network_data: Dictionary containing network information

        Returns:
            Tuple of (score, description, color) if cached and valid, None otherwise
        """
        key = cls.get_cache_key(network_data)
        if key in cls._cache:
            timestamp, score = cls._cache[key]
            if time.time() - timestamp <= cls._cache_duration:
                return score
            # Remove expired cache entry
            del cls._cache[key]
        return None

    @classmethod
    def cache_score(cls, network_data: Dict[str, Any], score: Tuple[int, str, str]) -> None:
        """
        Store a security score in the cache.

        Args:
            network_data: Dictionary containing network information
            score: Tuple of (score, description, color) to cache
        """
        key = cls.get_cache_key(network_data)
        cls._cache[key] = (time.time(), score)

    @classmethod
    def clear_cache(cls) -> None:
        """Clear all cached security scores."""
        cls._cache = {}

def assess_security_level(auth_type: str) -> int:
    """
    Assess the security level of a Wi-Fi network based on its authentication type.

    Args:
        auth_type: The authentication type string (e.g., 'WPA2', 'Open', 'WEP')

    Returns:
        An integer representing the security level:
        0 - Open/None (Insecure)
        1 - WEP (Obsolete)
        2 - WPA/WPA2 (Moderately secure to Secure)
        3 - WPA3/Enterprise (Very secure)
    """
    auth_lower = auth_type.lower()

    security_levels = {
        "open": 0,
        "none": 0,
        "wep": 1,
        "wpa": 2,
        "wpa2": 2,
        "wpa3": 3,
        "enterprise": 3
    }

    # Find all matching security levels in the authentication string
    matching_levels = [
        security_levels.get(key, 2)
        for key in security_levels
        if key in auth_lower
    ]

    # Default to level 2 (WPA2) if no matches found
    if not matching_levels:
        return 2

    # Return the highest security level found
    return max(matching_levels)


def get_security_color(auth_type: str) -> str:
    """
    Get the color associated with a network's security level.

    Args:
        auth_type: The authentication type string

    Returns:
        A color string (hex code) representing the security level
    """
    security_level = assess_security_level(auth_type)

    color_mapping = {
        0: COLORS["security_open"],    # Open/None - Red
        1: COLORS["security_wep"],     # WEP - Yellow/Orange
        2: COLORS["security_wpa2"],    # WPA/WPA2 - Green
        3: COLORS["security_wpa3"]     # WPA3/Enterprise - Blue
    }

    return color_mapping.get(security_level, COLORS["bg_dark"][0])


def get_security_description(auth_type: str) -> str:
    """
    Get a human-readable description of a network's security level.

    Args:
        auth_type: The authentication type string

    Returns:
        A string describing the security level and recommendations
    """
    auth_lower = auth_type.lower()

    # Open/None networks
    if "open" in auth_lower or auth_lower == "none":
        return SECURITY_LEVEL_DESCRIPTIONS[0]
    # WEP networks
    elif "wep" in auth_lower:
        return SECURITY_LEVEL_DESCRIPTIONS[1]
    # WPA (but not WPA2 or WPA3) networks
    elif "wpa" in auth_lower and "wpa2" not in auth_lower and "wpa3" not in auth_lower:
        return SECURITY_LEVEL_DESCRIPTIONS[2]
    # WPA2 (but not WPA3) networks
    elif "wpa2" in auth_lower and "wpa3" not in auth_lower:
        if "enterprise" in auth_lower:
            return SECURITY_LEVEL_DESCRIPTIONS[3]  # WPA2-Enterprise
        else:
            return SECURITY_LEVEL_DESCRIPTIONS[4]  # WPA2-Personal
    # WPA3 networks
    elif "wpa3" in auth_lower:
        if "enterprise" in auth_lower:
            return SECURITY_LEVEL_DESCRIPTIONS[5]  # WPA3-Enterprise
        else:
            return SECURITY_LEVEL_DESCRIPTIONS[6]  # WPA3-Personal
    # Unknown security type
    else:
        return SECURITY_LEVEL_DESCRIPTIONS[7]

def get_network_security_score(network_data: Dict[str, Any]) -> Tuple[int, str, str]:
    """
    Calculate a comprehensive security score for a Wi-Fi network.

    This function evaluates multiple factors including:
    - Authentication type (WPA3, WPA2, WPA, WEP, Open)
    - Enterprise vs Personal security
    - Frequency band (5 GHz vs 2.4 GHz)
    - Signal strength

    Args:
        network_data: Dictionary containing network information

    Returns:
        Tuple containing:
        - Integer score (0-100)
        - String description of security level
        - Color string (hex code) representing security level
    """
    # Check cache first to avoid recalculation
    cached_score = SecurityScoreCache.get_cached_score(network_data)
    if cached_score:
        return cached_score

    score = 0
    auth_type = network_data.get('auth_type', '').lower()

    # Score based on authentication protocol
    if "wpa3" in auth_type:
        score += 40  # WPA3 provides strongest security
    elif "wpa2" in auth_type:
        score += 30  # WPA2 provides good security
    elif "wpa" in auth_type and "wpa2" not in auth_type and "wpa3" not in auth_type:
        score += 20  # WPA provides basic security
    elif "wep" in auth_type:
        score += 10  # WEP provides minimal security

    # Enterprise authentication adds security
    if "enterprise" in auth_type:
        score += 20

    # 5 GHz networks are generally more secure than 2.4 GHz
    if network_data.get('band') == "5 GHz":
        score += 10

    # Better signal strength improves security (less vulnerable to distance attacks)
    signal_strength = network_data.get('signal', 0)
    if isinstance(signal_strength, (int, float)):
        score += (signal_strength / 100) * 30
    else:
        # Default middle value if signal strength is not a number
        score += 15

    # Map score to description and color
    score_ranges = [
        (80, "very_secure", "score_very_secure"),  # 80-100: Very secure
        (60, "secure", "score_secure"),            # 60-79: Secure
        (40, "moderate", "score_moderate"),        # 40-59: Moderately secure
        (20, "low", "score_low"),                  # 20-39: Low security
        (0, "insecure", "score_insecure")          # 0-19: Insecure
    ]

    # Find the appropriate description and color based on score
    for threshold, desc_key, color_key in score_ranges:
        if score >= threshold:
            description = SECURITY_SCORE_DESCRIPTIONS[desc_key]
            color = COLORS[color_key]
            break

    # Cache and return the result
    result = (score, description, color)
    SecurityScoreCache.cache_score(network_data, result)

    return result


def get_encryption_type(auth_type: str) -> str:
    """
    Determine the encryption type used by a Wi-Fi network.

    Args:
        auth_type: The authentication type string

    Returns:
        A string describing the encryption method used
    """
    auth_lower = auth_type.lower()

    # Open networks
    if "open" in auth_lower or auth_lower == "none":
        return "None (Unencrypted)"

    # WEP networks
    elif "wep" in auth_lower:
        return "WEP (Obsolete)"

    # WPA (but not WPA2 or WPA3) networks
    elif "wpa" in auth_lower and "wpa2" not in auth_lower and "wpa3" not in auth_lower:
        if "tkip" in auth_lower:
            return "TKIP (Deprecated)"
        else:
            return "WPA (Deprecated)"

    # WPA2 (but not WPA3) networks
    elif "wpa2" in auth_lower and "wpa3" not in auth_lower:
        if "tkip" in auth_lower:
            return "TKIP/AES Mixed Mode"
        elif "aes" in auth_lower or "ccmp" in auth_lower:
            return "AES-CCMP"
        else:
            return "WPA2"

    # WPA3 networks
    elif "wpa3" in auth_lower:
        return "SAE/AES-GCMP"

    # Unknown encryption type
    else:
        return "Unknown"