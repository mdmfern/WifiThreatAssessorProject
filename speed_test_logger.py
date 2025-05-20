"""
Speed Test Logger for the Wi-Fi Threat Assessor application.

This module provides functionality for logging and retrieving speed test results.
It implements a singleton pattern to ensure consistent access to the log file
throughout the application. The logger stores test data in a CSV file and provides
methods for filtering and analyzing the results.

Features:
- Log speed test results with network information
- Retrieve logs with various filtering options
- Calculate ratings for download/upload speeds and ping values
- Enforce history length limits based on settings
"""

import os
import csv
import datetime
import socket
import logging
from typing import Dict, List, Optional, Tuple
import common_utils
from ui_constants import COLORS

# Configure logger
logger = logging.getLogger(__name__)

class SpeedTestLogger:
    """
    Singleton class for logging and retrieving speed test results.

    This class implements the singleton pattern to ensure that only one instance
    manages the speed test logs throughout the application. It provides methods
    for logging new test results, retrieving logs with various filters, and
    calculating ratings for speed and ping values.

    The data is stored in a CSV file with columns for timestamp, network information,
    speed metrics, and device details.
    """
    _instance = None

    def __new__(cls, log_file_path: str = "speed_test_logs.csv"):
        """
        Create a new SpeedTestLogger instance or return the existing one.

        Args:
            log_file_path: Path to the CSV file for storing logs

        Returns:
            The singleton SpeedTestLogger instance
        """
        if cls._instance is None:
            cls._instance = super(SpeedTestLogger, cls).__new__(cls)
            cls._instance.log_file_path = log_file_path
            cls._instance._ensure_log_file_exists()
        return cls._instance

    def __init__(self, _=None):
        """
        Initialize method (not used as initialization is done in __new__).

        The singleton pattern uses __new__ for initialization, so this method
        is intentionally empty.
        """
        # Initialization is done in __new__, this is intentionally empty
        pass

    def _ensure_log_file_exists(self) -> None:
        """
        Create log file with headers if it doesn't exist.

        This method checks if the log file exists and creates it with appropriate
        headers if it doesn't. It also ensures that any parent directories exist.
        """
        if not os.path.exists(self.log_file_path):
            # Create parent directory if needed
            log_dir = os.path.dirname(self.log_file_path)
            if log_dir and not os.path.exists(log_dir):
                common_utils.ensure_dir_exists(log_dir)

            # Create the CSV file with headers
            with open(self.log_file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                    'timestamp', 'ssid', 'bssid', 'security_type', 'download_speed',
                    'upload_speed', 'ping', 'server', 'device_name', 'ip_address',
                    'location', 'channel', 'band'
                ])

    def log_speed_test(self, test_data: Dict, settings: Dict = None) -> bool:
        """
        Log a new speed test to the CSV file.

        Args:
            test_data: Dictionary containing speed test results
            settings: Application settings (optional)

        Returns:
            bool: True if logging was successful, False otherwise
        """
        if not test_data:
            logger.warning("Cannot log speed test: empty test data provided")
            return False

        try:
            # Get timestamp or generate a new one
            timestamp = test_data.get('timestamp', common_utils.format_timestamp())

            # Ensure all required fields are present
            required_fields = ['download_speed', 'upload_speed', 'ping']
            missing_fields = [field for field in required_fields if field not in test_data]
            if missing_fields:
                logger.warning(f"Cannot log speed test: missing required fields {missing_fields}")
                return False

            # Add the new log entry
            with open(self.log_file_path, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                    timestamp,
                    test_data.get('ssid', 'Unknown'),
                    test_data.get('bssid', 'Unknown'),
                    test_data.get('security_type', 'Unknown'),
                    test_data.get('download_speed', 0),
                    test_data.get('upload_speed', 0),
                    test_data.get('ping', 0),
                    test_data.get('server', 'Unknown'),
                    test_data.get('device_name', socket.gethostname()),
                    test_data.get('ip_address', 'Unknown'),
                    test_data.get('location', 'Unknown'),
                    test_data.get('channel', 'Unknown'),
                    test_data.get('band', 'Unknown')
                ])

                logger.debug(f"Speed test logged: {timestamp} - Download: {test_data.get('download_speed')} Mbps, "
                           f"Upload: {test_data.get('upload_speed')} Mbps, Ping: {test_data.get('ping')} ms")

            # Check if we need to enforce history length limit
            if settings and 'speed_history_length' in settings:
                self._enforce_history_length(settings['speed_history_length'])

            return True
        except Exception as e:
            logger.error(f"Error logging speed test: {str(e)}")
            return False

    def _enforce_history_length(self, max_entries: int) -> None:
        """
        Ensure the log file doesn't exceed the maximum number of entries.

        This method retrieves all logs, sorts them by timestamp (newest first),
        and keeps only the most recent entries up to the specified maximum.

        Args:
            max_entries: Maximum number of log entries to keep
        """
        if max_entries <= 0:
            logger.debug("History length enforcement skipped: max_entries <= 0")
            return

        try:
            # Get all logs
            logs = self.get_all_logs()

            # If we're under the limit, no action needed
            if len(logs) <= max_entries:
                logger.debug(f"History length enforcement not needed: {len(logs)} <= {max_entries}")
                return

            # Sort by timestamp (newest first)
            logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

            # Keep only the most recent entries
            logs_to_keep = logs[:max_entries]
            removed_count = len(logs) - len(logs_to_keep)

            # Write back the logs to keep
            with open(self.log_file_path, 'w', newline='') as file:
                if logs_to_keep:
                    writer = csv.DictWriter(file, fieldnames=logs_to_keep[0].keys())
                    writer.writeheader()
                    writer.writerows(logs_to_keep)

            logger.info(f"Trimmed speed test history from {len(logs)} to {max_entries} entries (removed {removed_count})")

        except Exception as e:
            logger.error(f"Error enforcing history length: {str(e)}")

    def get_all_logs(self) -> List[Dict]:
        """
        Retrieve all speed test logs.

        Reads all logs from the CSV file and returns them as a list of dictionaries,
        sorted by timestamp with the newest entries first.

        Returns:
            List of dictionaries containing speed test data
        """
        logs = []

        if not os.path.exists(self.log_file_path):
            logger.debug(f"Log file not found: {self.log_file_path}")
            return logs

        try:
            with open(self.log_file_path, 'r', newline='') as file:
                reader = csv.DictReader(file)
                logs = list(reader)

            # Sort by timestamp (newest first)
            logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            logger.debug(f"Retrieved {len(logs)} speed test logs")
        except Exception as e:
            logger.error(f"Error retrieving speed test logs: {str(e)}")
            return []

        return logs

    def get_filtered_logs(self, filter_criteria: Dict = None) -> List[Dict]:
        """
        Retrieve logs matching specific criteria.

        Filters logs based on exact matches for the provided criteria.
        String comparisons are case-insensitive.

        Args:
            filter_criteria: Dictionary of field:value pairs to filter by

        Returns:
            List of dictionaries containing filtered speed test data
        """
        all_logs = self.get_all_logs()

        if not filter_criteria:
            return all_logs

        filtered_logs = []

        # Log the filtering operation
        logger.debug(f"Filtering logs with criteria: {filter_criteria}")

        for log in all_logs:
            match = True
            for key, value in filter_criteria.items():
                if key in log and str(log[key]).lower() != str(value).lower():
                    match = False
                    break

            if match:
                filtered_logs.append(log)

        logger.debug(f"Filter returned {len(filtered_logs)} of {len(all_logs)} logs")
        return filtered_logs

    def get_logs_by_speed_range(self,
                               min_download: Optional[float] = None,
                               max_download: Optional[float] = None,
                               min_upload: Optional[float] = None,
                               max_upload: Optional[float] = None,
                               min_ping: Optional[float] = None,
                               max_ping: Optional[float] = None) -> List[Dict]:
        """
        Retrieve logs within specific speed ranges.

        Filters logs based on download speed, upload speed, and ping values.
        Each parameter is optional - if not provided, that constraint is not applied.

        Args:
            min_download: Minimum download speed in Mbps
            max_download: Maximum download speed in Mbps
            min_upload: Minimum upload speed in Mbps
            max_upload: Maximum upload speed in Mbps
            min_ping: Minimum ping in ms
            max_ping: Maximum ping in ms

        Returns:
            List of dictionaries containing filtered speed test data
        """
        all_logs = self.get_all_logs()
        filtered_logs = []

        # Log the filtering operation
        filter_params = {
            'min_download': min_download,
            'max_download': max_download,
            'min_upload': min_upload,
            'max_upload': max_upload,
            'min_ping': min_ping,
            'max_ping': max_ping
        }
        active_filters = {k: v for k, v in filter_params.items() if v is not None}
        logger.debug(f"Filtering logs by speed range: {active_filters}")

        for log in all_logs:
            try:
                download = float(log.get('download_speed', 0))
                upload = float(log.get('upload_speed', 0))
                ping = float(log.get('ping', 0))

                # Check download speed range
                if min_download is not None and download < min_download:
                    continue
                if max_download is not None and download > max_download:
                    continue

                # Check upload speed range
                if min_upload is not None and upload < min_upload:
                    continue
                if max_upload is not None and upload > max_upload:
                    continue

                # Check ping range
                if min_ping is not None and ping < min_ping:
                    continue
                if max_ping is not None and ping > max_ping:
                    continue

                # If all checks pass, add to filtered logs
                filtered_logs.append(log)
            except (ValueError, TypeError):
                # Skip logs with invalid numeric values
                continue

        logger.debug(f"Speed range filter returned {len(filtered_logs)} of {len(all_logs)} logs")
        return filtered_logs

    def get_logs_by_network(self,
                           ssid: Optional[str] = None,
                           bssid: Optional[str] = None,
                           security_type: Optional[str] = None,
                           band: Optional[str] = None) -> List[Dict]:
        """
        Retrieve logs for specific networks.

        Filters logs based on network properties. SSID uses partial matching
        (case-insensitive), while other parameters use exact matching.

        Args:
            ssid: Network name to filter by (partial match)
            bssid: BSSID to filter by (exact match)
            security_type: Security type to filter by (exact match)
            band: Network band to filter by (exact match)

        Returns:
            List of dictionaries containing filtered speed test data
        """
        all_logs = self.get_all_logs()
        filtered_logs = []

        # Log the filtering operation
        filter_params = {
            'ssid': ssid,
            'bssid': bssid,
            'security_type': security_type,
            'band': band
        }
        active_filters = {k: v for k, v in filter_params.items() if v is not None}
        logger.debug(f"Filtering logs by network properties: {active_filters}")

        for log in all_logs:
            # Check SSID (partial match)
            if ssid and ssid.lower() not in log.get('ssid', '').lower():
                continue

            # Check BSSID (exact match)
            if bssid and bssid.lower() != log.get('bssid', '').lower():
                continue

            # Check security type (exact match)
            if security_type and security_type.lower() != log.get('security_type', '').lower():
                continue

            # Check band (exact match)
            if band and band.lower() != log.get('band', '').lower():
                continue

            # If all checks pass, add to filtered logs
            filtered_logs.append(log)

        logger.debug(f"Network filter returned {len(filtered_logs)} of {len(all_logs)} logs")
        return filtered_logs

    def get_logs_by_server(self, server: str) -> List[Dict]:
        """
        Retrieve logs for tests performed against a specific server.

        Filters logs based on a partial match of the server name (case-insensitive).

        Args:
            server: Server name to filter by (partial match)

        Returns:
            List of dictionaries containing filtered speed test data
        """
        if not server:
            logger.warning("Empty server name provided for filtering")
            return []

        all_logs = self.get_all_logs()
        filtered_logs = []

        logger.debug(f"Filtering logs by server: {server}")

        for log in all_logs:
            if server.lower() in log.get('server', '').lower():
                filtered_logs.append(log)

        logger.debug(f"Server filter returned {len(filtered_logs)} of {len(all_logs)} logs")
        return filtered_logs

    def get_advanced_filtered_logs(self,
                                  date_range: Optional[Tuple[str, str]] = None,
                                  speed_range: Optional[Dict] = None,
                                  network_filter: Optional[Dict] = None,
                                  server: Optional[str] = None) -> List[Dict]:
        """
        Apply multiple filters to retrieve logs.

        This method applies multiple filter types in sequence, progressively narrowing
        down the result set. Each filter is optional and will only be applied if provided.

        Args:
            date_range: Tuple of (start_date, end_date) in format "YYYY-MM-DD"
            speed_range: Dict with keys min_download, max_download, min_upload, max_upload, min_ping, max_ping
            network_filter: Dict with keys ssid, bssid, security_type, band
            server: Server name to filter by (partial match)

        Returns:
            List of dictionaries containing filtered speed test data
        """
        filtered_logs = self.get_all_logs()
        initial_count = len(filtered_logs)

        # Log the advanced filtering operation
        logger.debug(f"Starting advanced filtering with {initial_count} logs")

        # Track which filters are applied
        applied_filters = []

        # Apply date range filter
        if date_range and len(date_range) == 2:
            start_date, end_date = date_range
            if start_date and end_date:
                date_filtered = self.get_logs_by_date_range(start_date, end_date)
                filtered_logs = [log for log in filtered_logs if log in date_filtered]
                applied_filters.append(f"date_range: {start_date} to {end_date}")
                logger.debug(f"After date filter: {len(filtered_logs)} logs")

        # Apply speed range filter
        if speed_range:
            speed_filtered = self.get_logs_by_speed_range(
                min_download=speed_range.get('min_download'),
                max_download=speed_range.get('max_download'),
                min_upload=speed_range.get('min_upload'),
                max_upload=speed_range.get('max_upload'),
                min_ping=speed_range.get('min_ping'),
                max_ping=speed_range.get('max_ping')
            )
            filtered_logs = [log for log in filtered_logs if log in speed_filtered]
            applied_filters.append("speed_range")
            logger.debug(f"After speed filter: {len(filtered_logs)} logs")

        # Apply network filter
        if network_filter:
            network_filtered = self.get_logs_by_network(
                ssid=network_filter.get('ssid'),
                bssid=network_filter.get('bssid'),
                security_type=network_filter.get('security_type'),
                band=network_filter.get('band')
            )
            filtered_logs = [log for log in filtered_logs if log in network_filtered]
            applied_filters.append("network_filter")
            logger.debug(f"After network filter: {len(filtered_logs)} logs")

        # Apply server filter
        if server:
            server_filtered = self.get_logs_by_server(server)
            filtered_logs = [log for log in filtered_logs if log in server_filtered]
            applied_filters.append(f"server: {server}")
            logger.debug(f"After server filter: {len(filtered_logs)} logs")

        logger.info(f"Advanced filtering applied {len(applied_filters)} filters: {', '.join(applied_filters)}")
        logger.info(f"Advanced filtering returned {len(filtered_logs)} of {initial_count} logs")
        return filtered_logs

    def get_logs_by_date_range(self, start_date: str, end_date: str) -> List[Dict]:
        """
        Retrieve logs within a specific date range.

        Filters logs based on their timestamp, including only those that fall
        between the start date (inclusive) and end date (inclusive, to the end of the day).

        Args:
            start_date: Start date in format "YYYY-MM-DD"
            end_date: End date in format "YYYY-MM-DD"

        Returns:
            List of dictionaries containing filtered speed test data
        """
        all_logs = self.get_all_logs()
        filtered_logs = []

        logger.debug(f"Filtering logs by date range: {start_date} to {end_date}")

        try:
            # Parse date strings to datetime objects
            start = datetime.datetime.strptime(start_date, "%Y-%m-%d")
            end = datetime.datetime.strptime(end_date, "%Y-%m-%d")
            # Set end time to end of day for inclusive filtering
            end = end.replace(hour=23, minute=59, second=59)

            for log in all_logs:
                try:
                    log_time = datetime.datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S")
                    if start <= log_time <= end:
                        filtered_logs.append(log)
                except (ValueError, KeyError) as e:
                    # Skip logs with invalid timestamp format
                    logger.debug(f"Skipping log with invalid timestamp: {log.get('timestamp', 'None')}, Error: {str(e)}")
                    continue

            logger.debug(f"Date range filter returned {len(filtered_logs)} of {len(all_logs)} logs")
        except ValueError as e:
            logger.error(f"Error parsing date range: {str(e)}")
            return []

        return filtered_logs

    def get_speed_rating(self, speed: float, is_download: bool = True) -> Tuple[str, str]:
        """
        Get a rating and color for a speed value.

        Evaluates the speed value against predefined thresholds to determine a
        qualitative rating and corresponding color. Different thresholds are used
        for download vs. upload speeds.

        Args:
            speed: Speed value in Mbps
            is_download: True if this is a download speed, False for upload

        Returns:
            Tuple of (rating, color_hex)
        """
        # Ensure speed is a positive number
        speed = max(0, float(speed))

        # Download speed thresholds
        if is_download:
            if speed >= 500:
                return "Exceptional", COLORS["score_very_secure"]
            elif speed >= 250:
                return "Excellent", COLORS["score_very_secure"]
            elif speed >= 100:
                return "Very Good", COLORS["score_secure"]
            elif speed >= 50:
                return "Good", COLORS["score_secure"]
            elif speed >= 25:
                return "Adequate", COLORS["score_moderate"]
            elif speed >= 10:
                return "Fair", COLORS["score_low"]
            else:
                return "Poor", COLORS["score_insecure"]
        # Upload speed thresholds
        else:
            if speed >= 200:
                return "Exceptional", COLORS["score_very_secure"]
            elif speed >= 100:
                return "Excellent", COLORS["score_very_secure"]
            elif speed >= 50:
                return "Very Good", COLORS["score_secure"]
            elif speed >= 25:
                return "Good", COLORS["score_secure"]
            elif speed >= 10:
                return "Adequate", COLORS["score_moderate"]
            elif speed >= 5:
                return "Fair", COLORS["score_low"]
            else:
                return "Poor", COLORS["score_insecure"]

    def get_ping_rating(self, ping: float) -> Tuple[str, str]:
        """
        Get a rating and color for a ping value.

        Evaluates the ping value against predefined thresholds to determine a
        qualitative rating and corresponding color. Lower ping values receive
        better ratings as they indicate lower latency.

        Args:
            ping: Ping value in milliseconds (ms)

        Returns:
            Tuple of (rating, color_hex)
        """
        # Ensure ping is a positive number
        ping = max(0, float(ping))

        # Ping thresholds (lower is better)
        if ping < 10:
            return "Exceptional", COLORS["score_very_secure"]
        elif ping < 20:
            return "Excellent", COLORS["score_very_secure"]
        elif ping < 40:
            return "Very Good", COLORS["score_secure"]
        elif ping < 60:
            return "Good", COLORS["score_secure"]
        elif ping < 100:
            return "Adequate", COLORS["score_moderate"]
        elif ping < 150:
            return "Fair", COLORS["score_low"]
        else:
            return "Poor", COLORS["score_insecure"]

    def delete_log(self, timestamp: str) -> bool:
        """
        Delete a specific log entry by timestamp.

        Removes a log entry with the exact matching timestamp. If multiple entries
        have the same timestamp (unlikely but possible), all matching entries will
        be removed.

        Args:
            timestamp: Timestamp of the log to delete (format: "%Y-%m-%d %H:%M:%S")

        Returns:
            bool: True if deletion was successful, False otherwise
        """
        if not timestamp:
            logger.warning("Cannot delete log: empty timestamp provided")
            return False

        if not os.path.exists(self.log_file_path):
            logger.warning(f"Cannot delete log: log file not found at {self.log_file_path}")
            return False

        try:
            # Get all logs
            logs = self.get_all_logs()

            # Filter out the log with the matching timestamp
            filtered_logs = [log for log in logs if log.get('timestamp') != timestamp]

            # Check if any log was removed
            if len(filtered_logs) == len(logs):
                logger.warning(f"No log found with timestamp: {timestamp}")
                return False  # No log was removed

            removed_count = len(logs) - len(filtered_logs)

            # Write back the filtered logs
            with open(self.log_file_path, 'w', newline='') as file:
                if filtered_logs:
                    writer = csv.DictWriter(file, fieldnames=logs[0].keys())
                    writer.writeheader()
                    writer.writerows(filtered_logs)
                else:
                    # If all logs were removed, just write the header
                    writer = csv.writer(file)
                    writer.writerow([
                        'timestamp', 'ssid', 'bssid', 'security_type', 'download_speed',
                        'upload_speed', 'ping', 'server', 'device_name', 'ip_address',
                        'location', 'channel', 'band'
                    ])

            logger.info(f"Successfully deleted {removed_count} log(s) with timestamp: {timestamp}")
            return True
        except Exception as e:
            logger.error(f"Error deleting log: {str(e)}")
            return False
