# Wi-Fi Threat Assessor

A comprehensive Windows application for scanning, analyzing, and monitoring Wi-Fi networks for security threats.

## Features

- **Network Scanning**: Scan for available Wi-Fi networks and display detailed information
- **Security Assessment**: Analyze network security and identify potential threats
- **Connection History**: Track and review previously connected networks
- **Speed Testing**: Measure and log internet connection speeds
- **Security Audit Reports**: Generate detailed PDF reports of network security
- **Automated Notifications**: Receive alerts about network security status
- **System Tray Integration**: Run in the background for continuous monitoring

## Requirements

- Windows 10/11 (required for network scanning functionality)
- Python 3.8 or higher
- Wi-Fi adapter (internal or external)
- Dependencies listed in requirements.txt

## Installation

1. Ensure you have Python 3.8 or higher installed
2. Clone this repository
3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the application:

```bash
python main.py
```

### System Tray Feature

The Wi-Fi Threat Assessor includes system tray functionality, allowing it to run in the background while maintaining access to key features.

#### System Tray Options

- **Open Wi-Fi Threat Assessor**: Show the main application window
- **Scan Networks**: Perform a network scan in the background
- **Security Status**: View the security status of your current connection
- **Exit**: Close the application completely

#### Configuration

System tray settings can be configured in the Settings dialog under the "Advanced" tab:

- **Enable System Tray Icon**: Enable or disable the system tray functionality
- **Minimize to Tray on Close**: When enabled, closing the application window will minimize it to the system tray instead of exiting
- **Show Tray Notifications**: Enable or disable notifications from the system tray

## Core Modules

- **main.py**: Main application entry point and UI
- **wifi_utils.py**: Wi-Fi scanning and network information utilities
- **security_utils.py**: Security assessment and scoring algorithms
- **wifi_report_generator.py**: PDF report generation
- **speed_test.py**: Internet speed testing functionality
- **wifi_logger.py**: Connection history logging

## Security Assessment System

The application uses a comprehensive scoring system to evaluate Wi-Fi network security:

### Security Score Calculation (0-100)

1. **Authentication Protocol (0-40 points)**
   - WPA3: 40 points
   - WPA2: 30 points
   - WPA: 20 points
   - WEP: 10 points
   - Open/None: 0 points

2. **Authentication Mode (0-20 points)**
   - Enterprise Authentication: +20 points
   - Personal Authentication: 0 points

3. **Frequency Band (0-10 points)**
   - 5 GHz: +10 points
   - 2.4 GHz: 0 points

4. **Signal Strength (0-30 points)**
   - Calculated as: (signal_strength / 100) * 30
   - Accounts for attack distance vulnerability

### Security Risk Levels

- **Very Secure (80-100)**: Blue color coding
- **Secure (60-79)**: Green color coding
- **Moderately Secure (40-59)**: Yellow color coding
- **Low Security (20-39)**: Orange color coding
- **Insecure (0-19)**: Red color coding

## Speed Test Implementation

The speed test functionality measures:

- **Ping**: Network latency in milliseconds
- **Download Speed**: Data transfer rate from server to client in Mbps
- **Upload Speed**: Data transfer rate from client to server in Mbps

### Test Servers

- **Ping Servers**: speedtest.net, google.com, cloudflare.com
- **Download Test**: Uses Cloudflare, Microsoft, and Ookla test files
- **Upload Test**: Uses Cloudflare and Ookla upload endpoints

### Test Process

1. Server selection and validation
2. Multiple ping measurements with outlier filtering
3. Adaptive download testing with multiple file sizes
4. Upload testing with generated data
5. Result processing and quality assessment

## PDF Security Reports

The application generates comprehensive security audit reports in PDF format with:

1. **Cover Page**: Overall security score and risk level
2. **Table of Contents**: Clickable navigation
3. **Executive Summary**: Key findings and recommendations
4. **Network Details**: Technical specifications of scanned networks
5. **Security Analysis**: Detailed assessment of security vulnerabilities
6. **Recommendations**: Actionable steps to improve security
7. **Technical Details**: In-depth explanation of security protocols

## Technologies Used

- **CustomTkinter**: Modern UI toolkit for the interface
- **Pystray**: System tray integration
- **PIL/Pillow**: Image processing for icons and graphics
- **ReportLab**: PDF generation for security reports
- **Threading**: Multi-threaded operations for responsive UI
- **Socket/urllib**: Network connectivity testing
- **Windows netsh**: Network scanning via command-line interface

## Project Structure

```
Wi-Fi Threat Assessor/
├── main.py                  # Main application entry point
├── base_app.py              # Base application class
├── wifi_utils.py            # Wi-Fi scanning utilities
├── security_utils.py        # Security assessment algorithms
├── security_audit.py        # Security audit implementation
├── security_advisor.py      # Security recommendations
├── wifi_report_generator.py # PDF report generation
├── speed_test.py            # Speed test implementation
├── speed_test_logger.py     # Speed test history logging
├── wifi_logger.py           # Connection history logging
├── notification_manager.py  # Notification system
├── automated_notifications.py # Automated alerts
├── system_tray.py           # System tray integration
├── state_manager.py         # Application state management
├── ui_constants.py          # UI constants and defaults
├── common_utils.py          # Common utility functions
```


