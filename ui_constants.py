PADDING_SMALL = 5
PADDING_MEDIUM = 8
PADDING_LARGE = 15
CELL_PADDING = (5, 15)
ROW_PADDING = (8, 8)

COLORS = {
    "primary": ("#1f538d", "#1f538d"),
    "primary_light": ("#3498db", "#3498db"),
    "primary_dark": ("#2980b9", "#2980b9"),
    "primary_hover": ("#2472a4", "#2472a4"),

    "secondary": ("#2ecc71", "#2ecc71"),
    "secondary_dark": ("#27ae60", "#27ae60"),
    "secondary_hover": ("#219a52", "#219a52"),

    "danger": ("#e74c3c", "#e74c3c"),
    "danger_dark": ("#c0392b", "#c0392b"),
    "danger_hover": ("#a93226", "#a93226"),
    "warning": ("#f39c12", "#f39c12"),
    "warning_dark": ("#e67e22", "#e67e22"),

    "bg_light": ("#f0f0f0", "#333333"),
    "bg_medium": ("gray78", "#2d2d2d"),
    "bg_dark": ("gray70", "#1a1a1a"),

    "text_primary": ("black", "white"),
    "text_secondary": ("gray50", "gray70"),
    "text_success": ("#2ecc71", "#2ecc71"),
    "text_warning": ("#f39c12", "#f39c12"),
    "text_danger": ("#e74c3c", "#e74c3c"),

    "security_open": "#FF6B6B",
    "security_wep": "#FFD166",
    "security_wpa": "#f1c40f",
    "security_wpa2": "#06D6A0",
    "security_wpa3": "#118AB2",

    "score_very_secure": "#2ecc71",
    "score_secure": "#27ae60",
    "score_moderate": "#f1c40f",
    "score_low": "#e67e22",
    "score_insecure": "#e74c3c",

    "row_even": ("gray90", "gray17"),
    "row_odd": ("gray85", "gray20"),
    "row_hover": ("gray95", "gray25"),

    "padding_compact": 5,
    "padding_standard": 10,
    "padding_comfortable": 15,
}

FONT_SIZES = {
    "title": 18,
    "subtitle": 16,
    "heading": 15,
    "subheading": 14,
    "normal": 13,
    "small": 12,
    "tiny": 10,
}

DEFAULT_THEMES = ["blue", "dark-blue", "green"]
DEFAULT_APPEARANCE_MODES = ["System", "Light", "Dark"]
INTERFACE_DENSITY_OPTIONS = ["Compact", "Standard", "Comfortable"]
FONT_SIZE_OPTIONS = ["Small", "Medium", "Large", "Extra Large"]
ANIMATION_SPEED_OPTIONS = ["None", "Slow", "Medium", "Fast"]

DEFAULT_SETTINGS = {
    'auto_refresh': False,
    'refresh_interval': 30,
    'scan_depth': 'Standard',
    'background_scanning': False,

    'theme': 'blue',
    'appearance': 'System',
    'corner_radius': 8,
    'animation_enabled': True,
    'animation_speed': 'Medium',
    'interface_density': 'Standard',
    'font_size': 'Medium',
    'font_family': 'Segoe UI',

    'log_retention': 30,
    'auto_logging': True,
    'log_detail_level': 'Standard',

    # System tray settings
    'enable_system_tray': True,
    'minimize_to_tray': True,
    'tray_notifications': True,

    'startup_scan': True,
    'save_window_position': True,
    'window_position': None
}

SECURITY_LEVEL_DESCRIPTIONS = {
    0: "Unsecured - Not recommended",
    1: "Obsolete security - Not recommended",
    2: "Basic security - Moderately secure",
    3: "Enterprise security - Highly secure",
    4: "Personal security - Secure",
    5: "Enterprise security - Maximum security",
    6: "Personal security - Very secure",
    7: "Unknown security type"
}

SECURITY_SCORE_DESCRIPTIONS = {
    "very_secure": "Very Secure",
    "secure": "Secure",
    "moderate": "Moderately Secure",
    "low": "Low Security",
    "insecure": "Insecure"
}
