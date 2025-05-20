import customtkinter as ctk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import deque
import time


class SignalMonitor(ctk.CTkFrame):
    """
    A real-time signal strength monitoring widget that displays signal strength over time.

    This widget creates a graph that shows the signal strength percentage over the last 60 seconds,
    updating in real-time as new signal strength data is provided. It also includes an information
    section explaining how to interpret the signal strength values.
    """

    # Constants for graph configuration
    HISTORY_LENGTH = 60  # Number of seconds to display in history
    GRAPH_BG_COLOR = '#2b2b2b'
    GRAPH_LINE_COLOR = '#2ecc71'
    GRAPH_GRID_COLOR = 'gray'
    GRAPH_TEXT_COLOR = 'white'

    def __init__(self, master, **kwargs):
        """
        Initialize the SignalMonitor widget.

        Args:
            master: The parent widget
            **kwargs: Additional keyword arguments to pass to the parent CTkFrame
        """
        super().__init__(master, **kwargs)

        # Initialize data storage for signal history
        self.signal_data = deque(maxlen=self.HISTORY_LENGTH)
        self.time_data = deque(maxlen=self.HISTORY_LENGTH)
        self.start_time = time.time()

        # Create and configure the graph display
        self._setup_graph_frame()

        # Create and configure the information section
        self.info_frame = ctk.CTkFrame(self, fg_color=("gray95", "gray17"))
        self.info_frame.pack(fill="x", padx=10, pady=(0, 10))
        self._setup_info_section()

    def _setup_graph_frame(self):
        """Set up the graph frame and matplotlib figure for signal visualization."""
        # Create frame to hold the graph
        self.graph_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.graph_frame.pack(fill="x", expand=True)

        # Create and configure matplotlib figure
        self.fig = Figure(figsize=(8, 3), dpi=100)
        self.fig.patch.set_facecolor(self.GRAPH_BG_COLOR)

        # Configure the plot area
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor(self.GRAPH_BG_COLOR)
        self.ax.tick_params(colors=self.GRAPH_TEXT_COLOR)
        self.ax.grid(True, color=self.GRAPH_GRID_COLOR, alpha=0.3)

        # Set labels and titles
        self.ax.set_title('Real-Time Signal Strength Monitor', color=self.GRAPH_TEXT_COLOR, pad=10)
        self.ax.set_xlabel('Time (seconds)', color=self.GRAPH_TEXT_COLOR)
        self.ax.set_ylabel('Signal Strength (%)', color=self.GRAPH_TEXT_COLOR)
        self.ax.set_ylim(0, 100)

        # Create the canvas to display the figure
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

        # Initialize the line plot
        self.line, = self.ax.plot([], [], color=self.GRAPH_LINE_COLOR, linewidth=2)

    def _setup_info_section(self):
        """Set up the information section explaining signal strength interpretation."""
        # Add section title
        info_title = ctk.CTkLabel(
            self.info_frame,
            text="📊 About Signal Strength Monitor",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#1f538d", "#3498db")
        )
        info_title.pack(anchor="w", padx=15, pady=(10, 5))

        # Define information sections
        sections = [
            ("Updates", "Real-time updates every second showing current signal strength"),
            ("Duration", f"Displays last {self.HISTORY_LENGTH} seconds of signal history"),
            ("Range", "Signal strength shown from 0% (no signal) to 100% (excellent)"),
            ("Interpretation", [
                "Excellent (80-100%): Optimal connection",
                "Good (60-79%): Reliable connection",
                "Fair (40-59%): May experience issues",
                "Poor (20-39%): Unstable connection",
                "Very Poor (0-19%): Unreliable connection"
            ])
        ]

        # Create each section
        for title, content in sections:
            self._create_info_section(title, content)

    def _create_info_section(self, title, content):
        """
        Create a single information section with title and content.

        Args:
            title (str): The title of the information section
            content (str or list): The content to display, either as text or a list of bullet points
        """
        section_frame = ctk.CTkFrame(self.info_frame, fg_color="transparent")
        section_frame.pack(fill="x", padx=15, pady=2)

        # Add section title
        ctk.CTkLabel(
            section_frame,
            text=f"{title}:",
            font=ctk.CTkFont(size=13, weight="bold"),
            width=100,
            anchor="w"
        ).pack(side="left")

        # Handle different content types (text or bullet list)
        if isinstance(content, list):
            content_frame = ctk.CTkFrame(section_frame, fg_color="transparent")
            content_frame.pack(side="left", fill="x", expand=True)

            for item in content:
                ctk.CTkLabel(
                    content_frame,
                    text=f"• {item}",
                    font=ctk.CTkFont(size=12),
                    justify="left",
                    anchor="w"
                ).pack(fill="x", pady=1)
        else:
            ctk.CTkLabel(
                section_frame,
                text=content,
                font=ctk.CTkFont(size=12),
                justify="left",
                anchor="w"
            ).pack(side="left", fill="x", expand=True)

    def update_signal(self, signal_strength):
        """
        Update the signal monitor with a new signal strength reading.

        Args:
            signal_strength (float): The current signal strength as a percentage (0-100)
        """
        # Calculate elapsed time since start
        current_time = time.time() - self.start_time

        # Add new data points
        self.signal_data.append(signal_strength)
        self.time_data.append(current_time)

        # Update the plot with new data
        self.line.set_data(list(self.time_data), list(self.signal_data))

        # Adjust x-axis limits based on elapsed time
        if current_time > self.HISTORY_LENGTH:
            self.ax.set_xlim(current_time - self.HISTORY_LENGTH, current_time)
        else:
            self.ax.set_xlim(0, self.HISTORY_LENGTH)

        # Redraw the canvas to show updates
        self.canvas.draw()