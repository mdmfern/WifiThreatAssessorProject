"""
State Manager for Wi-Fi Threat Assessor.

This module provides a centralized state management system for the application,
implementing the observer pattern for UI updates. It maintains application state
and notifies registered components when state changes occur, enabling reactive
UI updates and decoupled component communication.
"""

from typing import Dict, List, Callable, Any


class StateManager:
    """
    Centralized state manager implementing the observer pattern.

    This class manages application state and notifies observers when state changes.
    It provides methods to get and set state values, register and unregister observers,
    and notify observers when state changes occur. The state is maintained as a dictionary
    with predefined keys for various application states.
    """

    def __init__(self):
        """
        Initialize the state manager with default state values.

        Sets up the initial application state with default values and
        initializes empty observer lists for each state key.

        Initial state includes:
        - networks: List of detected Wi-Fi networks
        - current_connection: Currently connected network
        - scanning: Whether a network scan is in progress
        - auto_refresh: Whether automatic refresh is enabled
        - auto_refresh_interval: Time between automatic refreshes (seconds)
        - current_tab: Currently active tab in the UI
        - last_scan_time: Timestamp of the last network scan
        - network_count: Number of networks detected
        """
        self._state = {
            'networks': [],
            'current_connection': None,
            'scanning': False,
            'auto_refresh': False,
            'auto_refresh_interval': 30,
            'current_tab': 'networks',
            'last_scan_time': None,
            'network_count': 0
        }

        # Dictionary to store observers for each state key
        self._observers: Dict[str, List[Callable[[Any], None]]] = {}

        # Initialize observer lists for each state key
        for key in self._state:
            self._observers[key] = []

    def get_state(self, key: str) -> Any:
        """
        Get the current value of a state item.

        Retrieves the current value for the specified state key.
        Returns None if the key doesn't exist in the state dictionary.

        Args:
            key: The state key to retrieve

        Returns:
            The current value of the state item or None if key doesn't exist
        """
        return self._state.get(key)

    def set_state(self, key: str, value: Any) -> None:
        """
        Set the value of a state item and notify observers.

        Updates the value of the specified state key and notifies all registered
        observers if the value has changed. Raises KeyError if the key doesn't
        exist in the state dictionary.

        Args:
            key: The state key to update
            value: The new value for the state item

        Raises:
            KeyError: If the specified key doesn't exist in the state dictionary
        """
        if key not in self._state:
            raise KeyError(f"Invalid state key: {key}")

        # Only update and notify if the value has changed
        if self._state[key] != value:
            self._state[key] = value
            self._notify_observers(key, value)

    def update_state(self, updates: Dict[str, Any]) -> None:
        """
        Update multiple state items at once.

        This is a batch update method that allows updating multiple state items
        in a single call. Only valid keys that exist in the state will be updated,
        and observers will only be notified if values actually change.

        Args:
            updates: Dictionary of state updates with keys matching state keys
        """
        for key, value in updates.items():
            if key in self._state and self._state[key] != value:
                self._state[key] = value
                self._notify_observers(key, value)

    def register_observer(self, key: str, callback: Callable[[Any], None]) -> None:
        """
        Register an observer for a state item.

        Adds a callback function to be called whenever the specified state key
        changes. If the key doesn't exist in the observers dictionary, it will
        be created. Each callback is only registered once per key.

        Args:
            key: The state key to observe
            callback: Function to call when the state changes
        """
        if key not in self._observers:
            self._observers[key] = []

        if callback not in self._observers[key]:
            self._observers[key].append(callback)

    def unregister_observer(self, key: str, callback: Callable[[Any], None]) -> None:
        """
        Unregister an observer for a state item.

        Removes a previously registered callback function from the observers list
        for the specified state key. If the key or callback doesn't exist,
        no action is taken.

        Args:
            key: The state key being observed
            callback: Function to remove from observers
        """
        if key in self._observers and callback in self._observers[key]:
            self._observers[key].remove(callback)

    def _notify_observers(self, key: str, value: Any) -> None:
        """
        Notify all observers of a state change.

        Calls each registered observer callback with the new value.
        Catches and logs any exceptions that occur during notification
        to prevent observer errors from affecting the application.

        Args:
            key: The state key that changed
            value: The new value of the state item
        """
        if key in self._observers:
            for callback in self._observers[key]:
                try:
                    callback(value)
                except Exception as e:
                    # Log the error but continue notifying other observers
                    # Using print for now, but could be replaced with proper logging
                    print(f"Error notifying observer for {key}: {str(e)}")

    def register_multi_observer(self, keys: List[str], callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Register an observer for multiple state items.

        Creates and registers individual observers for each key that will call the
        provided callback with a dictionary containing all requested state values.

        Args:
            keys: List of state keys to observe
            callback: Function to call when any of the states change
        """
        def create_observer():
            def observer(_):
                # Create a dictionary of all requested keys and their current values
                state_subset = {key: self._state[key] for key in keys}
                callback(state_subset)
            return observer

        # Create a single observer function to be used for all keys
        observer = create_observer()

        # Register the observer for each valid key
        for key in keys:
            if key in self._state:
                self.register_observer(key, observer)

    def clear_observers(self) -> None:
        """
        Clear all observers from all state keys.

        This method removes all registered observer callbacks from all state keys.
        Useful when shutting down the application or when a component that has
        registered multiple observers is being destroyed.
        """
        for key in self._observers:
            self._observers[key] = []

    def get_full_state(self) -> Dict[str, Any]:
        """
        Get the complete current state.

        Returns a deep copy of the entire state dictionary to prevent
        accidental modification of the internal state.

        Returns:
            Dictionary containing all state items
        """
        return self._state.copy()
