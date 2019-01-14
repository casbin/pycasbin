class Logger:
    """Logger is the logging interface implementation."""

    def enable_log(self, enable):
        """controls whether print the message."""
        pass

    def is_enabled(self):
        """returns if logger is enabled."""
        pass

    def write(self, *v):
        """formats using the default formats for its operands and logs the message."""
        pass

    def writef(self, fmt, *v):
        """formats according to a format specifier and logs the message."""
        pass
