from .logger import Logger
import logging


class DefaultLogger(Logger):
    """the implementation for a Logger using logging."""

    enable = False
    def __init__(self):
        self.logger = logging.getLogger('casbin')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        fmt = "%(asctime)s - %(levelname)s - %(message)s"
        formatter = logging.Formatter(fmt)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def enable_log(self, enable):
        """controls whether print the message."""
        self.enable = enable

    def is_enabled(self):
        """returns if logger is enabled."""
        return self.enable

    def write(self, *v):
        """formats using the default formats for its operands and logs the message."""
        if self.enable:
            s = ""
            for vv in v:
                s = s + str(vv)
            self.logger.info(s)

    def writef(self, fmt, *v):
        """formats according to a format specifier and logs the message."""
        if self.enable:
            self.logger.info(fmt, *v)
