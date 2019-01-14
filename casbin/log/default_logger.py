from .logger import Logger
import logging

logging.basicConfig(level=logging.NOTSET, format="%(asctime)s - %(levelname)s - %(message)s")


class DefaultLogger(Logger):
    """the implementation for a Logger using logging."""

    enable = False

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
            logging.info(s)

    def writef(self, fmt, *v):
        """formats according to a format specifier and logs the message."""
        if self.enable:
            logging.info(fmt, *v)
