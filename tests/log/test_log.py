from unittest import TestCase
from casbin import log


class TestLog(TestCase):

    def test_log(self):
        log.get_logger().enable_log(True)
        log.log_print("test log", "print")
        log.log_printf("test log %s", "print")

        self.assertTrue(log.get_logger().is_enabled())
