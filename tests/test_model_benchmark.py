import casbin
import datetime
import logging
import sys
from tests.test_enforcer import get_examples, TestCaseBase
from unittest import TestCase

log = logging.getLogger(__name__)
loglevel = logging.DEBUG
logging.basicConfig(level=loglevel)


def get_function_name():
    return sys._getframe(2).f_code.co_name


def print_time_diff(start, end, time):
    ms = (end - start).total_seconds() * 1000 / time
    log.debug("%s %f ms" % (get_function_name(), ms))


class TestModelBenchmark(TestCaseBase):
    def test_benchmark_basic_model(self):
        e = self.get_enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))

        time = 10000
        start = datetime.datetime.now()
        for i in range(0, time):
            e.enforce("alice", "data1", "read")
        end = datetime.datetime.now()
        print_time_diff(start, end, time)

    def test_benchmark_rbac_model(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

        time = 10000
        start = datetime.datetime.now()
        for i in range(0, time):
            e.enforce("alice", "data2", "read")
        end = datetime.datetime.now()
        print_time_diff(start, end, time)

class TestModelBenchmarkSynced(TestModelBenchmark):

    def get_enforcer(self, model=None, adapter=None, enable_log=False):
        return casbin.SyncedEnforcer(
            model,
            adapter,
            enable_log,
        )
