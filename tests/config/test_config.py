import os
from casbin.config import Config
from unittest import TestCase


class TestConfig(TestCase):
    def test_new_config(self):
        path = os.path.split(os.path.realpath(__file__))[0]
        path = os.path.abspath(path + "/test.ini")

        config = Config.new_config(path)

        # default::key
        self.assertEqual(config.get("debug"), "true")
        self.assertEqual(config.get("url"), "act.wiki")

        # reids::key
        self.assertEqual(config.get("redis::redis.key"), "push1,push2")
        self.assertEqual(config.get("mysql::mysql.dev.host"), "127.0.0.1")
        self.assertEqual(config.get("mysql::mysql.master.host"), "10.0.0.1")

        # math::key test
        self.assertEqual(config.get("math::math.i64"), "64")
        self.assertEqual(config.get("math::math.f64"), "64.1")

        # other::key test
        self.assertEqual(config.get("other::name"), "ATC自动化测试^-^&($#……#")
        self.assertEqual(config.get("other::key1"), "test key")

        config.set("other::key1", "new test key")

        self.assertEqual(config.get("other::key1"), "new test key")

        config.set("other::key1", "test key")

        self.assertEqual(config.get("multi1::name"), "r.sub==p.sub && r.obj==p.obj")
        self.assertEqual(config.get("multi2::name"), "r.sub==p.sub && r.obj==p.obj")
        self.assertEqual(config.get("multi3::name"), "r.sub==p.sub && r.obj==p.obj")
        self.assertEqual(config.get("multi4::name"), "")
        self.assertEqual(config.get("multi5::name"), "r.sub==p.sub && r.obj==p.obj")

        self.assertEqual(config.get_bool("multi5::name"), False)
        self.assertEqual(
            config.get_string("multi5::name"), "r.sub==p.sub && r.obj==p.obj"
        )
        self.assertEqual(
            config.get_strings("multi5::name"), ["r.sub==p.sub && r.obj==p.obj"]
        )
        with self.assertRaises(ValueError):
            config.get_int("multi5::name")
        with self.assertRaises(ValueError):
            config.get_float("multi5::name")
