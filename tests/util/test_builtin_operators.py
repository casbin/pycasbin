from unittest import TestCase
from casbin import util


class TestBuiltinOperators(TestCase):

    def test_key_match(self):
        self.assertTrue(util.key_match_func("/foo", "/foo"))
        self.assertTrue(util.key_match_func("/foo", "/foo*"))
        self.assertFalse(util.key_match_func("/foo", "/foo/*"))
        self.assertFalse(util.key_match_func("/foo/bar", "/foo"))
        self.assertTrue(util.key_match_func("/foo/bar", "/foo*"))
        self.assertTrue(util.key_match_func("/foo/bar", "/foo/*"))
        self.assertFalse(util.key_match_func("/foobar", "/foo"))
        self.assertTrue(util.key_match_func("/foobar", "/foo*"))
        self.assertFalse(util.key_match_func("/foobar", "/foo/*"))

    def test_key_match2(self):
        self.assertTrue(util.key_match2_func("/foo", "/foo"))
        self.assertTrue(util.key_match2_func("/foo", "/foo*"))
        self.assertFalse(util.key_match2_func("/foo", "/foo/*"))
        self.assertTrue(util.key_match2_func("/foo/bar", "/foo"))  # different with KeyMatch.
        self.assertTrue(util.key_match2_func("/foo/bar", "/foo*"))
        self.assertTrue(util.key_match2_func("/foo/bar", "/foo/*"))
        self.assertTrue(util.key_match2_func("/foobar", "/foo"))  # different with KeyMatch.
        self.assertTrue(util.key_match2_func("/foobar", "/foo*"))
        self.assertFalse(util.key_match2_func("/foobar", "/foo/*"))

        self.assertFalse(util.key_match2_func("/", "/:resource"))
        self.assertTrue(util.key_match2_func("/resource1", "/:resource"))
        self.assertFalse(util.key_match2_func("/myid", "/:id/using/:resId"))
        self.assertTrue(util.key_match2_func("/myid/using/myresid", "/:id/using/:resId"))

        self.assertFalse(util.key_match2_func("/proxy/myid", "/proxy/:id/*"))
        self.assertTrue(util.key_match2_func("/proxy/myid/", "/proxy/:id/*"))
        self.assertTrue(util.key_match2_func("/proxy/myid/res", "/proxy/:id/*"))
        self.assertTrue(util.key_match2_func("/proxy/myid/res/res2", "/proxy/:id/*"))
        self.assertTrue(util.key_match2_func("/proxy/myid/res/res2/res3", "/proxy/:id/*"))
        self.assertFalse(util.key_match2_func("/proxy/", "/proxy/:id/*"))

        self.assertTrue(util.key_match2_func("/alice", "/:id"))
        self.assertTrue(util.key_match2_func("/alice/all", "/:id/all"))
        self.assertFalse(util.key_match2_func("/alice", "/:id/all"))
        self.assertFalse(util.key_match2_func("/alice/all", "/:id"))
