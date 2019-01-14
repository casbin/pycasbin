from unittest import TestCase
from casbin import util


class TestUtil(TestCase):

    def test_remove_comments(self):
        self.assertEqual(util.remove_comments("r.act == p.act # comments"), "r.act == p.act")
        self.assertEqual(util.remove_comments("r.act == p.act#comments"), "r.act == p.act")
        self.assertEqual(util.remove_comments("r.act == p.act###"), "r.act == p.act")
        self.assertEqual(util.remove_comments("### comments"), "")
        self.assertEqual(util.remove_comments("r.act == p.act"), "r.act == p.act")

    def test_escape_assertion(self):
        self.assertEqual(util.escape_assertion("m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"),
                         "m = r_sub == p_sub && r_obj == p_obj && r_act == p_act")

    def test_array_remove_duplicates(self):
        res = util.array_remove_duplicates(["data", "data1", "data2", "data1", "data2", "data3"])
        self.assertEqual(res, ['data', 'data1', 'data2', 'data3'])

    def test_array_to_string(self):
        self.assertEqual(util.array_to_string(['data', 'data1', 'data2', 'data3']), "data, data1, data2, data3")

    def test_params_to_string(self):
        self.assertEqual(util.params_to_string('data', 'data1', 'data2', 'data3'), "data, data1, data2, data3")
