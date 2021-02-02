from unittest import TestCase

from casbin.model import Model
from tests.test_enforcer import get_examples


class TestPolicy(TestCase):
    def test_get_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ['admin', 'domain1', 'data1', 'read']

        m.add_policy('p', 'p', rule)

        self.assertTrue(m.get_policy('p', 'p') == [rule])

    def test_has_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ['admin', 'domain1', 'data1', 'read']
        m.add_policy('p', 'p', rule)

        self.assertTrue(m.has_policy('p', 'p', rule))

    def test_add_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ['admin', 'domain1', 'data1', 'read']

        self.assertFalse(m.has_policy('p', 'p', rule))

        m.add_policy('p', 'p', rule)
        self.assertTrue(m.has_policy('p', 'p', rule))

    def test_add_role_policy(self):
        m = Model()
        m.load_model(get_examples("rbac_model.conf"))

        p_rule1 = ['alice', 'data1', 'read']
        m.add_policy('p', 'p', p_rule1)
        self.assertTrue(m.has_policy('p', 'p', p_rule1))

        p_rule2 = ['data2_admin', 'data2', 'read']
        m.add_policy('p', 'p', p_rule2)
        self.assertTrue(m.has_policy('p', 'p', p_rule2))

        g_rule = ['alice', 'data2_admin']
        m.add_policy('g', 'g', g_rule)
        self.assertTrue(m.has_policy('g', 'g', g_rule))

        self.assertTrue(m.get_policy('p', 'p') == [p_rule1, p_rule2])
        self.assertTrue(m.get_policy('g', 'g') == [g_rule])

    def test_update_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        old_rule = ['admin', 'domain1', 'data1', 'read']
        new_rule = ['admin', 'domain1', 'data2', 'read']

        m.add_policy('p', 'p', old_rule)
        self.assertTrue(m.has_policy('p', 'p', old_rule))

        m.update_policy('p', 'p', old_rule, new_rule)
        self.assertFalse(m.has_policy('p', 'p', old_rule))
        self.assertTrue(m.has_policy('p', 'p', new_rule))

    def test_update_policies(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        old_rules = [['admin', 'domain1', 'data1', 'read'],
                     ['admin', 'domain1', 'data2', 'read'],
                     ['admin', 'domain1', 'data3', 'read']]
        new_rules = [['admin', 'domain1', 'data4', 'read'],
                     ['admin', 'domain1', 'data5', 'read'],
                     ['admin', 'domain1', 'data6', 'read']]

        m.add_policies('p', 'p', old_rules)

        for old_rule in old_rules:
            self.assertTrue(m.has_policy('p', 'p', old_rule))

        m.update_policies('p', 'p', old_rules, new_rules)

        for old_rule in old_rules:
            self.assertFalse(m.has_policy('p', 'p', old_rule))
        for new_rule in new_rules:
            self.assertTrue(m.has_policy('p', 'p', new_rule))

    def test_remove_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ['admin', 'domain1', 'data1', 'read']
        m.add_policy('p', 'p', rule)
        self.assertTrue(m.has_policy('p', 'p', rule))

        m.remove_policy('p', 'p', rule)
        self.assertFalse(m.has_policy('p', 'p', rule))
        self.assertFalse(m.remove_policy('p', 'p', rule))

    def test_remove_filtered_policy(self):
        m = Model()
        m.load_model(get_examples("rbac_with_domains_model.conf"))

        rule = ['admin', 'domain1', 'data1', 'read']
        m.add_policy('p', 'p', rule)

        res = m.remove_filtered_policy('p', 'p', 1, 'domain1', 'data1')
        self.assertTrue(res)

        res = m.remove_filtered_policy('p', 'p', 1, 'domain1', 'data1')
        self.assertFalse(res)
