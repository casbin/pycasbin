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

    def test_remove_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ['admin', 'domain1', 'data1', 'read']
        m.add_policy('p', 'p', rule)
        self.assertTrue(m.has_policy('p', 'p', rule))

        m.remove_policy('p', 'p', rule)
        self.assertFalse(m.has_policy('p', 'p', rule))
        self.assertFalse(m.remove_policy('p', 'p', rule))

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