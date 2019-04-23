import casbin
import os
from unittest import TestCase


def get_enforcer(model=None, adapter=None, enable_log=False):
    return casbin.Enforcer(
        model,
        adapter,
        enable_log,
    )


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


class TestConfig(TestCase):
    def test_enforcer_basic(self):
        e = get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
            # True,
        )

        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))

    def test_enforce_basic_with_root(self):
        e = get_enforcer(get_examples("basic_with_root_model.conf"), get_examples("basic_policy.csv"))
        self.assertTrue(e.enforce('root', 'any', 'any'))

    def test_enforce_basic_without_resources(self):
        e = get_enforcer(get_examples("basic_without_resources_model.conf"),
                         get_examples("basic_without_resources_policy.csv"))
        self.assertTrue(e.enforce('alice', 'read'))
        self.assertFalse(e.enforce('alice', 'write'))
        self.assertTrue(e.enforce('bob', 'write'))
        self.assertFalse(e.enforce('bob', 'read'))

    def test_enforce_basic_without_users(self):
        e = get_enforcer(get_examples("basic_without_users_model.conf"),
                         get_examples("basic_without_users_policy.csv"))
        self.assertTrue(e.enforce('data1', 'read'))
        self.assertFalse(e.enforce('data1', 'write'))
        self.assertTrue(e.enforce('data2', 'write'))
        self.assertFalse(e.enforce('data2', 'read'))

    def test_enforce_ip_match(self):
        e = get_enforcer(get_examples("ipmatch_model.conf"),
                         get_examples("ipmatch_policy.csv"))
        self.assertTrue(e.enforce('192.168.2.1', 'data1', 'read'))
        self.assertFalse(e.enforce('192.168.3.1', 'data1', 'read'))

    def test_enforce_key_match(self):
        e = get_enforcer(get_examples("keymatch_model.conf"),
                         get_examples("keymatch_policy.csv"))
        self.assertTrue(e.enforce('alice', '/alice_data/test', 'GET'))
        self.assertFalse(e.enforce('alice', '/bob_data/test', 'GET'))
        self.assertTrue(e.enforce('cathy', '/cathy_data', 'GET'))
        self.assertTrue(e.enforce('cathy', '/cathy_data', 'POST'))
        self.assertFalse(e.enforce('cathy', '/cathy_data/12', 'POST'))

    def test_enforce_key_match2(self):
        e = get_enforcer(get_examples("keymatch2_model.conf"),
                         get_examples("keymatch2_policy.csv"))
        self.assertTrue(e.enforce('alice', '/alice_data/resource', 'GET'))
        self.assertTrue(e.enforce('alice', '/alice_data2/123/using/456', 'GET'))

    def test_enforce_priority(self):
        e = get_enforcer(get_examples("priority_model.conf"), get_examples("priority_policy.csv"))
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))

        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertTrue(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))

    def test_enforce_priority_indeterminate(self):
        e = get_enforcer(get_examples("priority_model.conf"), get_examples("priority_indeterminate_policy.csv"))
        self.assertFalse(e.enforce('alice', 'data1', 'read'))

    def test_enforce_rbac(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bogus', 'data2', 'write'))  # test non-existant subject

    def test_enforce_rbac__empty_policy(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("empty_policy.csv"))
        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))

    def test_enforce_rbac_with_deny(self):
        e = get_enforcer(get_examples("rbac_with_deny_model.conf"), get_examples("rbac_with_deny_policy.csv"))
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))

    def test_enforce_rbac_with_domains(self):
        e = get_enforcer(get_examples("rbac_with_domains_model.conf"), get_examples("rbac_with_domains_policy.csv"))
        self.assertTrue(e.enforce('alice', 'domain1', 'data1', 'read'))
        self.assertTrue(e.enforce('alice', 'domain1', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'domain1', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'domain1', 'data2', 'write'))

        self.assertFalse(e.enforce('bob', 'domain2', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'domain2', 'data1', 'write'))
        self.assertTrue(e.enforce('bob', 'domain2', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'domain2', 'data2', 'write'))

    def test_enforce_rbac_with_not_deny(self):
        e = get_enforcer(get_examples("rbac_with_not_deny_model.conf"), get_examples("rbac_with_deny_policy.csv"))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))

    def test_enforce_rbac_with_resource_roles(self):
        e = get_enforcer(get_examples("rbac_with_resource_roles_model.conf"),
                         get_examples("rbac_with_resource_roles_policy.csv"))
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertTrue(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))

    def test_enforce_abac_log_enabled(self):
        e = get_enforcer(get_examples("abac_model.conf"), enable_log=True)
        e.enable_log(True)

        sub = 'alice'
        obj = {'Owner': 'alice', 'id': 'data1'}
        self.assertTrue(e.enforce(sub, obj, 'write'))
