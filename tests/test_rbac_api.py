from tests.test_enforcer import get_examples, get_enforcer
from unittest import TestCase


class TestRbacApi(TestCase):
    def test_get_roles_for_user(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

        self.assertEqual(e.get_roles_for_user('alice'), ['data2_admin'])
        self.assertEqual(e.get_roles_for_user('bob'), [])
        self.assertEqual(e.get_roles_for_user('data2_admin'), [])
        self.assertEqual(e.get_roles_for_user('non_exist'), [])

    def test_get_users_for_role(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

        self.assertEqual(e.get_users_for_role('data2_admin'), ['alice'])
