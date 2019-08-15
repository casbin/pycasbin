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

    def test_has_role_for_user(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

        self.assertTrue(e.has_role_for_user('alice', 'data2_admin'))
        self.assertFalse(e.has_role_for_user('alice', 'data1_admin'))

    def test_add_role_for_user(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.add_role_for_user('alice', 'data1_admin')
        self.assertEqual(e.get_roles_for_user('alice'), ['data2_admin', 'data1_admin'])

    def test_delete_role_for_user(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.add_role_for_user('alice', 'data1_admin')
        self.assertEqual(e.get_roles_for_user('alice'), ['data2_admin', 'data1_admin'])

        e.delete_role_for_user('alice', 'data1_admin')
        self.assertEqual(e.get_roles_for_user('alice'), ['data2_admin'])

    def test_delete_roles_for_user(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.delete_roles_for_user('alice')
        self.assertEqual(e.get_roles_for_user('alice'), [])

    def test_delete_user(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.delete_user('alice')
        self.assertEqual(e.get_roles_for_user('alice'), [])

    def test_delete_role(self):
        e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.delete_role('data2_admin')
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))

    def test_delete_permission(self):
        e = get_enforcer(get_examples("basic_without_resources_model.conf"),
                         get_examples("basic_without_resources_policy.csv"))
        e.delete_permission('read')
        self.assertFalse(e.enforce('alice', 'read'))
        self.assertFalse(e.enforce('alice', 'write'))
        self.assertFalse(e.enforce('bob', 'read'))
        self.assertTrue(e.enforce('bob', 'write'))

    def test_add_permission_for_user(self):
        e = get_enforcer(get_examples("basic_without_resources_model.conf"),
                         get_examples("basic_without_resources_policy.csv"))
        e.delete_permission('read')
        e.add_permission_for_user('bob', 'read')
        self.assertTrue(e.enforce('bob', 'read'))
        self.assertTrue(e.enforce('bob', 'write'))

    def test_delete_permission_for_user(self):
        e = get_enforcer(get_examples("basic_without_resources_model.conf"),
                         get_examples("basic_without_resources_policy.csv"))
        e.add_permission_for_user('bob', 'read')

        self.assertTrue(e.enforce('bob', 'read'))
        e.delete_permission_for_user('bob', 'read')
        self.assertFalse(e.enforce('bob', 'read'))
        self.assertTrue(e.enforce('bob', 'write'))

    def test_delete_permissions_for_user(self):
        e = get_enforcer(get_examples("basic_without_resources_model.conf"),
                         get_examples("basic_without_resources_policy.csv"))
        e.delete_permissions_for_user('bob')

        self.assertTrue(e.enforce('alice', 'read'))
        self.assertFalse(e.enforce('bob', 'read'))
        self.assertFalse(e.enforce('bob', 'write'))

    def test_get_permissions_for_user(self):
        e = get_enforcer(get_examples("basic_without_resources_model.conf"),
                         get_examples("basic_without_resources_policy.csv"))
        self.assertEqual(e.get_permissions_for_user('alice'), [['alice', 'read']])

    def test_has_permission_for_user(self):
        e = get_enforcer(get_examples("basic_without_resources_model.conf"),
                         get_examples("basic_without_resources_policy.csv"))
        self.assertTrue(e.has_permission_for_user('alice', *['read']))
        self.assertFalse(e.has_permission_for_user('alice', *['write']))
        self.assertFalse(e.has_permission_for_user('bob', *['read']))
        self.assertTrue(e.has_permission_for_user('bob', *['write']))
