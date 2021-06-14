from unittest import TestCase
from casbin.rbac import default_role_manager
from casbin.util import regex_match_func
import time
from concurrent.futures import ThreadPoolExecutor


def get_role_manager():
    return default_role_manager.RoleManager(max_hierarchy_level=10)


class TestDefaultRoleManager(TestCase):
    def test_role(self):
        rm = get_role_manager()
        rm.add_link("u1", "g1")
        rm.add_link("u2", "g1")
        rm.add_link("u3", "g2")
        rm.add_link("u4", "g2")
        rm.add_link("u4", "g3")
        rm.add_link("g1", "g3")

        # Current role inheritance tree:
        #             g3    g2
        #            /  \  /  \
        #          g1    u4    u3
        #         /  \
        #       u1    u2

        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertFalse(rm.has_link("u1", "g2"))
        self.assertTrue(rm.has_link("u1", "g3"))
        self.assertTrue(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))
        self.assertTrue(rm.has_link("u2", "g3"))
        self.assertFalse(rm.has_link("u3", "g1"))
        self.assertTrue(rm.has_link("u3", "g2"))
        self.assertFalse(rm.has_link("u3", "g3"))
        self.assertFalse(rm.has_link("u4", "g1"))
        self.assertTrue(rm.has_link("u4", "g2"))
        self.assertTrue(rm.has_link("u4", "g3"))

        self.assertCountEqual(rm.get_roles("u1"), ["g1"])
        self.assertCountEqual(rm.get_roles("u2"), ["g1"])
        self.assertCountEqual(rm.get_roles("u3"), ["g2"])
        self.assertCountEqual(rm.get_roles("u4"), ["g2", "g3"])
        self.assertCountEqual(rm.get_roles("g1"), ["g3"])
        self.assertCountEqual(rm.get_roles("g2"), [])
        self.assertCountEqual(rm.get_roles("g3"), [])

        rm.delete_link("g1", "g3")
        rm.delete_link("u4", "g2")

        # Current role inheritance tree after deleting the links:
        #             g3    g2
        #               \     \
        #          g1    u4    u3
        #         /  \
        #       u1    u2

        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertFalse(rm.has_link("u1", "g2"))
        self.assertFalse(rm.has_link("u1", "g3"))
        self.assertTrue(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))
        self.assertFalse(rm.has_link("u2", "g3"))
        self.assertFalse(rm.has_link("u3", "g1"))
        self.assertTrue(rm.has_link("u3", "g2"))
        self.assertFalse(rm.has_link("u3", "g3"))
        self.assertFalse(rm.has_link("u4", "g1"))
        self.assertFalse(rm.has_link("u4", "g2"))
        self.assertTrue(rm.has_link("u4", "g3"))

        self.assertCountEqual(rm.get_roles("u1"), ["g1"])
        self.assertCountEqual(rm.get_roles("u2"), ["g1"])
        self.assertCountEqual(rm.get_roles("u3"), ["g2"])
        self.assertCountEqual(rm.get_roles("u4"), ["g3"])
        self.assertCountEqual(rm.get_roles("g1"), [])
        self.assertCountEqual(rm.get_roles("g2"), [])
        self.assertCountEqual(rm.get_roles("g3"), [])

    def test_domain_role(self):
        rm = get_role_manager()
        rm.add_link("u1", "g1", "domain1")
        rm.add_link("u2", "g1", "domain1")
        rm.add_link("u3", "admin", "domain2")
        rm.add_link("u4", "admin", "domain2")
        rm.add_link("u4", "admin", "domain1")
        rm.add_link("g1", "admin", "domain1")

        # Current role inheritance tree:
        #       domain1:admin    domain2:admin
        #            /       \  /       \
        #      domain1:g1     u4         u3
        #         /  \
        #       u1    u2

        self.assertTrue(rm.has_link("u1", "g1", "domain1"))
        self.assertFalse(rm.has_link("u1", "g1", "domain2"))
        self.assertTrue(rm.has_link("u1", "admin", "domain1"))
        self.assertFalse(rm.has_link("u1", "admin", "domain2"))

        self.assertTrue(rm.has_link("u2", "g1", "domain1"))
        self.assertFalse(rm.has_link("u2", "g1", "domain2"))
        self.assertTrue(rm.has_link("u2", "admin", "domain1"))
        self.assertFalse(rm.has_link("u2", "admin", "domain2"))

        self.assertFalse(rm.has_link("u3", "g1", "domain1"))
        self.assertFalse(rm.has_link("u3", "g1", "domain2"))
        self.assertFalse(rm.has_link("u3", "admin", "domain1"))
        self.assertTrue(rm.has_link("u3", "admin", "domain2"))

        self.assertFalse(rm.has_link("u4", "g1", "domain1"))
        self.assertFalse(rm.has_link("u4", "g1", "domain2"))
        self.assertTrue(rm.has_link("u4", "admin", "domain1"))
        self.assertTrue(rm.has_link("u4", "admin", "domain2"))

    def test_clear(self):
        rm = get_role_manager()
        rm.add_link("u1", "g1")
        rm.add_link("u2", "g1")
        rm.add_link("u3", "g2")
        rm.add_link("u4", "g2")
        rm.add_link("u4", "g3")
        rm.add_link("g1", "g3")

        # Current role inheritance tree:
        #             g3    g2
        #            /  \  /  \
        #          g1    u4    u3
        #         /  \
        #       u1    u2

        rm.clear()

        # All data is cleared.
        # No role inheritance now.

        self.assertFalse(rm.has_link("u1", "g1"))
        self.assertFalse(rm.has_link("u1", "g2"))
        self.assertFalse(rm.has_link("u1", "g3"))
        self.assertFalse(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))
        self.assertFalse(rm.has_link("u2", "g3"))
        self.assertFalse(rm.has_link("u3", "g1"))
        self.assertFalse(rm.has_link("u3", "g2"))
        self.assertFalse(rm.has_link("u3", "g3"))
        self.assertFalse(rm.has_link("u4", "g1"))
        self.assertFalse(rm.has_link("u4", "g2"))
        self.assertFalse(rm.has_link("u4", "g3"))

    def test_matching_func(self):
        rm = get_role_manager()
        rm.add_matching_func(regex_match_func)

        rm.add_link("u1", "g1")
        rm.add_link("u3", "g2")
        rm.add_link("u3", "g3")
        rm.add_link(r"u\d+", "g2")

        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertTrue(rm.has_link("u1", "g2"))
        self.assertFalse(rm.has_link("u1", "g3"))

        self.assertFalse(rm.has_link("u2", "g1"))
        self.assertTrue(rm.has_link("u2", "g2"))
        self.assertFalse(rm.has_link("u2", "g3"))

        self.assertFalse(rm.has_link("u3", "g1"))
        self.assertTrue(rm.has_link("u3", "g2"))
        self.assertTrue(rm.has_link("u3", "g3"))

    def test_one_to_many(self):
        rm = get_role_manager()
        rm.add_matching_func(regex_match_func)

        rm.add_link("u1", r"g\d+")
        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertTrue(rm.has_link("u1", "g2"))
        self.assertFalse(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))

    def test_many_to_one(self):
        rm = get_role_manager()
        rm.add_matching_func(regex_match_func)

        rm.add_link(r"u\d+", "g1")
        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertFalse(rm.has_link("u1", "g2"))
        self.assertTrue(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))

    def test_matching_func_order(self):
        rm = get_role_manager()
        rm.add_matching_func(regex_match_func)

        rm.add_link(r"g\d+", "root")
        rm.add_link("u1", "g1")
        self.assertTrue(rm.has_link("u1", "root"))

        rm.clear()

        rm.add_link("u1", "g1")
        rm.add_link(r"g\d+", "root")
        self.assertTrue(rm.has_link("u1", "root"))

        rm.clear()

        rm.add_link("u1", r"g\d+")
        rm.add_link("g1", "root")
        self.assertTrue(rm.has_link("u1", "root"))

        rm.clear()

        rm.add_link("g1", "root")
        rm.add_link("u1", r"g\d+")
        self.assertTrue(rm.has_link("u1", "root"))

    def test_concurrent_has_link_with_matching_func(self):
        def matching_func(*args):
            time.sleep(0.01)
            return regex_match_func(*args)

        rm = get_role_manager()
        rm.add_matching_func(matching_func)
        rm.add_link(r"u\d+", "users")

        def test_has_link(role):
            return rm.has_link(role, "users")

        executor = ThreadPoolExecutor(10)
        futures = [executor.submit(test_has_link, "u" + str(i)) for i in range(10)]
        for future in futures:
            self.assertTrue(future.result())
