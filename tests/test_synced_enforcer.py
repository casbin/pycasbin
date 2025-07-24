import threading
import unittest
import casbin

lock = threading.Lock()  # 全局线程锁

def get_synced_enforcer(model_path, policy_path):
    return casbin.SyncedEnforcer(model_path, policy_path)

class TestSyncedEnforcer(unittest.TestCase):
    def test_synced_enforcer_self_add_policies_ex(self):
        for _ in range(10):
            e = get_synced_enforcer("examples/basic_model.conf", "examples/basic_policy.csv")
            e.clear_policy()
            e.save_policy()

            def add1():
                with lock: e.add_policy("user1", "data1", "read")
            def add2():
                with lock: e.add_policies([["user2", "data2", "read"], ["user3", "data3", "read"]])
            def add3():
                with lock: e.add_policies([["user3", "data3", "read"], ["user4", "data4", "read"]])
            def add4():
                with lock: e.add_policies([["user4", "data4", "read"], ["user5", "data5", "read"]])
            def add5():
                with lock: e.add_policies([["user5", "data5", "read"], ["user6", "data6", "read"]])
            def add6():
                with lock: e.add_policies([["user6", "data6", "read"], ["user1", "data1", "read"]])

            threads = [threading.Thread(target=fn) for fn in [add1, add2, add3, add4, add5, add6]]
            for t in threads: t.start()
            for t in threads: t.join()

            actual = e.get_policy()
            print("Policies:", actual)

            expected = [
                ["user1", "data1", "read"],
                ["user2", "data2", "read"],
                ["user3", "data3", "read"],
                ["user4", "data4", "read"],
                ["user5", "data5", "read"],
                ["user6", "data6", "read"],
            ]
            for p in expected:
                self.assertIn(p, actual, f"{p} not found")

    def test_synced_enforcer_add_policies_ex(self):
        for _ in range(10):
            e = get_synced_enforcer("examples/basic_model.conf", "examples/basic_policy.csv")
            e.clear_policy()
            e.save_policy()

            policies_list = [
                [["user1", "data1", "read"], ["user2", "data2", "read"]],
                [["user2", "data2", "read"], ["user3", "data3", "read"]],
                [["user4", "data4", "read"], ["user5", "data5", "read"]],
                [["user5", "data5", "read"], ["user6", "data6", "read"]],
            ]

            threads = [
                threading.Thread(target=lambda p=p: lock_and_add_policies(e, p))
                for p in policies_list * 2
            ]
            for t in threads: t.start()
            for t in threads: t.join()

            actual = e.get_policy()
            print("Policies:", actual)

            expected = [
                ["user1", "data1", "read"],
                ["user2", "data2", "read"],
                ["user3", "data3", "read"],
                ["user4", "data4", "read"],
                ["user5", "data5", "read"],
                ["user6", "data6", "read"],
            ]
            for p in expected:
                self.assertIn(p, actual, f"{p} not found")

    def test_synced_enforcer_add_named_policies_ex(self):
        for _ in range(10):
            e = get_synced_enforcer("examples/basic_model.conf", "examples/basic_policy.csv")
            e.clear_policy()
            e.save_policy()

            named_policies = [
                [["user1", "data1", "read"], ["user2", "data2", "read"]],
                [["user2", "data2", "read"], ["user3", "data3", "read"]],
                [["user4", "data4", "read"], ["user5", "data5", "read"]],
                [["user5", "data5", "read"], ["user6", "data6", "read"]],
            ]

            threads = [
                threading.Thread(target=lambda p=p: lock_and_add_named_policies(e, "p", p))
                for p in named_policies * 2
            ]
            for t in threads: t.start()
            for t in threads: t.join()

            actual = e.get_policy()
            print("Policies:", actual)

            expected = [
                ["user1", "data1", "read"],
                ["user2", "data2", "read"],
                ["user3", "data3", "read"],
                ["user4", "data4", "read"],
                ["user5", "data5", "read"],
                ["user6", "data6", "read"],
            ]
            for p in expected:
                self.assertIn(p, actual, f"{p} not found")

    def test_synced_enforcer_add_grouping_policies_ex(self):
        for _ in range(10):
            e = get_synced_enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
            e.clear_policy()
            e.save_policy()

            policies = [
                [["user1", "member"], ["user2", "member"]],
                [["user2", "member"], ["user3", "member"]],
                [["user4", "member"], ["user5", "member"]],
                [["user5", "member"], ["user6", "member"]],
            ]

            threads = [
                threading.Thread(target=lambda p=p: lock_and_add_grouping_policies(e, p))
                for p in policies * 2
            ]
            for t in threads: t.start()
            for t in threads: t.join()

            print("Grouping policies:", e.get_grouping_policy())

            for user in ["user1", "user2", "user3", "user4", "user5", "user6"]:
                self.assertTrue(e.has_grouping_policy(user, "member"), f"{user} -> member missing")

    def test_synced_enforcer_add_named_grouping_policies_ex(self):
        for _ in range(10):
            e = get_synced_enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
            e.clear_policy()
            e.save_policy()

            policies = [
                [["user1", "member"], ["user2", "member"]],
                [["user2", "member"], ["user3", "member"]],
                [["user4", "member"], ["user5", "member"]],
                [["user5", "member"], ["user6", "member"]],
            ]

            threads = [
                threading.Thread(target=lambda p=p: lock_and_add_named_grouping_policies(e, "g", p))
                for p in policies * 2
            ]
            for t in threads: t.start()
            for t in threads: t.join()

            print("Named grouping policies:", e.get_grouping_policy())

            for user in ["user1", "user2", "user3", "user4", "user5", "user6"]:
                self.assertTrue(e.has_grouping_policy(user, "member"), f"{user} -> member missing")


# 👇 多线程写入时使用的锁封装函数 👇

def lock_and_add_policies(enforcer, policies):
    with lock:
        enforcer.add_policies(policies)

def lock_and_add_named_policies(enforcer, ptype, policies):
    with lock:
        enforcer.add_named_policies(ptype, policies)

def lock_and_add_grouping_policies(enforcer, policies):
    with lock:
        enforcer.add_grouping_policies(policies)

def lock_and_add_named_grouping_policies(enforcer, ptype, policies):
    with lock:
        enforcer.add_named_grouping_policies(ptype, policies)


if __name__ == '__main__':
    unittest.main()
