# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import TestCase

from casbin.model import Model, FilterablePolicy, filter_policy
from tests.test_enforcer import get_examples


class TestPolicy(TestCase):
    def test_get_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]

        m.add_policy("p", "p", rule)

        self.assertTrue(m.get_policy("p", "p") == [rule])

    def test_has_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]
        m.add_policy("p", "p", rule)

        self.assertTrue(m.has_policy("p", "p", rule))

    def test_add_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]

        self.assertFalse(m.has_policy("p", "p", rule))

        m.add_policy("p", "p", rule)
        self.assertTrue(m.has_policy("p", "p", rule))

    def test_add_role_policy(self):
        m = Model()
        m.load_model(get_examples("rbac_model.conf"))

        p_rule1 = ["alice", "data1", "read"]
        m.add_policy("p", "p", p_rule1)
        self.assertTrue(m.has_policy("p", "p", p_rule1))

        p_rule2 = ["data2_admin", "data2", "read"]
        m.add_policy("p", "p", p_rule2)
        self.assertTrue(m.has_policy("p", "p", p_rule2))

        g_rule = ["alice", "data2_admin"]
        m.add_policy("g", "g", g_rule)
        self.assertTrue(m.has_policy("g", "g", g_rule))

        self.assertTrue(m.get_policy("p", "p") == [p_rule1, p_rule2])
        self.assertTrue(m.get_policy("g", "g") == [g_rule])

    def test_update_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        old_rule = ["admin", "domain1", "data1", "read"]
        new_rule = ["admin", "domain1", "data2", "read"]

        m.add_policy("p", "p", old_rule)
        self.assertTrue(m.has_policy("p", "p", old_rule))

        m.update_policy("p", "p", old_rule, new_rule)
        self.assertFalse(m.has_policy("p", "p", old_rule))
        self.assertTrue(m.has_policy("p", "p", new_rule))

        m = Model()
        m.load_model(get_examples("priority_model_explicit.conf"))

        old_rule = ["1", "admin", "data1", "read", "allow"]
        new_rule = ["1", "admin", "data2", "read", "allow"]

        m.add_policy("p", "p", old_rule)
        self.assertTrue(m.has_policy("p", "p", old_rule))

        m.update_policy("p", "p", old_rule, new_rule)
        self.assertFalse(m.has_policy("p", "p", old_rule))
        self.assertTrue(m.has_policy("p", "p", new_rule))

    def test_update_policies(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        old_rules = [
            ["admin", "domain1", "data1", "read"],
            ["admin", "domain1", "data2", "read"],
            ["admin", "domain1", "data3", "read"],
        ]
        new_rules = [
            ["admin", "domain1", "data4", "read"],
            ["admin", "domain1", "data5", "read"],
            ["admin", "domain1", "data6", "read"],
        ]

        m.add_policies("p", "p", old_rules)

        for old_rule in old_rules:
            self.assertTrue(m.has_policy("p", "p", old_rule))

        m.update_policies("p", "p", old_rules, new_rules)

        for old_rule in old_rules:
            self.assertFalse(m.has_policy("p", "p", old_rule))
        for new_rule in new_rules:
            self.assertTrue(m.has_policy("p", "p", new_rule))

        m = Model()
        m.load_model(get_examples("priority_model_explicit.conf"))

        old_rules = [
            ["1", "admin", "data1", "read", "allow"],
            ["1", "admin", "data2", "read", "allow"],
            ["1", "admin", "data3", "read", "allow"],
        ]
        new_rules = [
            ["1", "admin", "data4", "read", "allow"],
            ["1", "admin", "data5", "read", "allow"],
            ["1", "admin", "data6", "read", "allow"],
        ]

        m.add_policies("p", "p", old_rules)

        for old_rule in old_rules:
            self.assertTrue(m.has_policy("p", "p", old_rule))

        m.update_policies("p", "p", old_rules, new_rules)

        for old_rule in old_rules:
            self.assertFalse(m.has_policy("p", "p", old_rule))
        for new_rule in new_rules:
            self.assertTrue(m.has_policy("p", "p", new_rule))

    def test_remove_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]
        m.add_policy("p", "p", rule)
        self.assertTrue(m.has_policy("p", "p", rule))

        m.remove_policy("p", "p", rule)
        self.assertFalse(m.has_policy("p", "p", rule))
        self.assertFalse(m.remove_policy("p", "p", rule))

    def test_remove_filtered_policy(self):
        m = Model()
        m.load_model(get_examples("rbac_with_domains_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]
        m.add_policy("p", "p", rule)

        res = m.remove_filtered_policy("p", "p", 1, "domain1", "data1")
        self.assertTrue(res)

        res = m.remove_filtered_policy("p", "p", 1, "domain1", "data1")
        self.assertFalse(res)


class TestFilterablePolicy:
    def test_able_to_add_rules(self) -> None:
        policy = FilterablePolicy([2, 1])

        policy.append(["sub", "obj", "read"])

        assert list(policy) == [["sub", "obj", "read"]]

    def test_does_not_add_duplicates(self) -> None:
        policy = FilterablePolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.append(["sub", "obj", "read"])

        assert list(policy) == [["sub", "obj", "read"]]

    def test_can_remove_rules(self) -> None:
        policy = FilterablePolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.remove(["sub", "obj", "read"])

        assert list(policy) == []

    def test_returns_lengtt(self) -> None:
        policy = FilterablePolicy([2, 1])

        policy.append(["sub", "obj", "read"])

        assert len(policy) == 1

    def test_supports_in_keyword(self) -> None:
        policy = FilterablePolicy([2, 1])

        policy.append(["sub", "obj", "read"])

        assert ["sub", "obj", "read"] in policy

    def test_supports_filters(self) -> None:
        policy = FilterablePolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.append(["sub", "obj", "read2"])
        policy.append(["sub", "obj2", "read2"])

        policy.apply_filter("read2", "obj2")

        assert list(policy) == [["sub", "obj2", "read2"]]

    def test_clears_filters(self) -> None:
        policy = FilterablePolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.append(["sub", "obj", "read2"])
        policy.append(["sub", "obj2", "read2"])

        policy.apply_filter("read2", "obj2")
        policy.clear_filter()

        assert list(policy) == [
            ["sub", "obj", "read"],
            ["sub", "obj", "read2"],
            ["sub", "obj2", "read2"],
        ]


class TestContextManager:
    def test_filters_policy(self) -> None:
        policy = FilterablePolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.append(["sub", "obj", "read2"])
        policy.append(["sub", "obj2", "read2"])

        with filter_policy(policy, "read2", "obj2"):
            assert list(policy) == [["sub", "obj2", "read2"]]

        assert list(policy) == [
            ["sub", "obj", "read"],
            ["sub", "obj", "read2"],
            ["sub", "obj2", "read2"],
        ]
