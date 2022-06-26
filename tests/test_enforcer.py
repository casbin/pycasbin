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

import os
import time
from unittest import TestCase

import casbin


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


class TestSub:
    def __init__(self, name, age):
        self.name = name
        self.age = age


class TestCaseBase(TestCase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.Enforcer(
            model,
            adapter,
        )


class TestConfig(TestCaseBase):
    def test_enforcer_basic(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "write"))

    def test_enforce_ex_basic(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        self.assertTupleEqual(e.enforce_ex("alice", "data1", "read"), (True, ["alice", "data1", "read"]))
        self.assertTupleEqual(e.enforce_ex("alice", "data2", "read"), (False, []))
        self.assertTupleEqual(e.enforce_ex("bob", "data2", "write"), (True, ["bob", "data2", "write"]))
        self.assertTupleEqual(e.enforce_ex("bob", "data1", "write"), (False, []))

    def test_model_set_load(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        if not isinstance(e, casbin.SyncedEnforcer):
            e.set_model(None)
            self.assertTrue(e.model is None)
            # creating new model
            e.load_model()
            self.assertTrue(e.model is not None)

    def test_enforcer_basic_without_spaces(self):
        e = self.get_enforcer(
            get_examples("basic_model_without_spaces.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    def test_enforce_basic_with_root(self):
        e = self.get_enforcer(get_examples("basic_with_root_model.conf"), get_examples("basic_policy.csv"))
        self.assertTrue(e.enforce("root", "any", "any"))

    def test_enforce_basic_without_resources(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        self.assertTrue(e.enforce("alice", "read"))
        self.assertFalse(e.enforce("alice", "write"))
        self.assertTrue(e.enforce("bob", "write"))
        self.assertFalse(e.enforce("bob", "read"))

    def test_enforce_basic_without_users(self):
        e = self.get_enforcer(
            get_examples("basic_without_users_model.conf"),
            get_examples("basic_without_users_policy.csv"),
        )
        self.assertTrue(e.enforce("data1", "read"))
        self.assertFalse(e.enforce("data1", "write"))
        self.assertTrue(e.enforce("data2", "write"))
        self.assertFalse(e.enforce("data2", "read"))

    def test_enforce_ip_match(self):
        e = self.get_enforcer(get_examples("ipmatch_model.conf"), get_examples("ipmatch_policy.csv"))
        self.assertTrue(e.enforce("192.168.2.1", "data1", "read"))
        self.assertFalse(e.enforce("192.168.3.1", "data1", "read"))

    def test_enforce_key_match(self):
        e = self.get_enforcer(get_examples("keymatch_model.conf"), get_examples("keymatch_policy.csv"))
        self.assertTrue(e.enforce("alice", "/alice_data/test", "GET"))
        self.assertFalse(e.enforce("alice", "/bob_data/test", "GET"))
        self.assertTrue(e.enforce("cathy", "/cathy_data", "GET"))
        self.assertTrue(e.enforce("cathy", "/cathy_data", "POST"))
        self.assertFalse(e.enforce("cathy", "/cathy_data/12", "POST"))

    def test_enforce_key_match2(self):
        e = self.get_enforcer(get_examples("keymatch2_model.conf"), get_examples("keymatch2_policy.csv"))
        self.assertTrue(e.enforce("alice", "/alice_data/resource", "GET"))
        self.assertTrue(e.enforce("alice", "/alice_data2/123/using/456", "GET"))

    def test_enforce_key_match_custom_model(self):
        e = self.get_enforcer(
            get_examples("keymatch_custom_model.conf"),
            get_examples("keymatch2_policy.csv"),
        )

        def custom_function(key1, key2):
            if key1 == "/alice_data2/myid/using/res_id" and key2 == "/alice_data/:resource":
                return True
            elif key1 == "/alice_data2/myid/using/res_id" and key2 == "/alice_data2/:id/using/:resId":
                return True
            return False

        e.add_function("keyMatchCustom", custom_function)

        self.assertFalse(e.enforce("alice", "/alice_data2/myid", "GET"))
        self.assertTrue(e.enforce("alice", "/alice_data2/myid/using/res_id", "GET"))

    def test_enforce_glob_match(self):
        e = self.get_enforcer(
            get_examples("globmatch_model.conf"),
            get_examples("globmatch_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "/alice_data/test_all", "GET"))
        self.assertTrue(e.enforce("alice", "/alice_data/123", "POST"))
        self.assertTrue(e.enforce("bob", "/alice_data/1", "GET"))
        self.assertFalse(e.enforce("bob", "/alice_data/0", "GET"))
        self.assertTrue(e.enforce("bob", "/bob_data/0", "POST"))
        self.assertFalse(e.enforce("bob", "/bob_data/1", "POST"))

    def test_enforce_priority(self):
        e = self.get_enforcer(get_examples("priority_model.conf"), get_examples("priority_policy.csv"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))

    def test_enforce_priority_explicit(self):
        e = self.get_enforcer(
            get_examples("priority_model_explicit.conf"),
            get_examples("priority_policy_explicit.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "read"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "write"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "read"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "write"))

        e.add_policy("1", "bob", "data2", "write", "deny")

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "read"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "write"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "read"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "write"))

    def test_enforce_priority_indeterminate(self):
        e = self.get_enforcer(
            get_examples("priority_model.conf"),
            get_examples("priority_indeterminate_policy.csv"),
        )
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_enforce_subpriority(self):
        e = self.get_enforcer(
            get_examples("subject_priority_model.conf"),
            get_examples("subject_priority_policy.csv"),
        )
        self.assertTrue(e.enforce("jane", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "read"))

    def test_enforce_subpriority_with_domain(self):
        e = self.get_enforcer(
            get_examples("subject_priority_model_with_domain.conf"),
            get_examples("subject_priority_policy_with_domain.csv"),
        )
        self.assertTrue(e.enforce("alice", "data1", "domain1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "domain2", "write"))

    def test_multiple_policy_definitions(self):

        e = self.get_enforcer(
            get_examples("multiple_policy_definitions_model.conf"),
            get_examples("multiple_policy_definitions_policy.csv"),
        )

        enforce_context = e.new_enforce_context("2")
        enforce_context.etype = "e"

        sub1 = TestSub("alice", 70)
        sub2 = TestSub("bob", 30)

        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce(enforce_context, sub1, "/data1", "read"))
        self.assertTrue(e.enforce(enforce_context, sub2, "/data1", "read"))
        self.assertFalse(e.enforce(enforce_context, sub2, "/data1", "write"))
        self.assertFalse(e.enforce(enforce_context, sub1, "/data2", "read"))

    def test_enforce_rbac(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bogus", "data2", "write"))  # test non-existant subject

    def test_enforce_rbac_empty_policy(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("empty_policy.csv"))
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_enforce_rbac_with_deny(self):
        e = self.get_enforcer(
            get_examples("rbac_with_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_enforce_rbac_with_domains(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("alice", "domain1", "data1", "write"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "read"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "write"))

        self.assertFalse(e.enforce("bob", "domain2", "data1", "read"))
        self.assertFalse(e.enforce("bob", "domain2", "data1", "write"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "write"))

    def test_enforce_rbac_with_not_deny(self):
        e = self.get_enforcer(
            get_examples("rbac_with_not_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_enforce_rbac_with_resource_roles(self):
        e = self.get_enforcer(
            get_examples("rbac_with_resource_roles_model.conf"),
            get_examples("rbac_with_resource_roles_policy.csv"),
        )
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    def test_enforce_rbac_with_pattern(self):
        e = self.get_enforcer(
            get_examples("rbac_with_pattern_model.conf"),
            get_examples("rbac_with_pattern_policy.csv"),
        )

        # set matching function to key_match2
        e.add_named_matching_func("g2", casbin.util.key_match2)

        self.assertTrue(e.enforce("alice", "/book/1", "GET"))
        self.assertTrue(e.enforce("alice", "/book/2", "GET"))
        self.assertTrue(e.enforce("alice", "/pen/1", "GET"))
        self.assertFalse(e.enforce("alice", "/pen/2", "GET"))
        self.assertFalse(e.enforce("bob", "/book/1", "GET"))
        self.assertFalse(e.enforce("bob", "/book/2", "GET"))
        self.assertTrue(e.enforce("bob", "/pen/1", "GET"))
        self.assertTrue(e.enforce("bob", "/pen/2", "GET"))

        # replace key_match2 with key_match3
        e.add_named_matching_func("g2", casbin.util.key_match3)
        self.assertTrue(e.enforce("alice", "/book2/1", "GET"))
        self.assertTrue(e.enforce("alice", "/book2/2", "GET"))
        self.assertTrue(e.enforce("alice", "/pen2/1", "GET"))
        self.assertFalse(e.enforce("alice", "/pen2/2", "GET"))
        self.assertFalse(e.enforce("bob", "/book2/1", "GET"))
        self.assertFalse(e.enforce("bob", "/book2/2", "GET"))
        self.assertTrue(e.enforce("bob", "/pen2/1", "GET"))
        self.assertTrue(e.enforce("bob", "/pen2/2", "GET"))

    def test_rbac_with_multipy_matched_pattern(self):
        e = self.get_enforcer(
            get_examples("rbac_with_multiply_matched_pattern.conf"),
            get_examples("rbac_with_multiply_matched_pattern.csv"),
        )

        e.add_named_matching_func("g2", casbin.util.glob_match)

        self.assertTrue(e.enforce("root@localhost", "/", "org.create"))

    def test_enforce_abac_log_enabled(self):
        e = self.get_enforcer(get_examples("abac_model.conf"))
        sub = "alice"
        obj = {"Owner": "alice", "id": "data1"}
        self.assertTrue(e.enforce(sub, obj, "write"))

    def test_abac_with_sub_rule(self):
        e = self.get_enforcer(get_examples("abac_rule_model.conf"), get_examples("abac_rule_policy.csv"))

        sub1 = TestSub("alice", 16)
        sub2 = TestSub("bob", 20)
        sub3 = TestSub("alice", 65)

        self.assertFalse(e.enforce(sub1, "/data1", "read"))
        self.assertFalse(e.enforce(sub1, "/data2", "read"))
        self.assertFalse(e.enforce(sub1, "/data1", "write"))
        self.assertTrue(e.enforce(sub1, "/data2", "write"))

        self.assertTrue(e.enforce(sub2, "/data1", "read"))
        self.assertFalse(e.enforce(sub2, "/data2", "read"))
        self.assertFalse(e.enforce(sub2, "/data1", "write"))
        self.assertTrue(e.enforce(sub2, "/data2", "write"))

        self.assertTrue(e.enforce(sub3, "/data1", "read"))
        self.assertFalse(e.enforce(sub3, "/data2", "read"))
        self.assertFalse(e.enforce(sub3, "/data1", "write"))
        self.assertFalse(e.enforce(sub3, "/data2", "write"))

    def test_abac_with_multiple_sub_rules(self):
        e = self.get_enforcer(
            get_examples("abac_multiple_rules_model.conf"),
            get_examples("abac_multiple_rules_policy.csv"),
        )

        sub1 = TestSub("alice", 16)
        sub2 = TestSub("alice", 20)
        sub3 = TestSub("bob", 65)
        sub4 = TestSub("bob", 35)

        self.assertFalse(e.enforce(sub1, "/data1", "read"))
        self.assertFalse(e.enforce(sub1, "/data2", "read"))
        self.assertFalse(e.enforce(sub1, "/data1", "write"))
        self.assertFalse(e.enforce(sub1, "/data2", "write"))

        self.assertTrue(e.enforce(sub2, "/data1", "read"))
        self.assertFalse(e.enforce(sub2, "/data2", "read"))
        self.assertFalse(e.enforce(sub2, "/data1", "write"))
        self.assertFalse(e.enforce(sub2, "/data2", "write"))

        self.assertFalse(e.enforce(sub3, "/data1", "read"))
        self.assertFalse(e.enforce(sub3, "/data2", "read"))
        self.assertFalse(e.enforce(sub3, "/data1", "write"))
        self.assertFalse(e.enforce(sub3, "/data2", "write"))

        self.assertFalse(e.enforce(sub4, "/data1", "read"))
        self.assertFalse(e.enforce(sub4, "/data2", "read"))
        self.assertFalse(e.enforce(sub4, "/data1", "write"))
        self.assertTrue(e.enforce(sub4, "/data2", "write"))

    def test_matcher_using_in_operator_bracket(self):
        e = self.get_enforcer(
            get_examples("rbac_model_matcher_using_in_op_bracket.conf"),
            get_examples("rbac_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data3", "scribble"))
        self.assertFalse(e.enforce("alice", "data4", "scribble"))


class TestConfigSynced(TestConfig):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.SyncedEnforcer(
            model,
            adapter,
        )

    def test_auto_loading_policy(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        e.start_auto_load_policy(5 / 1000)
        self.assertTrue(e.is_auto_loading_running())
        e.stop_auto_load_policy()
        # thread needs a moment to exit
        time.sleep(10 / 1000)
        self.assertFalse(e.is_auto_loading_running())
