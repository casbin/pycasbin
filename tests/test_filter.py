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

import casbin
from unittest import TestCase
from tests.test_enforcer import get_examples


class Filter:
    # P,G are strings
    P = []
    G = []


class TestFilteredAdapter(TestCase):
    def test_init_filtered_adapter(self):
        adapter = casbin.persist.adapters.FilteredAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        self.assertFalse(e.has_policy(["admin", "domain1", "data1", "read"]))

    def test_load_filtered_policy(self):
        adapter = casbin.persist.adapters.FilteredAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        try:
            e.load_policy()
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if not e.is_filtered:
            raise RuntimeError("adapter did not set the filtered flag correctly")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

        with self.assertRaises(RuntimeError):
            e.save_policy()

        with self.assertRaises(RuntimeError):
            e.get_adapter().save_policy(e.get_model())

    def test_append_filtered_policy(self):
        adapter = casbin.persist.adapters.FilteredAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        try:
            e.load_policy()
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if not e.is_filtered:
            raise RuntimeError("adapter did not set the filtered flag correctly")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

        filter.P = ["", "domain2"]
        filter.G = ["", "", "domain2"]
        try:
            e.load_increment_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_filtered_policy_invalid_filter(self):
        adapter = casbin.persist.adapters.FilteredAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = ["", "domain1"]

        with self.assertRaises(RuntimeError):
            e.load_filtered_policy(filter)

    def test_filtered_policy_empty_filter(self):
        adapter = casbin.persist.adapters.FilteredAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        try:
            e.load_filtered_policy(None)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if e.is_filtered():
            raise RuntimeError("adapter did not reset the filtered flag correctly")

        try:
            e.save_policy()
        except:
            raise RuntimeError("unexpected error in SavePolicy")

    def test_unsupported_filtered_policy(self):
        e = casbin.Enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        with self.assertRaises(ValueError):
            e.load_filtered_policy(filter)

    def test_filtered_adapter_empty_filepath(self):
        adapter = casbin.persist.adapters.FilteredAdapter("")
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        with self.assertRaises(RuntimeError):
            e.load_filtered_policy(None)

    def test_filtered_adapter_invalid_filepath(self):
        adapter = casbin.persist.adapters.FilteredAdapter(get_examples("does_not_exist_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        with self.assertRaises(RuntimeError):
            e.load_filtered_policy(None)
