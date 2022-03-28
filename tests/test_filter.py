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
from unittest import IsolatedAsyncioTestCase
from tests.test_enforcer import get_examples
import pytest


class Filter:
    # P,G are strings
    P = []
    G = []


class TestFilteredAdapter(IsolatedAsyncioTestCase):

    async def test_init_filtered_adapter(self):
        adapter = casbin.persist.adapters.FilteredAdapter(
            get_examples("rbac_with_domains_policy.csv")
        )
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        await e.load_policy()
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))

    async def test_load_filtered_policy(self):
        adapter = casbin.persist.adapters.FilteredAdapter(
            get_examples("rbac_with_domains_policy.csv")
        )
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        try:
            await e.load_policy()
        except BaseException:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        try:
            await e.load_filtered_policy(filter)
        except BaseException:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if not e.is_filtered:
            raise RuntimeError("adapter did not set the filtered flag correctly")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

        with self.assertRaises(RuntimeError):
            await e.save_policy()

        with self.assertRaises(RuntimeError):
            a = e.get_adapter()
            await a.save_policy(e.get_model())

    async def test_append_filtered_policy(self):
        adapter = casbin.persist.adapters.FilteredAdapter(
            get_examples("rbac_with_domains_policy.csv")
        )
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        try:
            await e.load_policy()
        except Exception:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        try:
            await e.load_filtered_policy(filter)
        except Exception:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if not e.is_filtered:
            raise RuntimeError("adapter did not set the filtered flag correctly")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

        filter.P = ["", "domain2"]
        filter.G = ["", "", "domain2"]
        try:
            await e.load_increment_filtered_policy(filter)
        except BaseException:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    async def test_filtered_policy_invalid_filter(self):
        adapter = casbin.persist.adapters.FilteredAdapter(
            get_examples("rbac_with_domains_policy.csv")
        )
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = ["", "domain1"]

        with self.assertRaises(RuntimeError):
            await e.load_filtered_policy(filter)

    async def test_filtered_policy_empty_filter(self):
        adapter = casbin.persist.adapters.FilteredAdapter(
            get_examples("rbac_with_domains_policy.csv")
        )
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        try:
            await e.load_filtered_policy(None)
        except BaseException:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if e.is_filtered():
            raise RuntimeError("adapter did not reset the filtered flag correctly")

        try:
            await e.save_policy()
        except BaseException:
            raise RuntimeError("unexpected error in SavePolicy")

    async def test_unsupported_filtered_policy(self):
        e = casbin.Enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        with self.assertRaises(ValueError):
            await e.load_filtered_policy(filter)

    async def test_filtered_adapter_empty_filepath(self):
        adapter = casbin.persist.adapters.FilteredAdapter("")
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        with self.assertRaises(RuntimeError):
            await e.load_filtered_policy(None)

    async def test_filtered_adapter_invalid_filepath(self):
        adapter = casbin.persist.adapters.FilteredAdapter(
            get_examples("does_not_exist_policy.csv")
        )
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        with self.assertRaises(RuntimeError):
            await e.load_filtered_policy(None)
