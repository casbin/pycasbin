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

import json
import re
import casbin
from unittest import TestCase
from tests.test_enforcer import get_examples


class TestFrontend(TestCase):
    def test_casbin_js_get_permission_for_user(self):
        e = casbin.SyncedEnforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_with_hierarchy_policy.csv"),
        )
        received = json.loads(casbin.casbin_js_get_permission_for_user(e, "alice"))
        with open(get_examples("rbac_model.conf"), "r") as file:
            expected_model_str = file.read()
        self.assertEqual(received["m"], re.sub("\n+", "\n", expected_model_str))

        with open(get_examples("rbac_with_hierarchy_policy.csv"), "r") as file:
            expected_policies_str = file.read()
        expected_policy_item = re.split(r",|\n", expected_policies_str)
        i = 0
        for s_arr in received["p"]:
            for s in s_arr:
                self.assertEqual(s.strip(), expected_policy_item[i].strip())
                i += 1
