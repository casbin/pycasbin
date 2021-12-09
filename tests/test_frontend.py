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
