# Copyright 2023 The casbin Authors. All Rights Reserved.
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
from tests.test_enforcer import get_examples, TestCaseBase


class SampleWatcher:
    def __init__(self):
        self.callback = None
        self.notify_message = None

    def close(self):
        pass

    def set_update_callback(self, callback):
        """
        sets the callback function to be called when the policy is updated
        :param callable callback: callback(event)
            - event: event received from the rabbitmq
        :return:
        """
        self.callback = callback

    def update(self, msg):
        """
        update the policy
        """
        self.notify_message = msg
        return True

    def update_for_add_policy(self, section, ptype, *params):
        """
        update for add policy
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:    True if updated
        """
        message = "called add policy"
        return self.update(message)

    def update_for_remove_policy(self, section, ptype, *params):
        """
        update for remove policy
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:    True if updated
        """
        message = "called remove policy"
        return self.update(message)

    def update_for_remove_filtered_policy(self, section, ptype, field_index, *params):
        """
        update for remove filtered policy
        :param section: section
        :param ptype:   policy type
        :param field_index: field index
        :param params: other params
        :return:
        """
        message = "called remove filtered policy"
        return self.update(message)

    def update_for_save_policy(self, model: casbin.Model):
        """
        update for save policy
        :param model: casbin model
        :return:
        """
        message = "called save policy"
        return self.update(message)

    def update_for_add_policies(self, section, ptype, *params):
        """
        update for add policies
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:
        """
        message = "called add policies"
        return self.update(message)

    def update_for_remove_policies(self, section, ptype, *params):
        """
        update for remove policies
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:
        """
        message = "called remove policies"
        return self.update(message)

    def start_watch(self):
        """
        starts the watch thread
        :return:
        """
        pass


class TestWatcherEx(TestCaseBase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.Enforcer(
            model,
            adapter,
        )

    def test_auto_notify_enabled(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        w = SampleWatcher()
        e.set_watcher(w)
        e.enable_auto_notify_watcher(True)

        e.save_policy()
        self.assertEqual(w.notify_message, "called save policy")

        e.add_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called add policy")

        e.remove_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called remove policy")

        e.remove_filtered_policy(1, "data1")
        self.assertEqual(w.notify_message, "called remove filtered policy")

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
            ["leyo", "data4", "read"],
            ["ham", "data4", "write"],
        ]
        e.add_policies(rules)
        self.assertEqual(w.notify_message, "called add policies")

        e.remove_policies(rules)
        self.assertEqual(w.notify_message, "called remove policies")

    def test_auto_notify_disabled(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        w = SampleWatcher()
        e.set_watcher(w)
        e.enable_auto_notify_watcher(False)

        e.save_policy()
        self.assertEqual(w.notify_message, "called save policy")

        w.notify_message = None

        e.add_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, None)

        e.remove_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, None)

        e.remove_filtered_policy(1, "data1")
        self.assertEqual(w.notify_message, None)

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
            ["leyo", "data4", "read"],
            ["ham", "data4", "write"],
        ]
        e.add_policies(rules)
        self.assertEqual(w.notify_message, None)

        e.remove_policies(rules)
        self.assertEqual(w.notify_message, None)
