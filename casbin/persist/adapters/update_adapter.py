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


class UpdateAdapter:
    """UpdateAdapter is the interface for Casbin adapters with add update policy function."""

    def update_policy(self, sec, ptype, old_rule, new_policy):
        """
        update_policy updates a policy rule from storage.
        This is part of the Auto-Save feature.
        """
        pass

    def update_policies(self, sec, ptype, old_rules, new_rules):
        """
        UpdatePolicies updates some policy rules to storage, like db, redis.
        """
        pass

    def update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        """
        update_filtered_policies deletes old rules and adds new rules.
        """
        pass
