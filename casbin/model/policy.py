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

import logging

from contextlib import contextmanager
from typing import Any, Container, Dict, Iterable, Iterator, Optional, Sequence, Set, cast

DEFAULT_SEP = ","


class Policy:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.model = {}

    def __getitem__(self, item):
        return self.model.get(item)

    def __setitem__(self, key, value):
        self.model[key] = value

    def keys(self):
        return self.model.keys()

    def values(self):
        return self.model.values()

    def items(self):
        return self.model.items()

    def build_role_links(self, rm_map):
        """initializes the roles in RBAC."""

        if "g" not in self.keys():
            return

        for ptype, ast in self["g"].items():
            rm = rm_map[ptype]
            ast.build_role_links(rm)

    def build_incremental_role_links(self, rm, op, sec, ptype, rules):
        if sec == "g":
            self[sec].get(ptype).build_incremental_role_links(rm, op, rules)

    def print_policy(self):
        """Log using info"""

        self.logger.info("Policy:")
        for sec in ["p", "g"]:
            if sec not in self.keys():
                continue

            for key, ast in self[sec].items():
                self.logger.info("{} : {} : {}".format(key, ast.value, ast.policy))

    def clear_policy(self):
        """clears all current policy."""

        for sec in ["p", "g"]:
            if sec not in self.keys():
                continue

            for key in self[sec].keys():
                self[sec][key].policy = []

    def get_policy(self, sec, ptype):
        """gets all rules in a policy."""

        return self[sec][ptype].policy

    def get_filtered_policy(self, sec, ptype, field_index, *field_values):
        """gets rules based on field filters from a policy."""
        return [
            rule
            for rule in self[sec][ptype].policy
            if all(
                (callable(value) and value(rule[field_index + i])) or (value == "" or rule[field_index + i] == value)
                for i, value in enumerate(field_values)
            )
        ]

    def has_policy(self, sec, ptype, rule):
        """determines whether a model has the specified policy rule."""
        if sec not in self.keys():
            return False
        if ptype not in self[sec]:
            return False

        return rule in self[sec][ptype].policy

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the model."""
        assertion = self[sec][ptype]
        if not self.has_policy(sec, ptype, rule):
            assertion.policy.append(rule)
        else:
            return False

        if sec == "p" and assertion.priority_index >= 0:
            try:
                idx_insert = int(rule[assertion.priority_index])

                i = len(assertion.policy) - 1
                for i in range(i, 0, -1):

                    try:
                        idx = int(assertion.policy[i - 1][assertion.priority_index])
                    except Exception as e:
                        print(e)

                    if idx > idx_insert:
                        assertion.policy[i] = assertion.policy[i - 1]
                    else:
                        break

                assertion.policy[i] = rule
                assertion.policy_map[DEFAULT_SEP.join(rule)] = i

            except Exception as e:
                print(e)

        assertion.policy_map[DEFAULT_SEP.join(rule)] = len(assertion.policy) - 1
        return True

    def add_policies(self, sec, ptype, rules):
        """adds policy rules to the model."""

        for rule in rules:
            if self.has_policy(sec, ptype, rule):
                return False

        for rule in rules:
            self[sec][ptype].policy.append(rule)

        return True

    def update_policy(self, sec, ptype, old_rule, new_rule):
        """update a policy rule from the model."""

        if sec not in self.keys():
            return False
        if ptype not in self[sec]:
            return False

        ast = self[sec][ptype]

        if old_rule in ast.policy:
            rule_index = ast.policy.index(old_rule)
        else:
            return False

        if "p_priority" in ast.tokens:
            priority_index = ast.tokens.index("p_priority")
            if old_rule[priority_index] == new_rule[priority_index]:
                ast.policy[rule_index] = new_rule
            else:
                raise Exception("New rule should have the same priority with old rule.")
        else:
            ast.policy[rule_index] = new_rule

        return True

    def update_policies(self, sec, ptype, old_rules, new_rules):
        """update policy rules from the model."""

        if sec not in self.keys():
            return False
        if ptype not in self[sec]:
            return False
        if len(old_rules) != len(new_rules):
            return False

        ast = self[sec][ptype]
        old_rules_index = []

        for old_rule in old_rules:
            if old_rule in ast.policy:
                old_rules_index.append(ast.policy.index(old_rule))
            else:
                return False

        if "p_priority" in ast.tokens:
            priority_index = ast.tokens.index("p_priority")
            for idx, old_rule, new_rule in zip(old_rules_index, old_rules, new_rules):
                if old_rule[priority_index] == new_rule[priority_index]:
                    ast.policy[idx] = new_rule
                else:
                    raise Exception("New rule should have the same priority with old rule.")
        else:
            for idx, old_rule, new_rule in zip(old_rules_index, old_rules, new_rules):
                ast.policy[idx] = new_rule

        return True

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the model."""
        if not self.has_policy(sec, ptype, rule):
            return False

        self[sec][ptype].policy.remove(rule)

        return rule not in self[sec][ptype].policy

    def remove_policies(self, sec, ptype, rules):
        """RemovePolicies removes policy rules from the model."""

        for rule in rules:
            if not self.has_policy(sec, ptype, rule):
                return False
            self[sec][ptype].policy.remove(rule)
            if rule in self[sec][ptype].policy:
                return False

        return True

    def remove_policies_with_effected(self, sec, ptype, rules):
        effected = []
        for rule in rules:
            if self.has_policy(sec, ptype, rule):
                effected.append(rule)
                self.remove_policy(sec, ptype, rule)

        return effected

    def remove_filtered_policy_returns_effects(self, sec, ptype, field_index, *field_values):
        """
        remove_filtered_policy_returns_effects removes policy rules based on field filters from the model.
        """
        tmp = []
        effects = []

        if len(field_values) == 0:
            return []
        if sec not in self.keys():
            return []
        if ptype not in self[sec]:
            return []

        for rule in self[sec][ptype].policy:
            if all(value == "" or rule[field_index + i] == value for i, value in enumerate(field_values)):
                effects.append(rule)
            else:
                tmp.append(rule)

        self[sec][ptype].policy = tmp

        return effects

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules based on field filters from the model."""
        tmp = []
        res = False

        if sec not in self.keys():
            return res
        if ptype not in self[sec]:
            return res

        for rule in self[sec][ptype].policy:
            if all(value == "" or rule[field_index + i] == value for i, value in enumerate(field_values)):
                res = True
            else:
                tmp.append(rule)

        self[sec][ptype].policy = tmp

        return res

    def get_values_for_field_in_policy(self, sec, ptype, field_index):
        """gets all values for a field for all rules in a policy, duplicated values are removed."""
        values = []
        if sec not in self.keys():
            return values
        if ptype not in self[sec]:
            return values

        for rule in self[sec][ptype].policy:
            value = rule[field_index]
            if value not in values:
                values.append(value)

        return values


def in_cache(cache: Dict[str, Any], keys: Sequence[str]) -> Optional[Set[Sequence[str]]]:
    if keys[0] in cache:
        if len(keys) > 1:
            return in_cache(cache[keys[-0]], keys[1:])
        return cast(Set[Sequence[str]], cache[keys[0]])
    else:
        return None


class FilterablePolicy(Container[Sequence[str]]):
    _cache: Dict[str, Any]
    _current_filter: Optional[Set[Sequence[str]]]
    _cache_key_order: Sequence[int]

    def __init__(self, cache_key_order: Sequence[int]) -> None:
        self._cache = {}
        self._current_filter = None
        self._cache_key_order = cache_key_order

    def __iter__(self) -> Iterator[Sequence[str]]:
        yield from self.__get_policy()

    def __len__(self) -> int:
        return len(list(self.__get_policy()))

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, (list, tuple)) or len(self._cache_key_order) >= len(item):
            return False
        keys = [item[x] for x in self._cache_key_order]
        exists = in_cache(self._cache, keys)
        if not exists:
            return False
        return tuple(item) in exists

    def __getitem__(self, item: int) -> Sequence[str]:
        for i, entry in enumerate(self):
            if i == item:
                return entry
        raise KeyError("No such value exists")

    def append(self, item: Sequence[str]) -> None:
        cache = self._cache
        keys = [item[x] for x in self._cache_key_order]

        for key in keys[:-1]:
            if key not in cache:
                cache[key] = dict()
            cache = cache[key]
        if keys[-1] not in cache:
            cache[keys[-1]] = set()

        cache[keys[-1]].add(tuple(item))

    def remove(self, policy: Sequence[str]) -> bool:
        keys = [policy[x] for x in self._cache_key_order]
        exists = in_cache(self._cache, keys)
        if not exists:
            return True

        exists.remove(tuple(policy))
        return True

    def __get_policy(self) -> Iterable[Sequence[str]]:
        if self._current_filter is not None:
            return (list(x) for x in self._current_filter)
        else:
            return (list(v2) for v in self._cache.values() for v1 in v.values() for v2 in v1)

    def apply_filter(self, *keys: str) -> None:
        value = in_cache(self._cache, keys)
        self._current_filter = value or set()

    def clear_filter(self) -> None:
        self._current_filter = None


@contextmanager
def filter_policy(policy: FilterablePolicy, *keys: str) -> Iterator[None]:
    try:
        policy.apply_filter(*keys)
        yield
    finally:
        policy.clear_filter()
