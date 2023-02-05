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

from . import Assertion
from casbin import util, config
from .policy import Policy

DEFAULT_DOMAIN = ""
DEFAULT_SEPARATOR = "::"


class Model(Policy):

    section_name_map = {
        "r": "request_definition",
        "p": "policy_definition",
        "g": "role_definition",
        "e": "policy_effect",
        "m": "matchers",
    }

    def _load_assertion(self, cfg, sec, key):
        value = cfg.get(self.section_name_map[sec] + "::" + key)

        return self.add_def(sec, key, value)

    def add_def(self, sec, key, value):
        if value == "":
            return

        ast = Assertion()
        ast.key = key
        ast.value = value

        if "r" == sec or "p" == sec:
            ast.tokens = ast.value.split(",")
            for i, token in enumerate(ast.tokens):
                ast.tokens[i] = key + "_" + token.strip()
        else:
            ast.value = util.remove_comments(util.escape_assertion(ast.value))

        if sec not in self.keys():
            self[sec] = {}

        self[sec][key] = ast

        return True

    def _get_key_suffix(self, i):
        if i == 1:
            return ""

        return str(i)

    def _load_section(self, cfg, sec):
        i = 1
        while True:
            if not self._load_assertion(cfg, sec, sec + self._get_key_suffix(i)):
                break
            else:
                i = i + 1

    def load_model(self, path):
        cfg = config.Config.new_config(path)

        self._load_section(cfg, "r")
        self._load_section(cfg, "p")
        self._load_section(cfg, "e")
        self._load_section(cfg, "m")

        self._load_section(cfg, "g")

    def load_model_from_text(self, text):
        cfg = config.Config.new_config_from_text(text)

        self._load_section(cfg, "r")
        self._load_section(cfg, "p")
        self._load_section(cfg, "e")
        self._load_section(cfg, "m")

        self._load_section(cfg, "g")

    def print_model(self):
        self.logger.info("Model:")
        for k, v in self.items():
            for i, j in v.items():
                self.logger.info("%s.%s: %s", k, i, j.value)

    def sort_policies_by_priority(self):
        for ptype, assertion in self["p"].items():
            for index, token in enumerate(assertion.tokens):
                if token == f"{ptype}_priority":
                    assertion.priority_index = index
                    break

            if assertion.priority_index == -1:
                continue

            assertion.policy = sorted(assertion.policy, key=lambda x: x[assertion.priority_index])

            for i, policy in enumerate(assertion.policy):
                assertion.policy_map[",".join(policy)] = i

        return None

    def sort_policies_by_subject_hierarchy(self):
        if self["e"]["e"].value != "subjectPriority(p_eft) || deny":
            return

        sub_index = 0
        domain_index = -1
        for ptype, assertion in self["p"].items():
            for index, token in enumerate(assertion.tokens):
                if token == "{}_dom".format(ptype):
                    domain_index = index
                    break

            subject_hierarchy_map = self.get_subject_hierarchy_map(self["g"]["g"].policy)

            def compare_policy(policy):
                domain = DEFAULT_DOMAIN
                if domain_index != -1:
                    domain = policy[domain_index]
                name = self.get_name_with_domain(domain, policy[sub_index])
                return subject_hierarchy_map[name]

            assertion.policy = sorted(assertion.policy, key=compare_policy, reverse=True)
            for i, policy in enumerate(assertion.policy):
                assertion.policy_map[",".join(policy)] = i

    def get_subject_hierarchy_map(self, policies):
        subject_hierarchy_map = {}
        # Tree structure of role
        policy_map = {}
        for policy in policies:
            if len(policy) < 2:
                raise RuntimeError("policy g expect 2 more params")
            domain = DEFAULT_DOMAIN
            if len(policy) != 2:
                domain = policy[2]
            child = self.get_name_with_domain(domain, policy[0])
            parent = self.get_name_with_domain(domain, policy[1])
            if parent not in policy_map.keys():
                policy_map[parent] = [child]
            else:
                policy_map[parent].append(child)
            if child not in subject_hierarchy_map.keys():
                subject_hierarchy_map[child] = 0
            if parent not in subject_hierarchy_map.keys():
                subject_hierarchy_map[parent] = 0
            subject_hierarchy_map[child] = 1
        # Use queues for levelOrder
        queue = []
        for k, v in subject_hierarchy_map.items():
            root = k
            if v != 0:
                continue
            lv = 0
            queue.append(root)
            while len(queue) != 0:
                sz = len(queue)
                for _ in range(sz):
                    node = queue.pop(0)
                    subject_hierarchy_map[node] = lv
                    if node in policy_map.keys():
                        for child in policy_map[node]:
                            queue.append(child)
                lv += 1
        return subject_hierarchy_map

    def get_name_with_domain(self, domain, name):
        return "{}{}{}".format(domain, DEFAULT_SEPARATOR, name)

    def to_text(self):
        s = []

        def write_string(sec):
            for p_type in self[sec]:
                value = self[sec][p_type].value
                s.append("{} = {}\n".format(sec, value.replace("p_", "p.").replace("r_", "r.")))

        s.append("[request_definition]\n")
        write_string("r")
        s.append("[policy_definition]\n")
        write_string("p")
        if "g" in self.keys():
            s.append("[role_definition]\n")
            for p_type in self["g"]:
                s.append("{} = {}\n".format(p_type, self["g"][p_type].value))
        s.append("[policy_effect]\n")
        write_string("e")
        s.append("[matchers]\n")
        write_string("m")

        # remove last \n
        s[-1] = s[-1].strip()

        return "".join(s)
