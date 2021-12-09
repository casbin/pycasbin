from . import Assertion
from casbin import util, config
from .policy import Policy


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

            assertion.policy = sorted(
                assertion.policy, key=lambda x: x[assertion.priority_index]
            )

            for i, policy in enumerate(assertion.policy):
                assertion.policy_map[",".join(policy)] = i

        return None

    def to_text(self):
        s = []

        def write_string(sec):
            for p_type in self[sec]:
                value = self[sec][p_type].value
                s.append(
                    "{} = {}\n".format(
                        sec, value.replace("p_", "p.").replace("r_", "r.")
                    )
                )

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
