import logging

class Policy:
    def __init__(self):
        self.logger = logging.getLogger()
        self.model = {}

    def build_role_links(self, rm_map):
        """initializes the roles in RBAC."""

        if "g" not in self.model:
            return

        for ptype, ast in self.model["g"].items():
            rm = rm_map[ptype]
            ast.build_role_links(rm)

    def print_policy(self):
        """Log using info"""

        self.logger.info("Policy:")
        for sec in ["p", "g"]:
            if sec not in self.model:
                continue

            for key, ast in self.model[sec].items():
                self.logger.info("{} : {} : {}".format(key, ast.value, ast.policy))

    def clear_policy(self):
        """clears all current policy."""

        for sec in ["p", "g"]:
            if sec not in self.model:
                continue

            for key in self.model[sec].keys():
                self.model[sec][key].policy = set()

    def get_policy(self, sec, ptype):
        """gets all rules in a policy."""

        return list(self.model[sec][ptype].policy)

    def get_filtered_policy(self, sec, ptype, field_index, *field_values):
        """gets rules based on field filters from a policy."""
        return [
            rule for rule in self.model[sec][ptype].policy
            if all(value == "" or rule[field_index + i] == value for i, value in enumerate(field_values))
        ]

    def has_policy(self, sec, ptype, rule):
        """determines whether a model has the specified policy rule."""
        if sec not in self.model:
            return False
        if ptype not in self.model[sec]:
            return False

        return rule in self.model[sec][ptype].policy

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the model."""

        if not self.has_policy(sec, ptype, rule):
            self.model[sec][ptype].policy.add(rule)
            return True

        return False

    def add_policies(self,sec, ptype, rules):
        """adds policy rules to the model."""

        if any(self.has_policy(sec, ptype, rule) is False for rule in rules):
            return False

        self.model[sec][ptype].policy.update(rules)

        return True

    def update_policy(self, sec, ptype, old_rule, new_rule):
        """update a policy rule from the model."""

        if not self.has_policy(sec, ptype, old_rule):
            return False

        return self.remove_policy(sec, ptype, old_rule) and self.add_policy(sec, ptype, new_rule)

    def update_policies(self, sec, ptype, old_rules, new_rules):
        """update policy rules from the model."""

        for rule in old_rules:
            if not self.has_policy(sec, ptype, rule):
                return False

        return self.remove_policies(sec, ptype, old_rules) and self.add_policies(sec, ptype, new_rules)

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the model."""
        if not self.has_policy(sec, ptype, rule):
            return False

        self.model[sec][ptype].policy.discard(rule)

        return True

    def remove_policies(self, sec, ptype, rules):
        """RemovePolicies removes policy rules from the model."""

        if not self.has_policy(sec, ptype, old_rule):
            return False

        self.model[sec][ptype].policy.difference_update(rules)

        return True

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules based on field filters from the model."""
        tmp = set()
        res = False

        if sec not in self.model.keys():
            return res
        if ptype not in self.model[sec]:
            return res

        for rule in self.model[sec][ptype].policy:
            if all(value == "" or rule[field_index + i] == value for i, value in enumerate(field_values)):
                res = True
            else:
                tmp.add(rule)

        self.model[sec][ptype].policy = tmp

        return res

    def get_values_for_field_in_policy(self, sec, ptype, field_index):
        """gets all values for a field for all rules in a policy, duplicated values are removed."""
        if sec not in self.model.keys():
            return []
        if ptype not in self.model[sec]:
            return []

        values = set(rule[field_index] for rule in self.model[sec][ptype].policy)
        return list(values)
