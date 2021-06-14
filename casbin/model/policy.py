import logging


class Policy:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.model = {}

    def build_role_links(self, rm_map):
        """initializes the roles in RBAC."""

        if "g" not in self.model.keys():
            return

        for ptype, ast in self.model["g"].items():
            rm = rm_map[ptype]
            ast.build_role_links(rm)

    def build_incremental_role_links(self, rm, op, sec, ptype, rules):
        if sec == "g":
            self.model.get(sec).get(ptype).build_incremental_role_links(rm, op, rules)

    def print_policy(self):
        """Log using info"""

        self.logger.info("Policy:")
        for sec in ["p", "g"]:
            if sec not in self.model.keys():
                continue

            for key, ast in self.model[sec].items():
                self.logger.info("{} : {} : {}".format(key, ast.value, ast.policy))

    def clear_policy(self):
        """clears all current policy."""

        for sec in ["p", "g"]:
            if sec not in self.model.keys():
                continue

            for key in self.model[sec].keys():
                self.model[sec][key].policy = []

    def get_policy(self, sec, ptype):
        """gets all rules in a policy."""

        return self.model[sec][ptype].policy

    def get_filtered_policy(self, sec, ptype, field_index, *field_values):
        """gets rules based on field filters from a policy."""
        return [
            rule
            for rule in self.model[sec][ptype].policy
            if all(
                value == "" or rule[field_index + i] == value
                for i, value in enumerate(field_values)
            )
        ]

    def has_policy(self, sec, ptype, rule):
        """determines whether a model has the specified policy rule."""
        if sec not in self.model.keys():
            return False
        if ptype not in self.model[sec]:
            return False

        return rule in self.model[sec][ptype].policy

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the model."""

        if not self.has_policy(sec, ptype, rule):
            self.model[sec][ptype].policy.append(rule)
            return True

        return False

    def add_policies(self, sec, ptype, rules):
        """adds policy rules to the model."""

        for rule in rules:
            if self.has_policy(sec, ptype, rule):
                return False

        for rule in rules:
            self.model[sec][ptype].policy.append(rule)

        return True

    def update_policy(self, sec, ptype, old_rule, new_rule):
        """update a policy rule from the model."""

        if sec not in self.model.keys():
            return False
        if ptype not in self.model[sec]:
            return False

        ast = self.model[sec][ptype]

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

        if sec not in self.model.keys():
            return False
        if ptype not in self.model[sec]:
            return False
        if len(old_rules) != len(new_rules):
            return False

        ast = self.model[sec][ptype]
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
                    raise Exception(
                        "New rule should have the same priority with old rule."
                    )
        else:
            for idx, old_rule, new_rule in zip(old_rules_index, old_rules, new_rules):
                ast.policy[idx] = new_rule

        return True

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the model."""
        if not self.has_policy(sec, ptype, rule):
            return False

        self.model[sec][ptype].policy.remove(rule)

        return rule not in self.model[sec][ptype].policy

    def remove_policies(self, sec, ptype, rules):
        """RemovePolicies removes policy rules from the model."""

        for rule in rules:
            if not self.has_policy(sec, ptype, rule):
                return False
            self.model[sec][ptype].policy.remove(rule)
            if rule in self.model[sec][ptype].policy:
                return False

        return True

    def remove_policies_with_effected(self, sec, ptype, rules):
        effected = []
        for rule in rules:
            if self.has_policy(sec, ptype, rule):
                effected.append(rule)
                self.remove_policy(sec, ptype, rule)

        return effected

    def remove_filtered_policy_returns_effects(
        self, sec, ptype, field_index, *field_values
    ):
        """
        remove_filtered_policy_returns_effects removes policy rules based on field filters from the model.
        """
        tmp = []
        effects = []

        if len(field_values) == 0:
            return []
        if sec not in self.model.keys():
            return []
        if ptype not in self.model[sec]:
            return []

        for rule in self.model[sec][ptype].policy:
            if all(
                value == "" or rule[field_index + i] == value
                for i, value in enumerate(field_values[0])
            ):
                effects.append(rule)
            else:
                tmp.append(rule)

        self.model[sec][ptype].policy = tmp

        return effects

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules based on field filters from the model."""
        tmp = []
        res = False

        if sec not in self.model.keys():
            return res
        if ptype not in self.model[sec]:
            return res

        for rule in self.model[sec][ptype].policy:
            if all(
                value == "" or rule[field_index + i] == value
                for i, value in enumerate(field_values)
            ):
                res = True
            else:
                tmp.append(rule)

        self.model[sec][ptype].policy = tmp

        return res

    def get_values_for_field_in_policy(self, sec, ptype, field_index):
        """gets all values for a field for all rules in a policy, duplicated values are removed."""
        values = []
        if sec not in self.model.keys():
            return values
        if ptype not in self.model[sec]:
            return values

        for rule in self.model[sec][ptype].policy:
            value = rule[field_index]
            if value not in values:
                values.append(value)

        return values
