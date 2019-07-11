from casbin import util, log


class Policy:
    def __init__(self):
        self.model = {}

    def build_role_links(self, rm):
        if "g" not in self.model.keys():
            return

        for ast in self.model["g"].values():
            ast.build_role_links(rm)

    def print_policy(self):
        log.log_print("Policy:")
        for sec in ["p", "g"]:
            if sec not in self.model.keys():
                continue

            for key, ast in self.model[sec].items():
                log.log_print(key, ": ", ast.value, ": ", ast.policy)

    def remove_policy(self, sec, ptype, rule):
        """remove a policy rule to the model."""
        if sec not in self.model.keys():
            return False
        if ptype not in self.model[sec]:
            return False

        for i, r in enumerate(self.model[sec][ptype].policy):
            if rule == r:
                self.model[sec][ptype].policy.pop(i)
                return True
        return False

    def clear_policy(self):
        for sec in ["p", "g"]:
            if sec not in self.model.keys():
                continue

            for key, ast in self.model[sec].items():
                self.model[sec][key].policy = []

    def get_policy(self, sec, ptype):
        return self.model[sec][ptype].policy

    def get_filtered_policy(self, sec, ptype, field_index, *field_values):
        """gets rules based on field filters from a policy."""
        res = []

        for rule in self.model[sec][ptype].policy:
            matched = True
            for i, field_value in enumerate(field_values):
                if field_value != '' and rule[field_index + i] != field_value:
                    matched = False
                    break

            if matched:
                res.append(rule)

        return res

    def has_policy(self, sec, ptype, rule):
        """determines whether a model has the specified policy rule."""
        if sec not in self.model.keys():
            return False
        if ptype not in self.model[sec]:
            return False

        for r in self.model[sec][ptype].policy:
            if rule == r:
                return True

        return False

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the model."""

        if not self.has_policy(sec, ptype, rule):
            self.model[sec][ptype].policy.append(rule)
            return True

        return False

    def get_values_for_field_in_policy(self, sec, ptype, field_index):
        """gets all values for a field for all rules in a policy, duplicated values are removed."""

        values = []
        if sec not in self.model.keys():
            return values
        if ptype not in self.model[sec]:
            return values

        for rule in self.model[sec][ptype].policy:
            values.append(rule[field_index])

        return util.array_remove_duplicates(values)
