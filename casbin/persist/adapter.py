def load_policy_line(line, model):
    """loads a text line as a policy rule to model."""

    if line == "":
        return

    if line[:1] == "#":
        return

    tokens = line.split(", ")
    key = tokens[0]
    sec = key[0]

    if sec not in model.model.keys():
        return

    if key not in model.model[sec].keys():
        return

    model.model[sec][key].policy.append(tokens[1:])


class Adapter:
    """the interface for Casbin adapters."""

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        pass

    def save_policy(self, model):
        """saves all policy rules to the storage."""
        pass

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        pass

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        pass
