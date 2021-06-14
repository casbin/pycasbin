class Dispatcher:
    """Dispatcher is the interface for pycasbin dispatcher"""

    def add_policies(self, sec, ptype, rules):
        """add_policies adds policies rule to all instance."""
        pass

    def remove_policies(self, sec, ptype, rules):
        """remove_policies removes policies rule from all instance."""
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, field_values):
        """remove_filtered_policy removes policy rules that match the filter from all instance."""
        pass

    def clear_policy(self):
        """clear_policy clears all current policy in all instances."""
        pass

    def update_policy(self, sec, ptype, old_rule, new_rule):
        """update_policy updates policy rule from all instance."""
        pass
