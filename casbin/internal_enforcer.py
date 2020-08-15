
from casbin.core_enforcer import CoreEnforcer


class InternalEnforcer(CoreEnforcer):
    """
        InternalEnforcer = CoreEnforcer + Internal API.
    """

    def _add_policy(self, sec, ptype, rule):
        """adds a rule to the current policy."""
        rule_added = self.model.add_policy(sec, ptype, rule)
        if not rule_added:
            return rule_added

        if self.adapter and self.auto_save:
            if self.adapter.add_policy(sec, ptype, rule) is False:
                return False

            if self.watcher:
                self.watcher.update()

        return rule_added

    def _add_policies(self, sec, ptype, rules):
        """adds rules to the current policy."""

        if self.adapter and self.auto_save and not self.model.has_policies(sec, ptype, rules):
            try:
                rules_added = self.adapter.add_policies(sec, ptype, rules)
                return rules_added
            except:
                print("Batch function haven't been implemented in this adapter")

                for rule in rules:
                    rule_added = self.model.add_policy(sec, ptype, rule)
                    if not rule_added:
                        continue

                    if self.adapter and self.auto_save:
                        if self.adapter.add_policy(sec, ptype, rule) is False:
                            continue

                        if self.watcher:
                            self.watcher.update()

            return True

        else:
            return False


    def _remove_policy(self, sec, ptype, rule):
        """removes a rule from the current policy."""
        rule_removed = self.model.remove_policy(sec, ptype, rule)
        if not rule_removed:
            return rule_removed

        if self.adapter and self.auto_save:
            if self.adapter.remove_policy(sec, ptype, rule) is False:
                return False

            if self.watcher:
                self.watcher.update()

        return rule_removed

    def _remove_policies(self, sec, ptype, rules):
        """removes rules from the current policy."""
        if self.adapter and self.auto_save:
            try:
                rules_added = self.adapter.remove_policies(sec, ptype, rules)
                return rules_added
            except:
                print("Batch function haven't been implemented in this adapter")

                for rule in rules:
                    rule_removed = self.model.remove_policy(sec, ptype, rule)
                    if not rule_removed:
                        continue

                    if self.adapter and self.auto_save:
                        if self.adapter.remove_policy(sec, ptype, rule) is False:
                            continue

                        if self.watcher:
                            self.watcher.update()

            return True

        else:
            return False


    def _remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes rules based on field filters from the current policy."""
        rule_removed = self.model.remove_filtered_policy(sec, ptype, field_index, *field_values)
        if not rule_removed:
            return rule_removed

        if self.adapter and self.auto_save:
            if self.adapter.remove_filtered_policy(sec, ptype, field_index, *field_values) is False:
                return False

            if self.watcher:
                self.watcher.update()

        return rule_removed
