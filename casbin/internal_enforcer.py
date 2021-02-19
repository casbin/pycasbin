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
    
    def _add_policies(self,sec,ptype,rules):
        """adds rules to the current policy."""
        rules_added = self.model.add_policies(sec, ptype, rules)
        if not rules_added:
            return rules_added

        if self.adapter and self.auto_save:
            if hasattr(self.adapter,'add_policies') is False:
                return False
                
            if self.adapter.add_policies(sec, ptype, rules) is False:
                return False

            if self.watcher:
                self.watcher.update()

        return rules_added

    def _update_policy(self, sec, ptype, old_rule, new_rule):
        """updates a rule from the current policy."""
        rule_updated = self.model.update_policy(sec, ptype, old_rule, new_rule)

        if not rule_updated:
            return rule_updated

        if self.adapter and self.auto_save:

            if self.adapter.update_policy(sec, ptype, old_rule, new_rule) is False:
                return False

            if self.watcher:
                self.watcher.update()

        return rule_updated

    def _update_policies(self, sec, ptype, old_rules, new_rules):
        """updates rules from the current policy."""
        rules_updated = self.model.update_policies(sec, ptype, old_rules, new_rules)

        if not rules_updated:
            return rules_updated

        if self.adapter and self.auto_save:

            if self.adapter.update_policies(sec, ptype, old_rules, new_rules) is False:
                return False

            if self.watcher:
                self.watcher.update()

        return rules_updated
    
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
        """RemovePolicies removes policy rules from the model."""
        rules_removed = self.model.remove_policies(sec, ptype, rules)
        if not rules_removed:
            return rules_removed

        if self.adapter and self.auto_save:
            if hasattr(self.adapter,'remove_policies') is False:
                return False

            if self.adapter.remove_policies(sec, ptype, rules) is False:
                return False

            if self.watcher:
                self.watcher.update()

        return rules_removed

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