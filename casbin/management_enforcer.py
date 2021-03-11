from casbin.internal_enforcer import InternalEnforcer

class ManagementEnforcer(InternalEnforcer):
    """
        ManagementEnforcer = InternalEnforcer + Management API.
    """

    def get_all_subjects(self):
        """gets the list of subjects that show up in the current policy."""
        return self.get_all_named_subjects('p')

    def get_all_named_subjects(self, ptype):
        """gets the list of subjects that show up in the current named policy."""
        return self.model.get_values_for_field_in_policy('p', ptype, 0)

    def get_all_objects(self):
        """gets the list of objects that show up in the current policy."""
        return self.get_all_named_objects('p')

    def get_all_named_objects(self, ptype):
        """gets the list of objects that show up in the current named policy."""
        return self.model.get_values_for_field_in_policy('p', ptype, 1)

    def get_all_actions(self):
        """gets the list of actions that show up in the current policy."""
        return self.get_all_named_actions('p')

    def get_all_named_actions(self, ptype):
        """gets the list of actions that show up in the current named policy."""
        return self.model.get_values_for_field_in_policy('p', ptype, 2)

    def get_all_roles(self):
        """gets the list of roles that show up in the current named policy."""
        return self.get_all_named_roles('g')

    def get_all_named_roles(self, ptype):
        """gets all the authorization rules in the policy."""
        return self.model.get_values_for_field_in_policy('g', ptype, 1)

    def get_policy(self):
        """gets all the authorization rules in the policy."""
        return self.get_named_policy('p')

    def get_filtered_policy(self, field_index, *field_values):
        """gets all the authorization rules in the policy, field filters can be specified."""
        return self.get_filtered_named_policy('p', field_index, *field_values)

    def get_named_policy(self, ptype):
        """gets all the authorization rules in the named policy."""
        return self.model.get_policy('p', ptype)

    def get_filtered_named_policy(self, ptype, field_index, *field_values):
        """gets all the authorization rules in the named policy, field filters can be specified."""
        return self.model.get_filtered_policy('p', ptype, field_index, *field_values)

    def get_grouping_policy(self):
        """gets all the role inheritance rules in the policy."""
        return self.get_named_grouping_policy('g')

    def get_filtered_grouping_policy(self, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        return self.get_filtered_named_grouping_policy("g", field_index, *field_values)

    def get_named_grouping_policy(self, ptype):
        """gets all the role inheritance rules in the policy."""
        return self.model.get_policy('g', ptype)

    def get_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        return self.model.get_filtered_policy('g', ptype, field_index, *field_values)

    def has_policy(self, *params):
        """determines whether an authorization rule exists."""
        return self.has_named_policy('p', *params)

    def has_named_policy(self, ptype, *params):
        """determines whether a named authorization rule exists."""
        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            return self.model.has_policy('p', ptype, str_slice)

        return self.model.has_policy('p', ptype, list(params))

    def add_policy(self, *params):
        """adds an authorization rule to the current policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        return self.add_named_policy('p', *params)
    
    def add_policies(self,rules):
        """adds authorization rules to the current policy.
        
        If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
        Otherwise the function returns true for the corresponding rule by adding the new rule.
        """
        return self.add_named_policies('p',rules)

    def add_named_policy(self, ptype, *params):
        """adds an authorization rule to the current named policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """

        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            rule_added = self._add_policy('p', ptype, str_slice)
        else:
            rule_added = self._add_policy('p', ptype, list(params))

        return rule_added

    def add_named_policies(self,ptype,rules):
        """adds authorization rules to the current named policy.
        
        If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
        Otherwise the function returns true for the corresponding by adding the new rule."""
        return self._add_policies('p',ptype,rules)

    def update_policy(self, old_rule, new_rule):
        """updates an authorization rule from the current policy."""
        return self.update_named_policy('p', old_rule, new_rule)

    def update_policies(self, old_rules, new_rules):
        """updates authorization rules from the current policy."""
        return self.update_named_policies('p', old_rules, new_rules)

    def update_named_policy(self, ptype, old_rule, new_rule):
        """updates an authorization rule from the current named policy."""
        return self._update_policy('p', ptype, old_rule, new_rule)

    def update_named_policies(self, ptype, old_rules, new_rules):
        """updates authorization rules from the current named policy."""
        return self._update_policies('p', ptype, old_rules, new_rules)

    def remove_policy(self, *params):
        """removes an authorization rule from the current policy."""
        return self.remove_named_policy('p', *params)

    def remove_policies(self,rules):
        """removes authorization rules from the current policy."""
        return self.remove_named_policies('p',rules)

    def remove_filtered_policy(self, field_index, *field_values):
        """removes an authorization rule from the current policy, field filters can be specified."""
        return self.remove_filtered_named_policy('p', field_index, *field_values)

    def remove_named_policy(self, ptype, *params):
        """removes an authorization rule from the current named policy."""

        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            rule_removed = self._remove_policy('p', ptype, str_slice)
        else:
            rule_removed = self._remove_policy('p', ptype, list(params))

        return rule_removed

    def remove_named_policies(self,ptype,rules):
        """removes authorization rules from the current named policy."""
        return self._remove_policies('p',ptype,rules)

    def remove_filtered_named_policy(self, ptype, field_index, *field_values):
        """removes an authorization rule from the current named policy, field filters can be specified."""
        return self._remove_filtered_policy('p', ptype, field_index, *field_values)

    def has_grouping_policy(self, *params):
        """determines whether a role inheritance rule exists."""

        return self.has_named_grouping_policy('g', *params)

    def has_named_grouping_policy(self, ptype, *params):
        """determines whether a named role inheritance rule exists."""

        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            return self.model.has_policy('g', ptype, str_slice)

        return self.model.has_policy('g', ptype, list(params))

    def add_grouping_policy(self, *params):
        """adds a role inheritance rule to the current policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        return self.add_named_grouping_policy('g', *params)

    def add_grouping_policies(self,rules):
        """adds role inheritance rulea to the current policy.
        
        If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
        Otherwise the function returns true for the corresponding policy rule by adding the new rule.
        """
        return self.add_named_grouping_policies('g',rules)

    def add_named_grouping_policy(self, ptype, *params):
        """adds a named role inheritance rule to the current policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """

        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            rule_added = self._add_policy('g', ptype, str_slice)
        else:
            rule_added = self._add_policy('g', ptype, list(params))

        if self.auto_build_role_links:
            self.build_role_links()
        return rule_added

    def add_named_grouping_policies(self,ptype,rules):
        """"adds named role inheritance rules to the current policy.
        
        If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
        Otherwise the function returns true for the corresponding policy rule by adding the new rule."""
        rules_added = self._add_policies('g',ptype,rules)
        if self.auto_build_role_links:
            self.build_role_links()
        
        return rules_added

    def remove_grouping_policy(self, *params):
        """removes a role inheritance rule from the current policy."""
        return self.remove_named_grouping_policy('g', *params)

    def remove_grouping_policies(self,rules):
        """removes role inheritance rulea from the current policy."""
        return self.remove_named_grouping_policies('g',rules)

    def remove_filtered_grouping_policy(self, field_index, *field_values):
        """removes a role inheritance rule from the current policy, field filters can be specified."""
        return self.remove_filtered_named_grouping_policy('g', field_index, *field_values)

    def remove_named_grouping_policy(self, ptype, *params):
        """removes a role inheritance rule from the current named policy."""

        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            rule_removed = self._remove_policy('g', ptype, str_slice)
        else:
            rule_removed = self._remove_policy('g', ptype, list(params))

        if self.auto_build_role_links:
            self.build_role_links()
        return rule_removed
    
    def remove_named_grouping_policies(self,ptype,rules):
        """ removes role inheritance rules from the current named policy."""
        rules_removed = self._remove_policies('g',ptype,rules)

        if self.auto_build_role_links:
            self.build_role_links()
        
        return rules_removed

    def remove_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """removes a role inheritance rule from the current named policy, field filters can be specified."""
        rule_removed = self._remove_filtered_policy('g', ptype, field_index, *field_values)

        if self.auto_build_role_links:
            self.build_role_links()
        return rule_removed

    def add_function(self, name, func):
        """adds a customized function."""
        self.fm.add_function(name, func)