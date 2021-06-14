from casbin import SyncedEnforcer
import logging

from casbin.persist import batch_adapter
from casbin.model.policy_op import PolicyOp
from casbin.persist.adapters import update_adapter


class DistributedEnforcer(SyncedEnforcer):
    """DistributedEnforcer wraps SyncedEnforcer for dispatcher."""

    def __init__(self, model=None, adapter=None):
        self.logger = logging.getLogger(__name__)
        SyncedEnforcer.__init__(self, model, adapter)

    def add_policy_self(self, should_persist, sec, ptype, rules):
        """
        AddPolicySelf provides a method for dispatcher to add authorization rules to the current policy.
        The function returns the rules affected and error.
        """

        no_exists_policy = []
        for rule in rules:
            if not self.get_model().has_policy(sec, ptype, rule):
                no_exists_policy.append(rule)

        if should_persist:
            try:
                if isinstance(self.adapter, batch_adapter):
                    self.adapter.add_policies(sec, ptype, rules)
            except Exception as e:
                self.logger.log("An error occurred: " + e)

        self.get_model().add_policies(sec, ptype, no_exists_policy)

        if sec == "g":
            try:
                self.build_incremental_role_links(
                    PolicyOp.Policy_add, ptype, no_exists_policy
                )
            except Exception as e:
                self.logger.log("An exception occurred: " + e)
                return no_exists_policy

        return no_exists_policy

    def remove_policy_self(self, should_persist, sec, ptype, rules):
        """
        remove_policy_self provides a method for dispatcher to remove policies from current policy.
        The function returns the rules affected and error.
        """
        if should_persist:
            try:
                if isinstance(self.adapter, batch_adapter):
                    self.adapter.remove_policy(sec, ptype, rules)
            except Exception as e:
                self.logger.log("An exception occurred: " + e)

        effected = self.get_model().remove_policies_with_effected(sec, ptype, rules)

        if sec == "g":
            try:
                self.build_incremental_role_links(PolicyOp.Policy_remove, ptype, rules)
            except Exception as e:
                self.logger.log("An exception occurred: " + e)
                return effected

        return effected

    def remove_filtered_policy_self(
        self, should_persist, sec, ptype, field_index, *field_values
    ):
        """
        remove_filtered_policy_self provides a method for dispatcher to remove an authorization
        rule from the current policy,field filters can be specified.
        The function returns the rules affected and error.
        """
        if should_persist:
            try:
                self.adapter.remove_filtered_policy(
                    sec, ptype, field_index, field_values
                )
            except Exception as e:
                self.logger.log("An exception occurred: " + e)

        effects = self.get_model().remove_filtered_policy_returns_effects(
            sec, ptype, field_index, field_values
        )

        if sec == "g":
            try:
                self.build_incremental_role_links(
                    PolicyOp.Policy_remove, ptype, effects
                )
            except Exception as e:
                self.logger.log("An exception occurred: " + e)
                return effects

        return effects

    def clear_policy_self(self, should_persist):
        """
        clear_policy_self provides a method for dispatcher to clear all rules from the current policy.
        """
        if should_persist:
            try:
                self.adapter.save_policy(None)
            except Exception as e:
                self.logger.log("An exception occurred: " + e)

        self.get_model().clear_policy()

    def update_policy_self(self, should_persist, sec, ptype, old_rule, new_rule):
        """
        update_policy_self provides a method for dispatcher to update an authorization rule from the current policy.
        """
        if should_persist:
            try:
                if isinstance(self.adapter, update_adapter):
                    self.adapter.update_policy(sec, ptype, old_rule, new_rule)
            except Exception as e:
                self.logger.log("An exception occurred: " + e)
                return False

        rule_updated = self.get_model().update_policy(sec, ptype, old_rule, new_rule)

        if not rule_updated:
            return False

        if sec == "g":
            try:
                self.build_incremental_role_links(
                    PolicyOp.Policy_remove, ptype, [old_rule]
                )
            except Exception as e:
                return False

            try:
                self.build_incremental_role_links(
                    PolicyOp.Policy_add, ptype, [new_rule]
                )
            except Exception as e:
                return False

        return True
