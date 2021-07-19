class UpdateAdapter:
    """UpdateAdapter is the interface for Casbin adapters with add update policy function."""

    def update_policy(self, sec, ptype, old_rule, new_policy):
        """
        update_policy updates a policy rule from storage.
        This is part of the Auto-Save feature.
        """
        pass

    def update_policies(self, sec, ptype, old_rules, new_rules):
        """
        UpdatePolicies updates some policy rules to storage, like db, redis.
        """
        pass
