from abc import ABCMeta, abstractmethod


class AsyncUpdateAdapter(metaclass=ABCMeta):
    """AsyncUpdateAdapter is the interface for async Casbin adapters with add update policy function."""

    @abstractmethod
    async def update_policy(self, sec, ptype, old_rule, new_policy):
        """
        update_policy updates a policy rule from storage.
        This is part of the Auto-Save feature.
        """
        pass

    @abstractmethod
    async def update_policies(self, sec, ptype, old_rules, new_rules):
        """
        UpdatePolicies updates some policy rules to storage, like db, redis.
        """
        pass

    @abstractmethod
    async def update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        """
        update_filtered_policies deletes old rules and adds new rules.
        """
        pass
