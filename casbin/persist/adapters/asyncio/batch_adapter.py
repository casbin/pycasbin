from abc import ABCMeta, abstractmethod


class AsyncBatchAdapter(metaclass=ABCMeta):
    """AsyncBatchAdapter is the interface for async Casbin adapters with multiple add and remove policy functions."""

    @abstractmethod
    async def add_policies(self, sec, ptype, rules):
        """AddPolicies adds policy rules to the storage."""
        pass

    @abstractmethod
    async def remove_policies(self, sec, ptype, rules):
        """RemovePolicies removes policy rules from the storage."""
        pass
