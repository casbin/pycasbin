from abc import ABCMeta, abstractmethod


class AsyncAdapter(metaclass=ABCMeta):
    """The interface for async Casbin adapters."""

    @abstractmethod
    async def load_policy(self, model):
        """loads all policy rules from the storage."""
        pass

    @abstractmethod
    async def save_policy(self, model):
        """saves all policy rules to the storage."""
        pass

    @abstractmethod
    async def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        pass

    @abstractmethod
    async def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        pass

    @abstractmethod
    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        pass
