from abc import ABCMeta, abstractmethod


class AsyncFilteredAdapter(metaclass=ABCMeta):
    """AsyncFilteredAdapter is the interface for async Casbin adapters supporting filtered policies."""

    @abstractmethod
    async def is_filtered(self):
        """IsFiltered returns true if the loaded policy has been filtered
        Marks if the loaded policy is filtered or not
        """
        pass

    @abstractmethod
    async def load_filtered_policy(self, model, filter):
        """Loads policy rules that match the filter from the storage."""
        pass
