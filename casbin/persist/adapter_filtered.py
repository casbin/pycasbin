from .adapter import Adapter

""" FilteredAdapter is the interface for Casbin adapters supporting filtered policies."""


class FilteredAdapter(Adapter):
    def is_filtered(self):
        """IsFiltered returns true if the loaded policy has been filtered
        Marks if the loaded policy is filtered or not
        """
        pass

    def load_filtered_policy(self, model, filter):
        """Loads policy rules that match the filter from the storage."""
        pass
