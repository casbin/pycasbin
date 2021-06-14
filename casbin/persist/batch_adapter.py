from .adapter import Adapter

"""BatchAdapter is the interface for Casbin adapters with multiple add and remove policy functions."""


class BatchAdapter(Adapter):
    def add_policies(self, sec, ptype, rules):
        """AddPolicies adds policy rules to the storage."""
        pass

    def remove_policies(self, sec, ptype, rules):
        """RemovePolicies removes policy rules from the storage."""
        pass
