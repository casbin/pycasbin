import persist

class BatchAdapter:
    '''the interface for Casbin adapters with multiple add and remove policy functions'''

    def add_policies(self, sec, ptype, rules):
        '''AddPolicies adds policy rules to the storage.
            This is part of the Auto-Save feature.'''
        pass

    def remove_policies(self, sec, ptype, rules):
        '''RemovePolicies removes policy rules from the storage.
            This is part of the Auto-Save feature.'''
        pass