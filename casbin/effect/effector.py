class Effector:
    """Effector is the interface for Casbin effectors."""

    ALLOW = 0

    INDETERMINATE = 1

    DENY = 2

    def intermediate_effect(self, effects):
        """returns a intermediate effect based on the matched effects of the enforcer"""
        pass

    def final_effect(self, effects):
        """returns the final effect based on the matched effects of the enforcer"""
        pass
