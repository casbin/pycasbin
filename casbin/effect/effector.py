class Effector:
    """Effector is the interface for Casbin effectors."""

    ALLOW = 0

    INDETERMINATE = 1

    DENY = 2

    def merge_effects(self, expr, effects, results):
        """merges all matching results collected by the enforcer into a single decision."""
        pass
