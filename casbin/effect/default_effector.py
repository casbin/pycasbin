from .effector import Effector


class DefaultEffector(Effector):
    """default effector for Casbin."""

    def merge_effects(self, expr, effects, results):
        """merges all matching results collected by the enforcer into a single decision."""

        effects = set(effects)
        result = False
        if expr == "some(where (p_eft == allow))":
            if self.ALLOW in effects:
                result = True

        elif expr == "!some(where (p_eft == deny))":
            result = True

            if self.DENY in effects:
                result = False

        elif expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))":
            if self.DENY in effects:
                result = False
            elif self.ALLOW in effects:
                result = True

        elif expr == "priority(p_eft) || deny":
            for eft in effects:
                if eft != self.INDETERMINATE:
                    if eft == self.ALLOW:
                        result = True
                    else:
                        result = False
                    break
        else:
            raise RuntimeError("unsupported effect")

        return result
