from .effector import Effector


class DefaultEffector(Effector):
    """default effector for Casbin."""

    def merge_effects(self, expr, effects, results):
        """merges all matching results collected by the enforcer into a single decision."""

        result = False
        if expr == "some(where (p_eft == allow))":
            for eft in effects:
                if eft == self.ALLOW:
                    result = True
                    break

        elif expr == "!some(where (p_eft == deny))":
            result = True

            for eft in effects:
                if eft == self.DENY:
                    result = False
                    break

        elif expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))":
            for eft in effects:
                if eft == self.ALLOW:
                    result = True
                elif eft == self.DENY:
                    result = False
                    break

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
