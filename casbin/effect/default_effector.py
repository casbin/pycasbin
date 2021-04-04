from .effector import Effector


class DefaultEffector(Effector):
    """default effector for Casbin."""

    def merge_effects(self, expr, effects, results):
        """merges all matching results collected by the enforcer into a single decision."""

        result = False

        explain = False

        explain_index = -1

        if type(effects) == list:
            explain = True

        if expr == "some(where (p_eft == allow))":
            if self.ALLOW in effects:
                if explain:
                    explain_index = effects.index(self.ALLOW)
                result = True

        elif expr == "!some(where (p_eft == deny))":
            result = True

            if self.DENY in effects:
                if explain:
                    explain_index = effects.index(self.DENY)
                result = False

        elif expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))":
            if self.DENY in effects:
                if explain:
                    explain_index = effects.index(self.ALLOW)
                result = False
            elif self.ALLOW in effects:
                if explain:
                    explain_index = effects.index(self.DENY)
                result = True

        elif expr == "priority(p_eft) || deny":
            for i, eft in enumerate(effects):
                if eft != self.INDETERMINATE:
                    if eft == self.ALLOW:
                        result = True
                    else:
                        result = False
                    if explain:
                        explain_index = i
                    break
        else:
            raise RuntimeError("unsupported effect")

        if explain:
            return result, explain_index
        else:
            return result
