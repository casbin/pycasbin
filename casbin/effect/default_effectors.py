from .effector import Effector


class AllowOverrideEffector(Effector):
    def intermediate_effect(self, effects):
        """returns a intermediate effect based on the matched effects of the enforcer"""
        if Effector.ALLOW in effects:
            return Effector.ALLOW
        return Effector.INDETERMINATE

    def final_effect(self, effects):
        """returns the final effect based on the matched effects of the enforcer"""
        if Effector.ALLOW in effects:
            return Effector.ALLOW
        return Effector.DENY


class DenyOverrideEffector(Effector):
    def intermediate_effect(self, effects):
        """returns a intermediate effect based on the matched effects of the enforcer"""
        if Effector.DENY in effects:
            return Effector.DENY
        return Effector.INDETERMINATE

    def final_effect(self, effects):
        """returns the final effect based on the matched effects of the enforcer"""
        if Effector.DENY in effects:
            return Effector.DENY
        return Effector.ALLOW


class AllowAndDenyEffector(Effector):
    def intermediate_effect(self, effects):
        """returns a intermediate effect based on the matched effects of the enforcer"""
        if Effector.DENY in effects:
            return Effector.DENY
        return Effector.INDETERMINATE

    def final_effect(self, effects):
        """returns the final effect based on the matched effects of the enforcer"""
        if Effector.DENY in effects or Effector.ALLOW not in effects:
            return Effector.DENY
        return Effector.ALLOW


class PriorityEffector(Effector):
    def intermediate_effect(self, effects):
        """returns a intermediate effect based on the matched effects of the enforcer"""
        if Effector.ALLOW in effects:
            return Effector.ALLOW
        if Effector.DENY in effects:
            return Effector.DENY
        return Effector.INDETERMINATE

    def final_effect(self, effects):
        """returns the final effect based on the matched effects of the enforcer"""
        if Effector.ALLOW in effects:
            return Effector.ALLOW
        if Effector.DENY in effects:
            return Effector.DENY
        return Effector.DENY
