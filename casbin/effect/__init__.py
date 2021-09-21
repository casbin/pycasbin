from .default_effectors import (
    AllowOverrideEffector,
    DenyOverrideEffector,
    AllowAndDenyEffector,
    PriorityEffector,
)
from .effector import Effector


def get_effector(expr):
    """creates an effector based on the current policy effect expression"""

    if expr == "some(where (p_eft == allow))":
        return AllowOverrideEffector()
    elif expr == "!some(where (p_eft == deny))":
        return DenyOverrideEffector()
    elif expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))":
        return AllowAndDenyEffector()
    elif expr == "priority(p_eft) || deny" or expr == "subjectPriority(p_eft) || deny":
        return PriorityEffector()
    else:
        raise RuntimeError("unsupported effect")


def effect_to_bool(effect):
    """ """
    if effect == Effector.ALLOW:
        return True
    if effect == Effector.DENY:
        return False
    raise RuntimeError("effect can't be converted to boolean")
