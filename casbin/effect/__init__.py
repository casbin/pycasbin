# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
