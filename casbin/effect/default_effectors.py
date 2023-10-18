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

from .effector import Effector

class BaseEffector(Effector):
    def intermediate_effect(self, effects):
        if Effector.ALLOW in effects:
            return Effector.ALLOW
        if Effector.DENY in effects:
            return Effector.DENY
        return Effector.INDETERMINATE

    def final_effect(self, effects):
        if Effector.DENY in effects:
            return Effector.DENY
        if Effector.ALLOW in effects:
            return Effector.ALLOW
        return Effector.DENY

class AllowOverrideEffector(BaseEffector):
    def intermediate_effect(self, effects):
        return Effector.ALLOW if Effector.ALLOW in effects else Effector.INDETERMINATE

    def final_effect(self, effects):
        return Effector.ALLOW if Effector.ALLOW in effects else Effector.DENY

class DenyOverrideEffector(BaseEffector):
    def intermediate_effect(self, effects):
        return Effector.DENY if Effector.DENY in effects else Effector.INDETERMINATE

    def final_effect(self, effects):
        return Effector.DENY if Effector.DENY in effects else Effector.ALLOW

class AllowAndDenyEffector(BaseEffector):
    def intermediate_effect(self, effects):
        return Effector.DENY if Effector.DENY in effects else Effector.INDETERMINATE

    def final_effect(self, effects):
        return Effector.DENY if Effector.DENY in effects or Effector.ALLOW not in effects else Effector.ALLOW

class PriorityEffector(BaseEffector):
    def intermediate_effect(self, effects):
        if Effector.ALLOW in effects:
            return Effector.ALLOW
        if Effector.DENY in effects:
            return Effector.DENY
        return Effector.INDETERMINATE

    def final_effect(self, effects):
        if Effector.ALLOW in effects:
            return Effector.ALLOW
        if Effector.DENY in effects:
            return Effector.DENY
        return Effector.DENY

