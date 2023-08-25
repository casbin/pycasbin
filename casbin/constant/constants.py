# Copyright 2023 The casbin Authors. All Rights Reserved.
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

# Index constants
DOMAIN_INDEX = "dom"
SUBJECT_INDEX = "sub"
OBJECT_INDEX = "obj"
PRIORITY_INDEX = "priority"

# Effect constants
ALLOW_OVERRIDE_EFFECT = "some(where (p_eft == allow))"
DENY_OVERRIDE_EFFECT = "!some(where (p_eft == deny))"
ALLOW_AND_DENY_EFFECT = "some(where (p_eft == allow)) && !some(where (p_eft == deny))"
PRIORITY_EFFECT = "priority(p_eft) || deny"
SUBJECT_PRIORITY_EFFECT = "subjectPriority(p_eft) || deny"
