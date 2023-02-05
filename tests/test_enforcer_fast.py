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

import os
import time
from unittest import TestCase
from typing import Sequence

import casbin


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


class TestCaseBase(TestCase):
    def get_enforcer(self, model=None, adapter=None, cache_key_order: Sequence[int] = None):
        return casbin.Enforcer(
            model,
            adapter,
            cache_key_order,
        )


class TestFastEnforcer(TestCaseBase):
    def test_creates_proper_policy(self) -> None:
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
            [2, 1],
        )

        assert isinstance(e.model.model["p"]["p"].policy, casbin.FastPolicy)

    def test_initializes_model(self) -> None:
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
            [2, 1],
        )

        assert list(e.model.model["p"]["p"].policy) == [
            ["alice", "data1", "read"],
            ["bob", "data2", "write"],
        ]

    def test_able_to_clear_policy(self) -> None:
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
            [2, 1],
        )

        e.clear_policy()

        assert isinstance(e.model.model["p"]["p"].policy, casbin.FastPolicy)
        assert list(e.model.model["p"]["p"].policy) == []

    def test_able_to_enforce_rule(self) -> None:
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
            [2, 1],
        )

        assert e.enforce("alice", "data1", "read")
        assert not e.enforce("alice2", "data1", "read")
