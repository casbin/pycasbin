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

from casbin import persist
from .file_adapter import FileAdapter
import os


class Filter:
    # P,G are string []
    P = []
    G = []


class FilteredAdapter(FileAdapter, persist.FilteredAdapter):
    filtered = False
    _file_path = ""
    filter = Filter()
    # new_filtered_adapte is the constructor for FilteredAdapter.
    def __init__(self, file_path):
        self.filtered = True
        self._file_path = file_path

    def load_policy(self, model):
        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")
        self.filtered = False
        self._load_policy_file(model)

    # load_filtered_policy loads only policy rules that match the filter.
    def load_filtered_policy(self, model, filter):
        if filter == None:
            return self.load_policy(model)

        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")

        try:
            filter_value = [filter.__dict__["P"]] + [filter.__dict__["G"]]
        except:
            raise RuntimeError("invalid filter type")

        self.load_filtered_policy_file(model, filter_value, persist.load_policy_line)
        self.filtered = True

    def load_filtered_policy_file(self, model, filter, hanlder):
        with open(self._file_path, "rb") as file:
            while True:
                line = file.readline()
                line = line.decode().strip()
                if line == "\n":
                    continue
                if not line:
                    break
                if filter_line(line, filter):
                    continue

                hanlder(line, model)

    # is_filtered returns true if the loaded policy has been filtered.
    def is_filtered(self):
        return self.filtered

    def save_policy(self, model):
        if self.filtered:
            raise RuntimeError("cannot save a filtered policy")

        self._save_policy_file(model)


def filter_line(line, filter):
    if filter == None:
        return False

    p = line.split(",")
    if len(p) == 0:
        return True
    filter_slice = []

    if p[0].strip() == "p":
        filter_slice = filter[0]
    elif p[0].strip() == "g":
        filter_slice = filter[1]
    return filter_words(p, filter_slice)


def filter_words(line, filter):
    if len(line) < len(filter) + 1:
        return True
    skip_line = False
    for i, v in enumerate(filter):
        if len(v) > 0 and (v.strip() != line[i + 1].strip()):
            skip_line = True
            break

    return skip_line
