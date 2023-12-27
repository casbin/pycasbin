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

from .file_adapter import FileAdapter
from .filtered_file_adapter import FilteredFileAdapter
from ..update_adapter import UpdateAdapter

# alias import for backwards compatibility
FilteredAdapter = FilteredFileAdapter

__all__ = ["FileAdapter", "FilteredFileAdapter", "FilteredAdapter", "UpdateAdapter"]
