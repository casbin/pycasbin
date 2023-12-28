# NOTE: this file exists as a backwards compatible alias. please directly
# use FilteredFileAdapter from `casbin.persist.adapters.filtered_file_adapter` instead.

from .filtered_file_adapter import Filter
from .filtered_file_adapter import FilteredFileAdapter as FilteredAdapter

__all__ = ["Filter", "FilteredAdapter"]
