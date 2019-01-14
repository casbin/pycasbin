from casbin import persist
import os


class FileAdapter(persist.Adapter):
    """the file adapter for Casbin.
    It can load policy from file or save policy to file.
    """

    _file_path = ""

    def __init__(self, file_path):
        self._file_path = file_path

    def load_policy(self, model):
        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")

        self._load_policy_file(model)

    def save_policy(self, model):
        pass

    def _load_policy_file(self, model):
        with open(self._file_path, "rb") as file:
            line = file.readline()
            while line:
                persist.load_policy_line(line.decode().strip(), model)
                line = file.readline()

    def _save_policy_file(self, text):
        pass

    def add_policy(self, sec, ptype, rule):
        pass

    def remove_policy(self, sec, ptype, rule):
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        pass
