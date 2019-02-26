from casbin import log


class Policy:
    def __init__(self):
        self.model = {}

    def build_role_links(self, rm):
        if "g" not in self.model.keys():
            return

        for ast in self.model["g"].values():
            ast.build_role_links(rm)

    def print_policy(self):
        log.log_print("Policy:")
        for sec in ["p", "g"]:
            if sec not in self.model.keys():
                continue

            for key, ast in self.model[sec].items():
                log.log_print(key, ": ", ast.value, ": ", ast.policy)

    def clear_policy(self):
        for sec in ["p", "g"]:
            if sec not in self.model.keys():
                continue

            for key, ast in self.model[sec].items():
                self.model[sec][key].policy = []

    def get_policy(self, sec, ptype):
        return self.model[sec][ptype].policy
