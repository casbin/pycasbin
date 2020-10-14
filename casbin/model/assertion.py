from casbin import log


class Assertion:
    def __init__(self):
        self.key = ""
        self.value = ""
        self.tokens = []
        self.policy = []
        self.rm = None

    def build_role_links(self, rm):
        self.rm = rm
        count = self.value.count("_")

        for rule in self.policy:
            if count < 2:
                raise RuntimeError('the number of "_" in role definition should be at least 2')

            if len(rule) < count:
                raise RuntimeError("grouping policy elements do not meet role definition")

            self.rm.add_link(*rule[:count])

        log.log_print("Role links for: " + self.key)
        self.rm.print_roles()
