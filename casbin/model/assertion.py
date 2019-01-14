from casbin import log


class Assertion:
    key = ""
    value = ""
    tokens = []
    policy = []
    rm = None

    def build_role_links(self, rm):
        self.rm = rm
        count = self.value.count("_")

        for rule in self.policy:
            if count < 2:
                raise RuntimeError('the number of "_" in role definition should be at least 2')

            if len(rule) < count:
                raise RuntimeError("grouping policy elements do not meet role definition")

            if count == 2:
                self.rm.add_link(rule[0], rule[1])
            elif count == 3:
                self.rm.add_link(rule[0], rule[1], rule[2])
            elif count == 4:
                self.rm.add_link(rule[0], rule[1], rule[2], rule[3])

        log.log_print("Role links for: " + self.key)
        self.rm.print_roles()
