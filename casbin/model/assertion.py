import logging


class Assertion:
    def __init__(self):
        self.logger = logging.getLogger()
        self.key = ""
        self.value = ""
        self.tokens = []
        self.policy = set()
        self.rm = None

    def build_role_links(self, rm):
        self.rm = rm
        count = self.value.count("_")
        if count < 2:
            raise RuntimeError('the number of "_" in role definition should be at least 2')

        for rule in self.policy:
            if len(rule) < count:
                raise RuntimeError("grouping policy elements do not meet role definition")

            self.rm.add_link(*rule[:count])

        self.logger.info("Role links for: {}".format(self.key))
        self.rm.print_roles()
