import logging
from casbin.model.policy_op import PolicyOp


class Assertion:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.key = ""
        self.value = ""
        self.tokens = []
        self.policy = []
        self.rm = None
        self.priority_index: int = -1
        self.policy_map: dict = {}

    def build_role_links(self, rm):
        self.rm = rm
        count = self.value.count("_")
        if count < 2:
            raise RuntimeError(
                'the number of "_" in role definition should be at least 2'
            )

        for rule in self.policy:
            if len(rule) < count:
                raise RuntimeError(
                    "grouping policy elements do not meet role definition"
                )
            if len(rule) > count:
                rule = rule[:count]

            self.rm.add_link(*rule[:count])

        self.logger.info("Role links for: {}".format(self.key))
        self.rm.print_roles()

    def build_incremental_role_links(self, rm, op, rules):
        self.rm = rm
        count = self.value.count("_")
        if count < 2:
            raise RuntimeError(
                'the number of "_" in role definition should be at least 2'
            )
        for rule in rules:
            if len(rule) < count:
                raise TypeError("grouping policy elements do not meet role definition")
            if len(rule) > count:
                rule = rule[:count]
            if op == PolicyOp.Policy_add:
                rm.add_link(rule[0], rule[1], *rule[2:])
            elif op == PolicyOp.Policy_remove:
                rm.delete_link(rule[0], rule[1], *rule[2:])
            else:
                raise TypeError("Invalid operation: " + str(op))
