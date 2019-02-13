from casbin import log
from casbin.rbac import RoleManager


class RoleManager(RoleManager):
    """provides a default implementation for the RoleManager interface"""

    all_roles = dict()
    max_hierarchy_level = 0

    def __init__(self, max_hierarchy_level):
        self.all_roles = dict()
        self.max_hierarchy_level = max_hierarchy_level

    def has_role(self, name):
        return name in list(self.all_roles.keys())

    def create_role(self, name):
        if name not in self.all_roles.keys():
            self.all_roles[name] = Role(name)

        return self.all_roles[name]

    def clear(self):
        self.all_roles.clear()

    def add_link(self, name1, name2, *domain):
        if len(domain) == 1:
            name1 = domain[0] + "::" + name1
            name2 = domain[0] + "::" + name2
        elif len(domain) > 1:
            return RuntimeError("error: domain should be 1 parameter")

        role1 = self.create_role(name1)
        role2 = self.create_role(name2)
        role1.add_role(role2)

    def delete_link(self, name1, name2, *domain):
        if len(domain) == 1:
            name1 = domain[0] + "::" + name1
            name2 = domain[0] + "::" + name2
        elif len(domain) > 1:
            return RuntimeError("error: domain should be 1 parameter")

        if not self.has_role(name1) or not self.has_role(name2):
            return RuntimeError("error: name1 or name2 does not exist")

        role1 = self.create_role(name1)
        role2 = self.create_role(name2)
        role1.delete_role(role2)

    def has_link(self, name1, name2, *domain):
        if len(domain) == 1:
            name1 = domain[0] + "::" + name1
            name2 = domain[0] + "::" + name2
        elif len(domain) > 1:
            return RuntimeError("error: domain should be 1 parameter")

        if name1 == name2:
            return True

        if not self.has_role(name1) or not self.has_role(name2):
            return False

        role1 = self.create_role(name1)

        return role1.has_role(name2, self.max_hierarchy_level)

    def get_roles(self, name, *domain):
        if len(domain) == 1:
            name = domain[0] + "::" + name
        elif len(domain) > 1:
            return RuntimeError("error: domain should be 1 parameter")

        if not self.has_role(name):
            return dict()

        roles = self.create_role(name).get_roles()
        if len(domain) == 1:
            for value in roles:
                value = value[len(domain[0]) + 2:]

        return roles

    def get_users(self, name, *domain):
        if not self.has_role(name):
            return RuntimeError("error: name does not exist")

        names = []
        for role in self.all_roles.values():
            if role.has_direct_role(name):
                names.append(name)

        return names

    def print_roles(self):
        line = []
        for role in self.all_roles.values():
            text = role.to_string()
            if text:
                line.append(text)

        log.log_print(", ".join(line))


class Role:
    """represents the data structure for a role in RBAC."""

    name = ""

    roles = []

    def __init__(self, name):
        self.name = name
        self.roles = []

    def add_role(self, role):
        for rr in self.roles:
            if rr.name == role.name:
                return

        self.roles.append(role)

    def delete_role(self, role):
        for rr in self.roles:
            if rr.name == role.name:
                self.roles.remove(rr)
                return

    def has_role(self, name, hierarchy_level):
        if name == self.name:
            return True
        if hierarchy_level <= 0:
            return False

        for role in self.roles:
            if role.has_role(name, hierarchy_level - 1):
                return True

        return False

    def has_direct_role(self, name):
        for role in self.roles:
            if role.name == name:
                return True

        return False

    def to_string(self):
        if len(self.roles) == 0:
            return ""

        names = ", ".join(self.get_roles())

        if len(self.roles) == 1:
            return self.name + " < " + names
        else:
            return self.name + " < (" + names + ")"

    def get_roles(self):
        names = []
        for role in self.roles:
            names.append(role.name)

        return names
