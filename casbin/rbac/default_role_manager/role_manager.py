from casbin.rbac import RoleManager
import logging


class RoleManager(RoleManager):
    """provides a default implementation for the RoleManager interface"""

    all_roles = dict()
    max_hierarchy_level = 0

    def __init__(self, max_hierarchy_level):
        self.logger = logging.getLogger()
        self.all_roles = dict()
        self.max_hierarchy_level = max_hierarchy_level
        self.matching_func = None

    def add_matching_func(self, fn):
        self.matching_func = fn

    def has_role(self, name):
        if self.matching_func is None:
            return name in self.all_roles.keys()
        else:
            for key in self.all_roles.keys():
                if self.matching_func(name, key):
                    return True
        return False

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
            raise RuntimeError("error: domain should be 1 parameter")

        role1 = self.create_role(name1)
        role2 = self.create_role(name2)
        role1.add_role(role2)

        if self.matching_func is not None:
            for key, role in self.all_roles.items():
                if self.matching_func(key, name1) and name1 != key:
                    self.all_roles[key].add_role(role1)
                if self.matching_func(key, name2) and name2 != key:
                    self.all_roles[name2].add_role(role)
                if self.matching_func(name1, key) and name1 != key:
                    self.all_roles[key].add_role(role1)
                if self.matching_func(name2, key) and name2 != key:
                    self.all_roles[name2].add_role(role)

    def delete_link(self, name1, name2, *domain):
        if len(domain) == 1:
            name1 = domain[0] + "::" + name1
            name2 = domain[0] + "::" + name2
        elif len(domain) > 1:
            raise RuntimeError("error: domain should be 1 parameter")

        if not self.has_role(name1) or not self.has_role(name2):
            raise RuntimeError("error: name1 or name2 does not exist")

        role1 = self.create_role(name1)
        role2 = self.create_role(name2)
        role1.delete_role(role2)

    def has_link(self, name1, name2, *domain):
        if len(domain) == 1:
            name1 = domain[0] + "::" + name1
            name2 = domain[0] + "::" + name2
        elif len(domain) > 1:
            raise RuntimeError("error: domain should be 1 parameter")

        if name1 == name2:
            return True

        if not self.has_role(name1) or not self.has_role(name2):
            return False

        if self.matching_func is None:
            role1 = self.create_role(name1)
            return role1.has_role(name2, self.max_hierarchy_level)
        else:
            for key, role in self.all_roles.items():
                if self.matching_func(name1, key) and role.has_role(name2, self.max_hierarchy_level, self.matching_func):
                    return True
            return False        

    def get_roles(self, name, *domain):
        """
        gets the roles that a subject inherits.
        domain is a prefix to the roles.
        """
        if len(domain) == 1:
            name = domain[0] + "::" + name
        elif len(domain) > 1:
            return RuntimeError("error: domain should be 1 parameter")

        if not self.has_role(name):
            return []

        roles = self.create_role(name).get_roles()
        if len(domain) == 1:
            for key, value in enumerate(roles):
                roles[key] = value[len(domain[0]) + 2:]

        return roles

    def get_users(self, name, *domain):
        """
        gets the users that inherits a subject.
        domain is an unreferenced parameter here, may be used in other implementations.
        """
        if len(domain) == 1:
            name = domain[0] + "::" + name
        elif len(domain) > 1:
            return RuntimeError("error: domain should be 1 parameter")

        if not self.has_role(name):
            return []

        names = []
        for role in self.all_roles.values():
            if role.has_direct_role(name):
                if len(domain) == 1:
                    names.append(role.name[len(domain[0]) + 2:])
                else:
                    names.append(role.name)

        return names

    def print_roles(self):
        line = []
        for role in self.all_roles.values():
            text = role.to_string()
            if text:
                line.append(text)
        self.logger.info(", ".join(line))


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

    def has_role(self, name, hierarchy_level, matching_func=None):
        if self.has_direct_role(name, matching_func):
            return True
        if hierarchy_level <= 0:
            return False

        for role in self.roles:
            if role.has_role(name, hierarchy_level - 1, matching_func):
                return True

        return False

    def has_direct_role(self, name, matching_func=None):
        if matching_func is None:
            for role in self.roles:
                if role.name == name:
                    return True
        else:
            for role in self.roles:
                if matching_func(name, role.name):
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
