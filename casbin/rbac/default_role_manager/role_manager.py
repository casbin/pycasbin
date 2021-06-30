import logging

from casbin.rbac import RoleManager


class RoleManager(RoleManager):
    """provides a default implementation for the RoleManager interface"""

    all_roles = dict()
    max_hierarchy_level = 0

    def __init__(self, max_hierarchy_level=10):
        self.logger = logging.getLogger(__name__)
        self.all_roles = dict()
        self.max_hierarchy_level = max_hierarchy_level
        self.matching_func = None
        self.domain_matching_func = None
        self.has_pattern = False
        self.has_domain_pattern = False

    def add_matching_func(self, fn=None):
        self.has_pattern = True
        self.matching_func = fn

    def add_domain_matching_func(self, fn=None):
        self.has_domain_pattern = True
        self.domain_matching_func = fn

    def has_role(self, role):

        if not self.has_pattern and not self.has_domain_pattern:
            return role in self.all_roles.values()

        for known_role in list(self.all_roles.values()):
            if self.has_pattern:
                if not self.matching_func(role.name, known_role.name):
                    continue
            else:
                if not role.name == known_role.name:
                    continue

            if self.has_domain_pattern:
                if not self.domain_matching_func(role.domain, known_role.domain):
                    continue
            else:
                if not role.domain == known_role.domain:
                    continue
            return True

    def create_role(self, name, domain=""):
        role = Role(name, domain)
        if domain:
            key = domain + "::" + name
        else:
            key = name

        if key not in self.all_roles.keys():
            self.all_roles[key] = role

        return self.all_roles[key]

    def clear(self):
        self.all_roles.clear()

    def add_link(self, name1, name2, *domain):
        if len(domain) > 1:
            raise RuntimeError("error: domain should be 1 parameter")
        elif len(domain) == 1:
            domain = domain[0]
        else:
            domain = ""

        role1 = self.create_role(name1, domain)
        role2 = self.create_role(name2, domain)
        role1.add_role(role2)

        if self.has_pattern:
            for role in self.all_roles.values():
                if self.has_domain_pattern:
                    if not self.domain_matching_func(domain, role.domain):
                        continue
                else:
                    if domain != role.domain:
                        continue

                def duplicate_judge():
                    return role1.name != role.name and role2.name != role.name

                if (
                    match_error_handler(self.matching_func, role.name, role1.name)
                    or match_error_handler(self.matching_func, role1.name, role.name)
                    and duplicate_judge()
                ):
                    self.all_roles[role.get_key()].add_role(role1)

                if (
                    match_error_handler(self.matching_func, role.name, role2.name)
                    or match_error_handler(self.matching_func, role2.name, role.name)
                    and duplicate_judge()
                ):
                    self.all_roles[role2.get_key()].add_role(role)

    def delete_link(self, name1, name2, *domain):
        role1, role2 = two_role_domain_wrapper(self, name1, name2, domain)

        if not self.has_role(role1) or not self.has_role(role2):
            raise RuntimeError("error: name1 or name2 does not exist")

        role1.delete_role(role2)

    def has_link(self, name1, name2, *domain):
        if len(domain) > 1:
            raise RuntimeError("error: domain should be 1 parameter")
        elif len(domain) == 1:
            domain = domain[0]
        else:
            domain = ""

        role1, role2 = two_role_domain_wrapper(self, name1, name2, domain)

        if role1 == role2:
            return True

        if not self.has_role(role1) or not self.has_role(role2):
            return False

        if not self.has_pattern and not self.has_domain_pattern:
            return role1.has_role(role2, self.max_hierarchy_level, None, None)

        # Here is has_pattern logic.
        for role in self.all_roles.values():
            if self.has_domain_pattern:
                if not self.domain_matching_func(domain, role.domain):
                    continue
            else:
                if role.domain != domain:
                    continue

            def role_judge():
                if role.has_role(
                    role2,
                    self.max_hierarchy_level,
                    self.matching_func,
                    self.domain_matching_func,
                ):
                    return True
                return False

            if self.has_pattern:
                if self.matching_func(role1.name, role.name):
                    if role_judge():
                        return True
                    continue
            else:
                if role1.name == role.name:
                    if role_judge():
                        return True
                    continue
        return False

    def get_roles(self, name, *domain):
        """
        gets the roles that a subject inherits.
        domain is a prefix to the roles.
        """
        if len(domain) > 1:
            raise RuntimeError("error: domain should be 1 parameter")
        elif len(domain) == 1:
            domain = domain[0]
        else:
            domain = ""

        role = role_domain_wrapper(self, name, domain)

        if not self.has_role(role):
            return []

        roles = self.create_role(name, domain).get_roles()

        return roles

    def get_users(self, name, *domain):
        """
        gets the users that inherits a subject.
        domain is an unreferenced parameter here, may be used in other implementations.
        """
        target_role = role_domain_wrapper(self, name, domain)

        if not self.has_role(target_role):
            return []

        roles = []
        for role in self.all_roles.values():
            if role.has_direct_role(target_role):
                roles.append(role.name)

        return roles

    def print_roles(self):
        line = []
        for role in self.all_roles.values():
            text = role.to_string()
            if text:
                line.append(text)
        self.logger.info(", ".join(line))


class Role:
    """represents the data structure for a role in RBAC."""

    def __init__(self, name: str, domain: str = ""):
        self.name = name
        self.roles = []
        self.domain = domain

    def __eq__(self, other: "Role"):
        return (
            type(other) == type(self)
            and self.name == other.name
            and self.domain == other.domain
        )

    def __hash__(self):
        return hash(self.name + "::" + self.domain)

    def get_key(self):
        if self.domain:
            return self.domain + "::" + self.name
        return self.name

    def add_role(self, role: "Role"):
        if role in self.roles:
            return
        self.roles.append(role)

    def delete_role(self, role: "Role"):
        if role in self.roles:
            self.roles.remove(role)

    def has_role(
        self,
        role: "Role",
        hierarchy_level: int,
        matching_func=None,
        domain_matching_func=None,
    ):

        if self.has_direct_role(role, matching_func, domain_matching_func):
            return True
        if hierarchy_level <= 0:
            return False

        for knownRole in self.roles:
            if knownRole.has_role(
                role, hierarchy_level - 1, matching_func, domain_matching_func
            ):
                return True

        return False

    def has_direct_role(
        self, role: "Role", matching_func=None, domain_matching_func=None
    ):
        for known_role in self.roles:
            if matching_func:
                if not matching_func(role.name, known_role.name):
                    continue
            else:
                if not role.name == known_role.name:
                    continue

            if domain_matching_func:
                if not domain_matching_func(role.domain, known_role.domain):
                    continue
            else:
                if not role.domain == known_role.domain:
                    continue
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
        roles = []
        for role in self.roles:
            roles.append(role.name)

        return roles


def role_domain_wrapper(obj, name, domain):
    if type(domain) != str:
        if not domain or len(domain) == 0:
            domain = ""
        elif len(domain) == 1:
            domain = domain[0]
        elif len(domain) > 1:
            raise RuntimeError("error: domain should be 1 parameter")

    role = Role(name, domain)

    if not obj.has_role(role):
        return role
    return obj.create_role(name, domain)


def two_role_domain_wrapper(obj, name1, name2, domain):
    return role_domain_wrapper(obj, name1, domain), role_domain_wrapper(
        obj, name2, domain
    )


def match_error_handler(fn, key1, key2):
    try:
        return fn(key1, key2)
    except:
        return False
