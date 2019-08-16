import copy
from casbin.management_enforcer import ManagementEnforcer
from functools import reduce


class Enforcer(ManagementEnforcer):
    """
        Enforcer = ManagementEnforcer + RBAC
    """

    """creates an enforcer via file or DB.

        File:
            e = casbin.Enforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
        MySQL DB:
            a = mysqladapter.DBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
            e = casbin.Enforcer("path/to/basic_model.conf", a)
    """

    def get_roles_for_user(self, user):
        """gets the roles that a user has."""
        return self.model.model['g']['g'].rm.get_roles(user)

    def get_roles_for_user_in_domain(self, name, domain):
        """gets the roles that a user has inside a domain."""
        return self.model.model['g']['g'].rm.get_roles(name, domain)

    def get_users_for_role(self, role):
        """gets the users that has a role."""
        return self.model.model['g']['g'].rm.get_users(role)

    def get_users_for_role_in_domain(self, name, domain):
        """gets the users that has a role inside a domain."""
        return self.model.model['g']['g'].rm.get_users(name, domain)

    def has_role_for_user(self, user, role):
        """determines whether a user has a role."""
        roles = self.get_roles_for_user(user)

        return role in roles

    def add_role_for_user(self, user, role):
        """adds a role for a user."""
        """Returns false if the user already has the role (aka not affected)."""
        return self.add_grouping_policy(user, role)

    def add_role_for_user_in_domain(self, user, role, domain):
        """adds a role for a user inside a domain."""
        """Returns false if the user already has the role (aka not affected)."""
        return self.add_grouping_policy(user, role, domain)

    def delete_role_for_user(self, user, role):
        """deletes a role for a user."""
        """Returns false if the user does not have the role (aka not affected)."""
        return self.remove_grouping_policy(user, role)

    def delete_roles_for_user(self, user):
        """deletes all roles for a user."""
        """Returns false if the user does not have any roles (aka not affected)."""
        return self.remove_filtered_grouping_policy(0, user)

    def delete_roles_for_user_in_domain(self, user, role, domain):
        """deletes a role for a user inside a domain."""
        """Returns false if the user does not have any roles (aka not affected)."""
        return self.remove_filtered_grouping_policy(0, user, role, domain)

    def delete_user(self, user):
        """deletes a user."""
        """Returns false if the user does not exist (aka not affected)."""
        return self.remove_filtered_grouping_policy(0, user)

    def delete_role(self, role):
        """deletes a role."""
        self.remove_filtered_grouping_policy(1, role)
        self.remove_filtered_policy(0, role)

    def delete_permission(self, *permission):
        """deletes a permission."""
        """Returns false if the permission does not exist (aka not affected)."""
        return self.remove_filtered_policy(1, *permission)

    def add_permission_for_user(self, user, *permission):
        """adds a permission for a user or role."""
        """Returns false if the user or role already has the permission (aka not affected)."""
        params = [user]
        params.extend(permission)

        return self.add_policy(*params)

    def delete_permission_for_user(self, user, *permission):
        """adds a permission for a user or role."""
        """Returns false if the user or role already has the permission (aka not affected)."""
        params = [user]
        params.extend(permission)

        return self.remove_policy(*params)

    def delete_permissions_for_user(self, user):
        """deletes permissions for a user or role."""
        """Returns false if the user or role does not have any permissions (aka not affected)."""
        return self.remove_filtered_policy(0, user)

    def get_permissions_for_user(self, user):
        """gets permissions for a user or role."""
        return self.get_filtered_policy(0, user)

    def get_permissions_for_user_in_domain(self, user, domain):
        """gets permissions for a user or role inside domain."""
        return self.get_filtered_policy(0, user, domain)

    def has_permission_for_user(self, user, *permission):
        """determines whether a user has a permission."""
        params = [user]
        params.extend(permission)

        return self.has_policy(*params)

    def get_implicit_roles_for_user(self, user, domain=None):
        """
            get_implicit_roles_for_user gets implicit roles that a user has.
            Compared to get_roles_for_user(), this function retrieves indirect roles besides direct roles.
            For example:
                g, alice, role:admin
                g, role:admin, role:user

                get_roles_for_user("alice") can only get: ["role:admin"].
                But get_implicit_roles_for_user("alice") will get: ["role:admin", "role:user"].
        """
        roles = self.get_roles_for_user_in_domain(user, domain) if domain else self.get_roles_for_user(user)
        res = copy.copy(roles)
        for r in roles:
            _roles = self.get_roles_for_user_in_domain(r, domain) if domain else self.get_roles_for_user(r)
            res.extend(_roles)
        return res

    def get_implicit_permissions_for_user(self, user, domain=None):
        """
             gets implicit permissions for a user or role.
            Compared to get_permissions_for_user(), this function retrieves permissions for inherited roles.
            For example:
            p, admin, data1, read
            p, alice, data2, read
            g, alice, admin

            get_permissions_for_user("alice") can only get: [["alice", "data2", "read"]].
            But get_implicit_permissions_for_user("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
        """
        roles = self.get_implicit_roles_for_user(user, domain)
        permissions = self.get_permissions_for_user_in_domain(user,
                                                              domain) if domain else self.get_permissions_for_user(user)
        for role in roles:
            _permissions = self.get_permissions_for_user_in_domain(role,
                                                                   domain) if domain else self.get_permissions_for_user(
                role)
            for item in _permissions:
                if item not in permissions:
                    permissions.append(item)
        return permissions
