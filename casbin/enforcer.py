from casbin.management_enforcer import ManagementEnforcer
from casbin.util import join_slice, set_subtract

class Enforcer(ManagementEnforcer):
    """
        Enforcer = ManagementEnforcer + RBAC_API + RBAC_WITH_DOMAIN_API
    """

    """creates an enforcer via file or DB.

        File:
            e = casbin.Enforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
        MySQL DB:
            a = mysqladapter.DBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
            e = casbin.Enforcer("path/to/basic_model.conf", a)
    """

    def get_roles_for_user(self, name):
        """ gets the roles that a user has. """
        return self.model.model["g"]["g"].rm.get_roles(name)

    def get_users_for_role(self, name):
        """ gets the users that has a role. """
        return self.model.model["g"]["g"].rm.get_users(name)

    def has_role_for_user(self, name, role):
        """ determines whether a user has a role. """
        roles = self.get_roles_for_user(name)

        hasRole = False
        for r in roles:
            if r == role:
                hasRole = True
                break

        return hasRole

    def add_role_for_user(self, user, role):
        """
        adds a role for a user.
        Returns false if the user already has the role (aka not affected).
        """
        return self.add_grouping_policy(user, role)

    def delete_role_for_user(self, user, role):
        """
        deletes a role for a user.
        Returns false if the user does not have the role (aka not affected).
        """
        return self.remove_grouping_policy(user, role)

    def delete_roles_for_user(self, user):
        """
        deletes all roles for a user.
        Returns false if the user does not have any roles (aka not affected).
        """
        return self.remove_filtered_grouping_policy(0, user)

    def delete_user(self, user):
        """
        deletes a user.
        Returns false if the user does not exist (aka not affected).
        """
        res1 = self.remove_filtered_grouping_policy(0, user)

        res2 = self.remove_filtered_policy(0, user)
        return res1 or res2

    def delete_role(self, role):
        """
        deletes a role.
        Returns false if the role does not exist (aka not affected).
        """
        res1 = self.remove_filtered_grouping_policy(1, role)

        res2 = self.remove_filtered_policy(0, role)
        return res1 or res2

    def delete_permission(self, *permission):
        """
        deletes a permission.
        Returns false if the permission does not exist (aka not affected).
        """
        return self.remove_filtered_policy(1, *permission)

    def add_permission_for_user(self, user, *permission):
        """
        adds a permission for a user or role.
        Returns false if the user or role already has the permission (aka not affected).
        """
        return self.add_policy(join_slice(user, *permission))

    def delete_permission_for_user(self, user, *permission):
        """
        deletes a permission for a user or role.
        Returns false if the user or role does not have the permission (aka not affected).
        """
        return self.remove_policy(join_slice(user, *permission))

    def delete_permissions_for_user(self, user):
        """
        deletes permissions for a user or role.
        Returns false if the user or role does not have any permissions (aka not affected).
        """
        return self.remove_filtered_policy(0, user)

    def get_permissions_for_user(self, user):
        """
        gets permissions for a user or role.
        """
        return self.get_filtered_policy(0, user)

    def has_permission_for_user(self, user, *permission):
        """
        determines whether a user has a permission.
        """
        return self.has_policy(join_slice(user, *permission))

    def get_implicit_roles_for_user(self, name, *domain):
        """
        gets implicit roles that a user has.
        Compared to get_roles_for_user(), this function retrieves indirect roles besides direct roles.
        For example:
        g, alice, role:admin
        g, role:admin, role:user

        get_roles_for_user("alice") can only get: ["role:admin"].
        But get_implicit_roles_for_user("alice") will get: ["role:admin", "role:user"].
        """
        res = list()
        roleSet = dict()
        roleSet[name] = True

        q = list()
        q.append(name)

        while len(q) > 0:
            name = q[0]
            q = q[1:]

            roles = self.rm.get_roles(name, *domain)
            for r in roles:
                if  r not in roleSet:
                    res.append(r)
                    q.append(r)
                    roleSet[r] = True

        return res

    def get_implicit_permissions_for_user(self, user, *domain):
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
        roles = self.get_implicit_roles_for_user(user, *domain)

        roles.insert(0, user)

        withDomain = False
        if len(domain) == 1:
            withDomain = True
        elif len(domain) > 1:
            return None

        res = []
        permissions = [list()]
        for role in roles:
            if withDomain:
                permissions = self.get_permissions_for_user_in_domain(role, domain[0])
            else:
                permissions = self.get_permissions_for_user(role)
            res.extend(permissions)

        return res

    def get_implicit_users_for_permission(self, *permission):
        """
        gets implicit users for a permission.
        For example:
        p, admin, data1, read
        p, bob, data1, read
        g, alice, admin

        get_implicit_users_for_permission("data1", "read") will get: ["alice", "bob"].
        Note: only users will be returned, roles (2nd arg in "g") will be excluded.
        """
        subjects = self.get_all_subjects()
        roles = self.get_all_roles()

        users = set_subtract(subjects, roles)

        res = list()
        for user in users:
            req = join_slice(user, *permission)
            allowed = self.enforce(*req)

            if allowed:
                res.append(user)

        return res

    def get_roles_for_user_in_domain(self, name, domain):
        """gets the roles that a user has inside a domain."""
        return self.model.model['g']['g'].rm.get_roles(name, domain)

    def get_users_for_role_in_domain(self, name, domain):
        """gets the users that has a role inside a domain."""
        return self.model.model['g']['g'].rm.get_users(name, domain)

    def add_role_for_user_in_domain(self, user, role, domain):
        """adds a role for a user inside a domain."""
        """Returns false if the user already has the role (aka not affected)."""
        return self.add_grouping_policy(user, role, domain)

    def delete_roles_for_user_in_domain(self, user, role, domain):
        """deletes a role for a user inside a domain."""
        """Returns false if the user does not have any roles (aka not affected)."""
        return self.remove_filtered_grouping_policy(0, user, role, domain)

    def get_permissions_for_user_in_domain(self, user, domain):
        """gets permissions for a user or role inside domain."""
        return self.get_filtered_policy(0, user, domain)