from casbin.management_enforcer import ManagementEnforcer


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

    def get_users_for_role(self, role):
        """gets the users that has a role."""
        return self.model.model['g']['g'].rm.get_users(role)

    def has_role_for_user(self, user, role):
        """determines whether a user has a role."""
        roles = self.get_roles_for_user(user)

        for r in roles:
            if r == role:
                return True

        return False

    def add_role_for_user(self, user, role):
        """adds a role for a user."""
        """Returns false if the user already has the role (aka not affected)."""
        return self.add_grouping_policy(user, role)

    def delete_role_for_user(self, user, role):
        """deletes a role for a user."""
        """Returns false if the user does not have the role (aka not affected)."""
        return self.remove_grouping_policy(user, role)

    def delete_roles_for_user(self, user):
        """deletes all roles for a user."""
        """Returns false if the user does not have any roles (aka not affected)."""
        return self.remove_filtered_grouping_policy(0, user)

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
        return self.add_policy(*permission)

    def delete_permission_for_user(self, user, *permission):
        """adds a permission for a user or role."""
        """Returns false if the user or role already has the permission (aka not affected)."""
        return self.remove_policy(*permission)

    def delete_permissions_for_user(self, user):
        """deletes permissions for a user or role."""
        """Returns false if the user or role does not have any permissions (aka not affected)."""
        return self.remove_filtered_policy(0, user)

    def get_permissions_for_user(self, user):
        """gets permissions for a user or role."""
        return self.get_filtered_policy(0, user)

    def has_permission_for_user(self, user, *permission):
        """determines whether a user has a permission."""
        return self.has_policy(*permission)
