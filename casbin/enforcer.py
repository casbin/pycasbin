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

    def get_roles_for_user(self, name):
        """gets the roles that a user has."""
        return self.model.model['g']['g'].rm.get_roles(name)

    def get_users_for_role(self, name):
        """gets the users that has a role."""
        return self.model.model['g']['g'].rm.get_users(name)
