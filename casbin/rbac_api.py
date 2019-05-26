from casbin.management_api import ManagementApi


class RbacApi(ManagementApi):
    def get_roles_for_user(self, name):
        """gets the roles that a user has."""
        return self.model.model['g']['g'].rm.get_roles(name)

    def get_users_for_role(self, name):
        """gets the users that has a role."""
        return self.model.model['g']['g'].rm.get_users(name)
