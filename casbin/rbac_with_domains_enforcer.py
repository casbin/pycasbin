from casbin.rbac_enforcer import RBACEnforcer

class RBACWithDomainsEnforcer(RBACEnforcer):
    """
        RBACWithDomainsEnforcer = RBAC_With_Domains_API + RBACEnforcer.
    """

    def get_roles_for_user_in_domain(self, name, domain):
        """gets the roles that a user has inside a domain."""
        res = self.model.model['g']['g'].rm.get_roles(name, domain)
        return res

    def get_users_for_role_in_domain(self, name, domain):
        """gets the users that has a role inside a domain."""
        res = self.model.model['g']['g'].rm.get_users(name, domain)
        return res
    
    def add_role_for_user_in_domain(self, user, role, domain):
        """adds a role for a user inside a domain."""
        """Returns false if the user already has the role (aka not affected)."""
        res = self.add_grouping_policy(user, role, domain)
        return res
    
    def delete_roles_for_user_in_domain(self, user, role, domain):
        """deletes a role for a user inside a domain."""
        """Returns false if the user does not have any roles (aka not affected)."""
        res = self.remove_filtered_grouping_policy(0, user, role, domain)
        return res
    
    def get_permissions_for_user_in_domain(self, user, domain):
        """gets permissions for a user or role inside domain."""
        res = self.get_filtered_policy(0, user, domain)
        return res