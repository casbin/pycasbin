class RoleManager:
    """provides interface to define the operations for managing roles."""

    def clear(self):
        pass

    def add_link(self, name1, name2, *domain):
        pass

    def delete_link(self, name1, name2, *domain):
        pass

    def has_link(self, name1, name2, *domain):
        pass

    def get_roles(self, name, *domain):
        pass

    def get_users(self, name, *domain):
        pass

    def print_roles(self):
        pass
