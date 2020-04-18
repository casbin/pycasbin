from casbin.rbac_with_domains_enforcer import RBACWithDomainsEnforcer


class Enforcer(RBACWithDomainsEnforcer):
    """
        Enforcer = RBACWithDomainsEnforcer
    """

    """creates an enforcer via file or DB.

        File:
            e = casbin.Enforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
        MySQL DB:
            a = mysqladapter.DBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
            e = casbin.Enforcer("path/to/basic_model.conf", a)
    """
    pass