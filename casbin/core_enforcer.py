from casbin import log
from casbin.persist.adapters import FileAdapter
from casbin.model import Model, FunctionMap
from casbin.rbac import default_role_manager
from casbin.util import generate_g_function, SimpleEval, has_eval, replace_eval, get_eval_value
from casbin.effect import DefaultEffector, Effector


class CoreEnforcer:
    """CoreEnforcer defines the core functionality of an enforcer."""

    model_path = ""
    model = None
    fm = None
    eft = None

    adapter = None
    watcher = None
    rm = None

    enabled = False
    auto_save = False
    auto_build_role_links = False

    def __init__(self, model=None, adapter=None, enable_log=False):
        self.enable_log(enable_log)
        if isinstance(model, str):
            if isinstance(adapter, str):
                self.init_with_file(model, adapter)
            else:
                self.init_with_adapter(model, adapter)
                pass
        else:
            if isinstance(adapter, str):
                raise RuntimeError("Invalid parameters for enforcer.")
            else:
                self.init_with_model_and_adapter(model, adapter)

    def init_with_file(self, model_path, policy_path):
        """initializes an enforcer with a model file and a policy file."""
        a = FileAdapter(policy_path)
        self.init_with_adapter(model_path, a)

    def init_with_adapter(self, model_path, adapter=None):
        """initializes an enforcer with a database adapter."""
        m = self.new_model(model_path)
        self.init_with_model_and_adapter(m, adapter)

        self.model_path = model_path

    def init_with_model_and_adapter(self, m, adapter=None):
        """initializes an enforcer with a model and a database adapter."""
        self.adapter = adapter

        self.model = m
        self.model.print_model()
        self.fm = FunctionMap.load_function_map()

        self._initialize()

        # Do not initialize the full policy when using a filtered adapter
        if self.adapter:
            self.load_policy()

    def _initialize(self):
        self.rm = default_role_manager.RoleManager(10)
        self.eft = DefaultEffector()
        self.watcher = None

        self.enabled = True
        self.auto_save = True
        self.auto_build_role_links = True

    @staticmethod
    def new_model(path="", text=""):
        """creates a model."""

        m = Model()
        if len(path) > 0:
            m.load_model(path)
        else:
            m.load_model_from_text(text)

        return m

    def load_model(self):
        """reloads the model from the model CONF file.
        Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
        """

        self.model = self.new_model()
        self.model.load_model(self.model_path)
        self.model.print_model()
        self.fm = FunctionMap.load_function_map()

    def get_model(self):
        """gets the current model."""

        return self.model

    def set_model(self, m):
        """sets the current model."""

        self.model = m
        self.fm = FunctionMap.load_function_map()

    def get_adapter(self):
        """gets the current adapter."""

        return self.adapter

    def set_adapter(self, adapter):
        """sets the current adapter."""

        self.adapter = adapter

    def set_watcher(self, watcher):
        """sets the current watcher."""

        self.watcher = watcher
        pass

    def set_role_manager(self, rm):
        """sets the current role manager."""

        self.rm = rm

    def set_effector(self, eft):
        """sets the current effector."""

        self.eft = eft

    def clear_policy(self):
        """ clears all policy."""

        self.model.clear_policy()

    def load_policy(self):
        """reloads the policy from file/database."""

        self.model.clear_policy()
        self.adapter.load_policy(self.model)

        self.model.print_policy()
        if self.auto_build_role_links:
            self.build_role_links()

    def load_filtered_policy(self, filter):
        """reloads a filtered policy from file/database."""

        pass

    def is_filtered(self):
        """returns true if the loaded policy has been filtered."""

        pass

    def save_policy(self):
        if self.is_filtered():
            raise RuntimeError("cannot save a filtered policy")

        self.adapter.save_policy(self.model)

        if self.watcher:
            self.watcher.update()

    def enable_enforce(self, enabled=True):
        """changes the enforcing state of Casbin,
        when Casbin is disabled, all access will be allowed by the Enforce() function.
        """

        self.enabled = enabled

    def enable_log(self, enable):
        """changes whether Casbin will log messages to the Logger."""

        log.get_logger().enable_log(enable)

    def enable_auto_save(self, auto_save):
        """controls whether to save a policy rule automatically to the adapter when it is added or removed."""
        self.auto_save = auto_save

    def enable_auto_build_role_links(self, auto_build_role_links):
        """controls whether to rebuild the role inheritance relations when a role is added or deleted."""
        self.auto_build_role_links = auto_build_role_links

    def build_role_links(self):
        """manually rebuild the role inheritance relations."""

        self.rm.clear()
        self.model.build_role_links(self.rm)

    def enforce(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        """

        if not self.enabled:
            return False

        functions = self.fm.get_functions()

        if "g" in self.model.model.keys():
            for key, ast in self.model.model["g"].items():
                rm = ast.rm
                functions[key] = generate_g_function(rm)

        if "m" not in self.model.model.keys():
            raise RuntimeError("model is undefined")

        if "m" not in self.model.model["m"].keys():
            raise RuntimeError("model is undefined")

        r_tokens = self.model.model["r"]["r"].tokens
        p_tokens = self.model.model["p"]["p"].tokens

        if len(r_tokens) != len(rvals):
            raise RuntimeError("invalid request size")

        exp_string = self.model.model["m"]["m"].value
        expression = self._get_expression(exp_string, functions)

        policy_effects = set()
        matcher_results = set()

        r_parameters = dict(zip(r_tokens, rvals))

        policy_len = len(self.model.model["p"]["p"].policy)

        if not 0 == policy_len:
            for i, pvals in enumerate(self.model.model["p"]["p"].policy):
                if len(p_tokens) != len(pvals):
                    raise RuntimeError("invalid policy size")

                parameters = dict(r_parameters, **dict(zip(p_tokens, pvals)))
                result = expression.eval(parameters)

                eval_policy = self.model.model["p"]["p"].policy
                if has_eval(eval_policy):
                    for eval_value in get_eval_value(eval_policy):
                        eval_policy = replace_eval(eval_policy, self.enforce(eval_value))

                if isinstance(result, bool):
                    if not result:
                        policy_effects.add(Effector.INDETERMINATE)
                        continue
                elif isinstance(result, float):
                    if 0 == result:
                        policy_effects.add(Effector.INDETERMINATE)
                        continue
                    else:
                        matcher_results.add(result)
                else:
                    raise RuntimeError("matcher result should be bool, int or float")

                if "p_eft" in parameters.keys():
                    eft = parameters["p_eft"]
                    if "allow" == eft:
                        policy_effects.add(Effector.ALLOW)
                    elif "deny" == eft:
                        policy_effects.add(Effector.DENY)
                    else:
                        policy_effects.add(Effector.INDETERMINATE)
                else:
                    policy_effects.add(Effector.ALLOW)

                if "priority(p_eft) || deny" == self.model.model["e"]["e"].value:
                    break

        else:

            parameters = r_parameters.copy()

            for token in self.model.model["p"]["p"].tokens:
                parameters[token] = ""

            result = expression.eval(parameters)

            if result:
                policy_effects.add(Effector.ALLOW)
            else:
                policy_effects.add(Effector.INDETERMINATE)

        result = self.eft.merge_effects(self.model.model["e"]["e"].value, policy_effects, matcher_results)

        # Log request.
        if log.get_logger().is_enabled():
            req_str = "Request: "
            req_str = req_str + ", ".join([str(v) for v in rvals])

            req_str = req_str + " ---> %s" % result
            log.log_print(req_str)

        return result

    @staticmethod
    def _get_expression(expr, functions=None):
        expr = expr.replace("&&", "and")
        expr = expr.replace("||", "or")

        return SimpleEval(expr, functions)
