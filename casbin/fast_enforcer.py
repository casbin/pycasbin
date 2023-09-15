import logging
from typing import Sequence

from casbin.enforcer import Enforcer
from casbin.model import Model, FastModel, fast_policy_filter, FunctionMap
from casbin.persist.adapters import FileAdapter
from casbin.util.log import configure_logging


class FastEnforcer(Enforcer):
    _cache_key_order: Sequence[int] = None

    def __init__(self, model=None, adapter=None, enable_log=False, cache_key_order: Sequence[int] = None):
        self._cache_key_order = cache_key_order
        self.logger = logging.getLogger("casbin.enforcer")
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

        if enable_log:
            configure_logging()

    def init_with_file(self, model_path, policy_path):
        """initializes an enforcer with a model file and a policy file."""
        a = FileAdapter(policy_path)
        self.init_with_adapter(model_path, a)

    def init_with_adapter(self, model_path, adapter=None):
        """initializes an enforcer with a database adapter."""
        m = self.new_model(model_path)
        self.init_with_model_and_adapter(m, adapter)

        self.model_path = model_path

    def new_model(self, path="", text=""):
        """creates a model."""
        if self._cache_key_order is None:
            m = Model()
        else:
            m = FastModel(self._cache_key_order)
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

    def enforce(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        """
        if FastEnforcer._cache_key_order is None:
            result, _ = self.enforce_ex(*rvals)
        else:
            keys = [rvals[x] for x in self._cache_key_order]
            with fast_policy_filter(self.model.model["p"]["p"].policy, *keys):
                result, _ = self.enforce_ex(*rvals)

        return result
