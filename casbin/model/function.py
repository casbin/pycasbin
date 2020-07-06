from casbin import util


class FunctionMap:
    fm = dict()

    def add_function(self, name, func):
        self.fm[name] = func

    @staticmethod
    def load_function_map():
        fm = FunctionMap()
        fm.add_function("keyMatch", util.key_match_func)
        fm.add_function("keyMatch2", util.key_match2_func)
        fm.add_function("regexMatch", util.regex_match_func)
        fm.add_function("ipMatch", util.ip_match_func)
        fm.add_function("eval", util.eval_func)

        return fm

    def get_functions(self):
        return self.fm
