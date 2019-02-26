from simpleeval import simple_eval


def evaluate(exp_string, parameters=None, functions=None):
    if parameters is None:
        parameters = {}
    if functions is None:
        functions = {}
    exp_string = exp_string.replace("&&", "and")
    exp_string = exp_string.replace("||", "or")
    return simple_eval(exp_string, functions=functions, names=parameters)
