from simpleeval import simple_eval


def evaluate(exp_string, parameters=None, functions=None):
    exp_string = exp_string.replace("&&", "and")
    exp_string = exp_string.replace("||", "or")
    return simple_eval(exp_string, functions=functions, names=parameters)
