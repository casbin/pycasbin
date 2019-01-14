from simpleeval import simple_eval


def evaluate(exp_string, parameters=dict(), functions=dict()):
    exp_string = exp_string.replace("&&", "and")
    exp_string = exp_string.replace("||", "or")
    return simple_eval(exp_string, functions=functions, names=parameters)
