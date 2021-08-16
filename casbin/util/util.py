from collections import OrderedDict
import re

eval_reg = re.compile(r"\beval\((?P<rule>[^)]*)\)")


def escape_assertion(s):
    """escapes the dots in the assertion, because the expression evaluation doesn't support such variable names."""
    eval_p = re.search(r"\bp(\d?)\.", s)
    if eval_p is not None:
        p_suffix = eval_p.group(1)
        p_before = re.compile(f"\\bp{p_suffix}\\.")
        p_after = f"p{p_suffix}_"
        s = re.sub(p_before, p_after, s)

    eval_r = re.search(r"\br(\d?)\.", s)
    if eval_r is not None:
        r_suffix = eval_r.group(1)
        r_before = re.compile(f"\\br{r_suffix}\\.")
        r_after = f"r{r_suffix}_"
        s = re.sub(r_before, r_after, s)

    return s


def remove_comments(s):
    """removes the comments starting with # in the text."""

    pos = s.find("#")
    if pos == -1:
        return s

    return s[0:pos].strip()


def array_remove_duplicates(s):
    """removes any duplicated elements in a string array."""
    return list(OrderedDict.fromkeys(s))


def array_to_string(s):
    """gets a printable string for a string array."""

    return ", ".join(s)


def params_to_string(*s):
    """gets a printable string for variable number of parameters."""

    return ", ".join(s)


def join_slice(a, *b):
    """joins a string and a slice into a new slice."""
    res = [a]

    res.extend(b)

    return res


def set_subtract(a, b):
    """returns the elements in `a` that aren't in `b`."""
    return [i for i in a if i not in b]


def has_eval(s):
    """determine whether matcher contains function eval"""
    return eval_reg.search(s)


def replace_eval(expr, rules):
    """replace all occurences of function eval with rules"""
    pos = 0
    match = eval_reg.search(expr, pos)
    while match:
        rule = "(" + rules.pop(0) + ")"
        expr = expr[: match.start()] + rule + expr[match.end() :]
        pos = match.start() + len(rule)
        match = eval_reg.search(expr, pos)

    return expr


def get_eval_value(s):
    """returns the parameters of function eval"""
    sub_match = eval_reg.findall(s)
    return sub_match.copy()
