from collections import OrderedDict


def escape_assertion(s):
    """escapes the dots in the assertion, because the expression evaluation doesn't support such variable names."""

    s = s.replace("r.", "r_")
    s = s.replace("p.", "p_")

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
    ''' joins a string and a slice into a new slice.'''
    res = [a]

    res.extend(b)

    return res

def set_subtract(a, b):
    ''' returns the elements in `a` that aren't in `b`. '''
    mb = dict()

    for x in b:
        mb[x] = True

    diff = list()
    for x in a:
        if x not in mb:
            diff.append(x)

    return diff

def has_eval(s):
    '''determine whether matcher contains function eval'''
    line = s.split(" && ")
    flag = False
    for i in line:
        if(i[0:5] == "eval(" and ")" in i[4:]):
            flag = True
    return flag


def replace_eval(s, rule):
    '''replace function eval with the value of its parameters'''
    if has_eval(s):
        return s.replace("eval()", "(" + rule + ")")
    else:
        return s

def get_eval_value(s):
    '''returns the parameters of function eval'''
    if has_eval(s):
        value = []
        line = s.split(" && ")
        for i in line:
            if has_eval(i):
                value.append(i[5:-1])
    return value