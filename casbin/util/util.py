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
    found = dict()
    j = 0
    for x in s:
        if x not in found.keys():
            found[x] = True
            s[j] = x
            j = j + 1

    return s[:j]


def array_to_string(s):
    """gets a printable string for a string array."""

    return ", ".join(s)


def params_to_string(*s):
    """gets a printable string for variable number of parameters."""

    return ", ".join(s)
