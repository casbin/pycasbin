import fnmatch
import re
import ipaddress

KEY_MATCH2_PATTERN = re.compile(r'(.*?):[^\/]+(.*?)')
KEY_MATCH3_PATTERN = re.compile(r'(.*?){[^\/]+}(.*?)')


def key_match(key1, key2):
    """determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    For example, "/foo/bar" matches "/foo/*"
    """

    i = key2.find("*")
    if i == -1:
        return key1 == key2

    if len(key1) > i:
        return key1[:i] == key2[:i]
    return key1 == key2[:i]


def key_match_func(*args):
    """The wrapper for key_match.
    """
    name1 = args[0]
    name2 = args[1]

    return key_match(name1, name2)


def key_match2(key1, key2):
    """determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
    """

    key2 = key2.replace("/*", "/.*")
    key2 = KEY_MATCH2_PATTERN.sub(r'\g<1>[^\/]+\g<2>', key2, 0)

    return regex_match(key1, "^" + key2 + "$")


def key_match2_func(*args):
    name1 = args[0]
    name2 = args[1]

    return key_match2(name1, name2)


def key_match3(key1, key2):
    """determines determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
    """

    key2 = key2.replace("/*", "/.*")
    key2 = KEY_MATCH3_PATTERN.sub(r'\g<1>[^\/]+\g<2>', key2, 0)

    return regex_match(key1, "^" + key2 + "$")


def key_match3_func(*args):
    name1 = args[0]
    name2 = args[1]

    return key_match3(name1, name2)


def regex_match(key1, key2):
    """determines whether key1 matches the pattern of key2 in regular expression."""

    res = re.match(key2, key1)
    if res:
        return True
    else:
        return False


def regex_match_func(*args):
    """the wrapper for RegexMatch."""

    name1 = args[0]
    name2 = args[1]

    return regex_match(name1, name2)


def glob_match(string, pattern):
    """determines whether string matches the pattern in glob expression."""
    return fnmatch.fnmatch(string, pattern)


def glob_match_func(*args):
    """the wrapper for globMatch."""

    string = args[0]
    pattern = args[1]

    return glob_match(string, pattern)


def ip_match(ip1, ip2):
    """IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
    For example, "192.168.2.123" matches "192.168.2.0/24"
    """
    ip1 = ipaddress.ip_address(ip1)
    try:
        network = ipaddress.ip_network(ip2, strict=False)
        return ip1 in network
    except ValueError:
        return ip1 == ip2


def ip_match_func(*args):
    """the wrapper for IPMatch."""

    ip1 = args[0]
    ip2 = args[1]

    return ip_match(ip1, ip2)


def generate_g_function(rm):
    """the factory method of the g(_, _) function."""

    def f(*args):
        name1 = args[0]
        name2 = args[1]

        if not rm:
            return name1 == name2
        elif 2 == len(args):
            return rm.has_link(name1, name2)
        else:
            domain = str(args[2])
            return rm.has_link(name1, name2, domain)

    return f
