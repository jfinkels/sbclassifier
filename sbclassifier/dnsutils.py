import functools
import socket


#: The maximum number of seconds to wait when making a forward or reverse DNS
#: lookup.
DEFAULT_TIMEOUT = 10


def timed(f):
    @functools.wraps(f)
    def timed_f(*args, **kw):
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(DEFAULT_TIMEOUT)
            return f(*args, **kw)
        except socket.timeout:
            return ()
        finally:
            socket.setdefaulttimeout(old_timeout)
    return timed_f


# note that this only works on functions without keyword arguments
#
# taken from <https://wiki.python.org/moin/PythonDecoratorLibrary#Alternate_memoize_as_dict_subclass>
class memoize(dict):
    def __init__(self, func):
        self.func = func

    def __call__(self, *args):
        return self[args]

    def __missing__(self, key):
        result = self.func(*key)
        self[key] = result
        return result


#@memoize
@timed
def reverse_dns_lookup(address):
    try:
        return (socket.gethostbyaddr(address)[0], )
    except socket.herror:
        return ()


#@memoize
@timed
def dns_lookup(name):
    return set(x[-1][0] for x in socket.getaddrinfo(name, 80))
