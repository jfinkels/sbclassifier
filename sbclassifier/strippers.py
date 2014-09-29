import math
import re
import urllib

# Tell SpamBayes where to cache IP address lookup information.
# Only comes into play if lookup_ip is enabled. The default
# (empty string) disables the file cache.  When caching is enabled,
# the cache file is stored using the same database type as the main
# token store (only dbm and zodb supported so far, zodb has problems,
# dbm is untested, hence the default).
X_LOOKUP_IP_CACHE = ''

try:
    from spambayes import dnscache
    cache = dnscache.cache(cachefile=X_LOOKUP_IP_CACHE)
    cache.printStatsAtEnd = False
except (IOError, ImportError):
    class cache:
        @staticmethod
        def lookup(*args):
            return []
else:
    import atexit
    atexit.register(cache.close)

from sbclassifier.iputils import gen_dotted_quad_clues

#: (EXPERIMENTAL) Recognize 'www.python.org' or ftp.python.org as URLs
#: instead of just long words.
FANCY_URL_RECOGNITION = False

#: (EXPERIMENTAL) Note whether url contains non-standard port or user/password
#: elements.
X_PICK_APART_URLS = False

#: (EXPERIMENTAL) Generate IP address tokens from hostnames. Requires PyDNS
#: (http://pydns.sourceforge.net/).
X_LOOKUP_IP = False

# Nuke HTML <style gimmicks.
html_style_start_re = re.compile(r"""
    < \s* style\b [^>]* >
""", re.VERBOSE)

urlsep_re = re.compile(r"[;?:@&=+,$.]")

fname_sep_re = re.compile(r'[/\\:]')

url_fancy_re = re.compile(r"""
    \b                      # the preceeding character must not be alphanumeric
    (?:
        (?:
            (https? | ftp)  # capture the protocol
            ://             # skip the boilerplate
        )|
        (?= ftp\.[^\.\s<>"'\x7f-\xff] )|  # allow the protocol to be missing,
                                          # but only if
        (?= www\.[^\.\s<>"'\x7f-\xff] )   # the rest of the url starts "www.x"
                                          # or "ftp.x"
    )
    # Do a reasonable attempt at detecting the end.  It may or may not
    # be in HTML, may or may not be in quotes, etc.  If it's full of %
    # escapes, cool -- that's a clue too.
    ([^\s<>"'\x7f-\xff]+)  # capture the guts
""", re.VERBOSE)                        # '

url_re = re.compile(r"""
    (https? | ftp)  # capture the protocol
    ://             # skip the boilerplate
    # Do a reasonable attempt at detecting the end.  It may or may not
    # be in HTML, may or may not be in quotes, etc.  If it's full of %
    # escapes, cool -- that's a clue too.
    ([^\s<>"'\x7f-\xff]+)  # capture the guts
""", re.VERBOSE)                        # '


def log2(n, log=math.log, c=math.log(2)):
    return log(n)/c


def crack_filename(fname):
    yield "fname:" + fname
    components = fname_sep_re.split(fname)
    morethan1 = len(components) > 1
    for component in components:
        if morethan1:
            yield "fname comp:" + component
        pieces = urlsep_re.split(component)
        if len(pieces) > 1:
            for piece in pieces:
                yield "fname piece:" + piece


def crack_content_xyz(msg):
    yield 'content-type:' + msg.get_content_type()

    x = msg.get_param('type')
    if x is not None:
        yield 'content-type/type:' + x.lower()

    try:
        for x in msg.get_charsets(None):
            if x is not None:
                yield 'charset:' + x.lower()
    except UnicodeEncodeError:
        # Bad messages can cause an exception here.
        # See [ 1175439 ] UnicodeEncodeError raised for bogus Content-Type
        #                 header
        yield 'charset:invalid_unicode'

    x = msg.get('content-disposition')
    if x is not None:
        yield 'content-disposition:' + x.lower()

    try:
        fname = msg.get_filename()
        if fname is not None:
            for x in crack_filename(fname):
                yield 'filename:' + x
    except TypeError:
        # bug in email pkg?  see the thread beginning at
        # http://mail.python.org/pipermail/spambayes/2003-September/008006.html
        # and
        # http://mail.python.org/pipermail/spambayes-dev/2003-September/001177.html
        yield "filename:<bogus>"

    if 0:   # disabled; see comment before function
        x = msg.get('content-transfer-encoding')
        if x is not None:
            yield 'content-transfer-encoding:' + x.lower()


class Stripper(object):

    # The retained portions are catenated together with self.separator.
    # CAUTION:  This used to be blank.  But then I noticed spam putting
    # HTML comments embedded in words, like
    #     FR<!--slkdflskjf-->EE!
    # Breaking this into "FR" and "EE!" wasn't a real help <wink>.
    separator = ''  # a subclass can override if this isn't appropriate

    def __init__(self, find_start, find_end):
        # find_start and find_end have signature
        #     string, int -> match_object
        # where the search starts at string[int:int].  If a match isn't found,
        # they must return None.  The match_object for find_start, if not
        # None, is passed to self.tokenize, which returns a (possibly empty)
        # list of tokens to generate.  Subclasses may override tokenize().
        # Text between find_start and find_end is thrown away, except for
        # whatever tokenize() produces.  A match_object must support method
        #     span() -> int, int    # the slice bounds of what was matched
        self.find_start = find_start
        self.find_end = find_end

    # Efficiency note:  This is cheaper than it looks if there aren't any
    # special sections.  Under the covers, string[0:] is optimized to
    # return string (no new object is built), and likewise ' '.join([string])
    # is optimized to return string.  It would actually slow this code down
    # to special-case these "do nothing" special cases at the Python level!

    def analyze(self, text):
        i = 0
        retained = []
        pushretained = retained.append
        tokens = []
        while True:
            m = self.find_start(text, i)
            if not m:
                pushretained(text[i:])
                break
            start, end = m.span()
            pushretained(text[i:start])
            tokens.extend(self.tokenize(m))
            m = self.find_end(text, end)
            if not m:
                # No matching end - act as if the open
                # tag did not exist.
                pushretained(text[start:])
                break
            dummy, i = m.span()
        return self.separator.join(retained), tokens

    def tokenize(self, match_object):
        # Override this if you want to suck info out of the start pattern.
        return []

# Strip out uuencoded sections and produce tokens.  The return value
# is (new_text, sequence_of_tokens), where new_text no longer contains
# uuencoded stuff.  Note that we're not bothering to decode it!  Maybe
# we should.  One of my persistent false negatives is a spam containing
# nothing but a uuencoded money.txt; OTOH, uuencode seems to be on
# its way out (that's an old spam).

uuencode_begin_re = re.compile(r"""
    ^begin \s+
    (\S+) \s+   # capture mode
    (\S+) \s*   # capture filename
    $
""", re.VERBOSE | re.MULTILINE)

uuencode_end_re = re.compile(r"^end\s*\n", re.MULTILINE)


class UUencodeStripper(Stripper):
    def __init__(self):
        Stripper.__init__(self, uuencode_begin_re.search,
                          uuencode_end_re.search)

    def tokenize(self, m):
        mode, fname = m.groups()
        return (['uuencode mode:%s' % mode] +
                ['uuencode:%s' % x for x in crack_filename(fname)])


class URLStripper(Stripper):
    def __init__(self):
        # The empty regexp matches anything at once.
        if FANCY_URL_RECOGNITION:
            search = url_fancy_re.search
        else:
            search = url_re.search
        Stripper.__init__(self, search, re.compile("").search)

    def tokenize(self, m):
        proto, guts = m.groups()
        assert guts
        if proto is None:
            if guts.lower().startswith("www"):
                proto = "http"
            elif guts.lower().startswith("ftp"):
                proto = "ftp"
            else:
                proto = "unknown"
        tokens = ["proto:" + proto]
        pushclue = tokens.append

        if X_PICK_APART_URLS:
            url = proto + "://" + guts

            escapes = re.findall(r'%..', guts)
            # roughly how many %nn escapes are there?
            if escapes:
                pushclue("url:%%%d" % int(log2(len(escapes))))
            # %nn escapes are usually intentional obfuscation.  Generate a
            # lot of correlated tokens if the URL contains a lot of them.
            # The classifier will learn which specific ones are and aren't
            # spammy.
            tokens.extend(["url:" + escape for escape in escapes])

            # now remove any obfuscation and probe around a bit
            url = urllib.parse.unquote(url)
            scheme, netloc, path, params, query, frag = \
                urllib.parse.urlparse(url)

            if X_LOOKUP_IP:
                ips = cache.lookup(netloc)
                if not ips:
                    pushclue("url-ip:lookup error")
                else:
                    for clue in gen_dotted_quad_clues("url-ip", ips):
                        pushclue(clue)

            # one common technique in bogus "please (re-)authorize yourself"
            # scams is to make it appear as if you're visiting a valid
            # payment-oriented site like PayPal, CitiBank or eBay, when you
            # actually aren't.  The company's web server appears as the
            # beginning of an often long username element in the URL such as
            # http://www.paypal.com%65%43%99%35@10.0.1.1/iwantyourccinfo
            # generally with an innocuous-looking fragment of text or a
            # valid URL as the highlighted link.  Usernames should rarely
            # appear in URLs (perhaps in a local bookmark you established),
            # and never in a URL you receive from an unsolicited email or
            # another website.
            user_pwd, host_port = urllib.parse.splituser(netloc)
            if user_pwd is not None:
                pushclue("url:has user")

            host, port = urllib.parse.splitport(host_port)
            # web servers listening on non-standard ports are suspicious ...
            if port is not None and (scheme == "http" and port != '80' or
                                     scheme == "https" and port != '443'):
                    pushclue("url:non-standard %s port" % scheme)

            # ... as are web servers associated with raw ip addresses
            if re.match("(\d+\.?){4,4}$", host) is not None:
                pushclue("url:ip addr")

            # make sure we later tokenize the unobfuscated url bits
            proto, guts = url.split("://", 1)

        # Lose the trailing punctuation for casual embedding, like:
        #     The code is at http://mystuff.org/here?  Didn't resolve.
        # or
        #     I found it at http://mystuff.org/there/.  Thanks!
        while guts and guts[-1] in '.:?!/':
            guts = guts[:-1]
        for piece in guts.split('/'):
            for chunk in urlsep_re.split(piece):
                pushclue("url:" + chunk)
        return tokens


class StyleStripper(Stripper):
    def __init__(self):
        Stripper.__init__(self, html_style_start_re.search,
                          re.compile(r"</style>").search)


class CommentStripper(Stripper):
    def __init__(self):
        Stripper.__init__(self,
                          re.compile(r"<!--|<\s*comment\s*[^>]*>").search,
                          re.compile(r"-->|</comment>").search)


# Nuke stuff between <noframes> </noframes> tags.
class NoframesStripper(Stripper):
    def __init__(self):
        Stripper.__init__(self,
                          re.compile(r"<\s*noframes\s*>").search,
                          re.compile(r"</noframes\s*>").search)
