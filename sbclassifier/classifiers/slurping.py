# slurping.py - a classifier that also uses tokens from hyperlinks in messages
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
from email import message_from_string
import logging
import os
import re
import socket

import requests

from sbclassifier.classifiers.basic import Classifier
from sbclassifier.classifiers.constants import HAM_CUTOFF
from sbclassifier.classifiers.constants import MAX_DISCRIMINATORS
from sbclassifier.classifiers.constants import SPAM_CUTOFF
from sbclassifier.classifiers.constants import USE_BIGRAMS
from sbclassifier.corpora.filesystem import ExpiryFileCorpus
from sbclassifier.corpora.filesystem import FileMessageFactory
from sbclassifier.safepickle import pickle_read
from sbclassifier.safepickle import pickle_write
from sbclassifier.tokenizer import tokenize
from sbclassifier.strippers import URLStripper

DOMAIN_AND_PORT_RE = re.compile(r"([^:/\\]+)(:([\d]+))?")
HTTP_ERROR_RE = re.compile(r"HTTP Error ([\d]+)")
URL_KEY_RE = re.compile(r"[\W]")

#: The username to give to the HTTP proxy when required.  If a username is
#: not necessary, simply leave blank.
PROXY_USERNAME = ''

#: The password to give to the HTTP proxy when required.  This is stored in
#: clear text in your configuration file, so if that bothers you then don't do
#: this. You'll need to use a proxy that doesn't need authentication, or do
#: without any SpamBayes HTTP activity.
PROXY_PASSWORD = ''

#: If a spambayes application needs to use HTTP, it will try to do so through
#: this proxy server.
#:
#: See also :const:`PROXY_PORT`.
PROXY_SERVER = ''

#: If a spambayes application needs to use HTTP, it will try to do so through
#: this proxy port.
#:
#: See also :const:`PROXY_SERVER`.
PROXY_PORT = 8080

#: (EXPERIMENTAL) This is the number of days that local cached copies of the
#: text at the URLs will be stored for.
X_CACHE_EXPIRY_DAYS = 7

# TODO this should use the XDG Base Directory specification for caching.

#: (EXPERIMENTAL) So that SpamBayes doesn't need to retrieve the same URL over
#: and over again, it stores local copies of the text at the end of the URL.
#: This is the directory that will be used for those copies.
X_CACHE_DIRECTORY = 'url-cache'

#: (EXPERIMENTAL) To try and speed things up, and to avoid following unique
#: URLS, if this option is enabled, SpamBayes will convert the URL to as basic
#: a form it we can.  All directory information is removed and the domain is
#: reduced to the two (or three for those with a country TLD) top-most
#: elements. For example::
#:
#:     http://www.massey.ac.nz/~tameyer/index.html?you=me
#:
#: would become::
#:
#:     http://massey.ac.nz
#:
#: and::
#:
#:     http://id.example.com
#:
#: would become http://example.com
#:
#: This should have two beneficial effects:
#:  o It's unlikely that any information could be contained in this 'base'
#:    url that could identify the user (unless they have a *lot* of domains).
#:  o Many urls (both spam and ham) will strip down into the same 'base' url.
#:    Since we have a limited form of caching, this means that a lot fewer
#:    urls will have to be retrieved.
#: However, this does mean that if the 'base' url is hammy and the full is
#: spammy, or vice-versa, that the slurp will give back the wrong information.
#: Whether or not this is the case would have to be determined by testing.
X_ONLY_SLURP_BASE = False

#: (EXPERIMENTAL) It may be that what is hammy/spammy for you in email isn't
#: from webpages.  You can then set this option (to "web:", for example), and
#: effectively create an independent (sub)database for tokens derived from
#: parsing web pages.
X_WEB_PREFIX = ''

REQUEST_TIMEOUTS = 5

slurp_wordstream = None


def base_url(self, url):
    # To try and speed things up, and to avoid following
    # unique URLS, we convert the URL to as basic a form
    # as we can - so http://www.massey.ac.nz/~tameyer/index.html?you=me
    # would become http://massey.ac.nz and http://id.example.com
    # would become http://example.com
    url += '/'
    domain = url.split('/', 1)[0]
    parts = domain.split('.')
    if len(parts) > 2:
        base_domain = parts[-2] + '.' + parts[-1]
        if len(parts[-1]) < 3:
            base_domain = parts[-3] + '.' + base_domain
    else:
        base_domain = domain
    return base_domain


class SlurpingURLStripper(URLStripper):
    def __init__(self):
        URLStripper.__init__(self)

    def analyze(self, text):
        # If there are no URLS, then we need to clear the
        # wordstream, or whatever was there from the last message
        # will be used.
        slurp_wordstream = None
        # Continue as normal.
        return URLStripper.analyze(self, text)

    def tokenize(self, m):
        # XXX Note that the 'slurped' tokens are *always* trained
        # XXX on; it would be simple to change/parameterize this.
        tokens = URLStripper.tokenize(self, m)
        # if not options["URLRetriever", "x-slurp_urls"]:
        #     return tokens

        proto, guts = m.groups()
        if proto != "http":
            return tokens

        assert guts
        while guts and guts[-1] in '.:;?!/)':
            guts = guts[:-1]

        slurp_wordstream = (proto, guts)
        return tokens


class SlurpingClassifier(Classifier):

    def spamprob(self, wordstream, evidence=False):
        """Do the standard chi-squared spamprob, but if the evidence
        leaves the score in the unsure range, and we have fewer tokens
        than max_discriminators, also generate tokens from the text
        obtained by following http URLs in the message."""
        # Get the raw score.
        prob, clues = super().spamprob(wordstream, True)

        # If necessary, enhance it with the tokens from whatever is
        # at the URL's destination.
        if len(clues) < MAX_DISCRIMINATORS and \
           HAM_CUTOFF < prob < SPAM_CUTOFF and slurp_wordstream:
            slurp_tokens = list(self._generate_slurp())
            slurp_tokens.extend([w for (w, _p) in clues])
            sprob, sclues = super().spamprob(slurp_tokens, True)
            if not (HAM_CUTOFF < sprob < SPAM_CUTOFF):
                prob = sprob
                clues = sclues
        if evidence:
            return prob, clues
        return prob

    def learn(self, wordstream, is_spam):
        """Teach the classifier by example.

        wordstream is a word stream representing a message.  If is_spam is
        True, you're telling the classifier this message is definitely spam,
        else that it's definitely not spam.
        """
        if USE_BIGRAMS:
            wordstream = self._enhance_wordstream(wordstream)
        wordstream = self._add_slurped(wordstream)
        self._add_msg(wordstream, is_spam)

    def unlearn(self, wordstream, is_spam):
        """In case of pilot error, call unlearn ASAP after screwing up.

        Pass the same arguments you passed to learn().
        """
        if USE_BIGRAMS:
            wordstream = self._enhance_wordstream(wordstream)
        wordstream = self._add_slurped(wordstream)
        self._remove_msg(wordstream, is_spam)

    def _generate_slurp(self):
        # We don't want to do this recursively and check URLs
        # on webpages, so we have this little cheat.
        if not hasattr(self, "setup_done"):
            self.setup()
            self.setup_done = True
        if not hasattr(self, "do_slurp") or self.do_slurp:
            if slurp_wordstream:
                self.do_slurp = False

                tokens = self.slurp(*slurp_wordstream)
                self.do_slurp = True
                self._save_caches()
                return tokens
        return []

    def setup(self):
        # Setup the cache for retrieved urls
        age = X_CACHE_EXPIRY_DAYS * 24 * 60 * 60
        dir = X_CACHE_DIRECTORY
        if not os.path.exists(dir):
            # Create the directory.
            logging.debug("Creating URL cache directory")
            os.makedirs(dir)

        self.urlCorpus = ExpiryFileCorpus(age, FileMessageFactory(),
                                          dir, cacheSize=20)
        # Kill any old information in the cache
        self.urlCorpus.removeExpiredMessages()

        # Setup caches for unretrievable urls
        self.bad_url_cache_name = os.path.join(dir, "bad_urls.pck")
        self.http_error_cache_name = os.path.join(dir, "http_error_urls.pck")
        if os.path.exists(self.bad_url_cache_name):
            try:
                self.bad_urls = pickle_read(self.bad_url_cache_name)
            except (IOError, ValueError):
                # Something went wrong loading it (bad pickle,
                # probably).  Start afresh.
                logging.warning("Bad URL pickle, using new.")
                self.bad_urls = {"url:non_resolving": (),
                                 "url:non_html": (),
                                 "url:unknown_error": ()}
        else:
            logging.debug("URL caches don't exist: creating")
            self.bad_urls = {"url:non_resolving": (),
                             "url:non_html": (),
                             "url:unknown_error": ()}
        if os.path.exists(self.http_error_cache_name):
            try:
                self.http_error_urls = pickle_read(self.http_error_cache_name)
            except (IOError, ValueError):
                # Something went wrong loading it (bad pickle,
                # probably).  Start afresh.
                logging.debug("Bad HHTP error pickle, using new.")
                self.http_error_urls = {}
        else:
            self.http_error_urls = {}

    def _save_caches(self):
        # XXX Note that these caches are never refreshed, which might not
        # XXX be a good thing long-term (if a previously invalid URL
        # XXX becomes valid, for example).
        for name, data in [(self.bad_url_cache_name, self.bad_urls),
                           (self.http_error_cache_name, self.http_error_urls),
                           ]:
            pickle_write(name, data)

    def slurp(self, proto, url):
        # We generate these tokens:
        #  url:non_resolving
        #  url:non_html
        #  url:http_XXX (for each type of http error encounted,
        #                for example 404, 403, ...)
        # And tokenise the received page (but we do not slurp this).
        # Actually, the special url: tokens barely showed up in my testing,
        # although I would have thought that they would more - this might
        # be due to an error, although they do turn up on occasion.  In
        # any case, we have to do the test, so generating an extra token
        # doesn't cost us anything apart from another entry in the db, and
        # it's only two entries, plus one for each type of http error
        # encountered, so it's pretty neglible.
        # If there is no content in the URL, then just return immediately.
        # "http://)" will trigger this.
        if not url:
            return ["url:non_resolving"]

        if X_ONLY_SLURP_BASE:
            url = base_url(url)

        # Check the unretrievable caches
        for err in self.bad_urls.keys():
            if url in self.bad_urls[err]:
                return [err]
        if url in self.http_error_urls:
            return self.http_error_urls[url]

        # We check if the url will resolve first
        mo = DOMAIN_AND_PORT_RE.match(url)
        domain = mo.group(1)
        if mo.group(3) is None:
            port = 80
        else:
            port = mo.group(3)
        try:
            socket.getaddrinfo(domain, port)
        except OSError:
            self.bad_urls["url:non_resolving"] += (url,)
            return ["url:non_resolving"]

        # If the message is in our cache, then we can just skip over
        # retrieving it from the network, and get it from there, instead.
        url_key = URL_KEY_RE.sub('_', url)
        cached_message = self.urlCorpus.get(url_key)

        if cached_message is None:
            # We're going to ignore everything that isn't text/html,
            # so we might as well not bother retrieving anything with
            # these extensions.
            parts = url.split('.')
            if parts[-1] in ('jpg', 'gif', 'png', 'css', 'js'):
                self.bad_urls["url:non_html"] += (url,)
                return ["url:non_html"]

            url_with_proto = '{}://{}'.format(proto, url)
            proxy_info = (PROXY_USERNAME, PROXY_PASSWORD, PROXY_SERVER,
                          PROXY_PORT)
            proxies = dict(http='http://{}:{}@{}:{}'.format(*proxy_info))
            logging.debug("Slurping %s", url)
            try:
                f = requests.get(url_with_proto, proxies=proxies,
                                 timeout=REQUEST_TIMEOUTS)
            except requests.exceptions.RequestException as exception:
                mo = HTTP_ERROR_RE.match(str(exception))
                if mo:
                    self.http_error_urls[url] = "url:http_" + mo.group(1)
                    return ["url:http_" + mo.group(1)]
                self.bad_urls["url:unknown_error"] += (url,)
                return ["url:unknown_error"]

            # Anything that isn't text/html is ignored
            content_type = f.headers.get('content-type')
            if content_type is None or \
               not content_type.startswith("text/html"):
                self.bad_urls["url:non_html"] += (url,)
                return ["url:non_html"]

            fake_message_string = str(f.headers) + "\r\n" + f.text

            # Retrieving the same messages over and over again will tire
            # us out, so we store them in our own wee cache.
            message = self.urlCorpus.makeMessage(url_key,
                                                 fake_message_string)
            self.urlCorpus.addMessage(message)
        else:
            fake_message_string = cached_message.as_string()

        msg = message_from_string(fake_message_string)

        tokens = tokenize(msg, basic_header_tokenize=True,
                          basic_header_tokenize_only=True)
        tokens = ['{}{}'.format(X_WEB_PREFIX, tok) for tok in tokens]
        return tokens

    def _add_slurped(self, wordstream):
        """Add tokens generated by 'slurping' (i.e. tokenizing
        the text at the web pages pointed to by URLs in messages)
        to the wordstream."""
        for token in wordstream:
            yield token
        slurped_tokens = self._generate_slurp()
        for token in slurped_tokens:
            yield token
