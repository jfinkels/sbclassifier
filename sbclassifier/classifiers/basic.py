# basic.py - a basic Bayesian classifier for messages
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
"""An implementation of a Bayes-like spam classifier.

Paul Graham's original description:

    http://www.paulgraham.com/spam.html

A highly fiddled version of that can be retrieved from our CVS repository,
via tag Last-Graham.  This made many demonstrated improvements in error
rates over Paul's original description.

This code implements Gary Robinson's suggestions, the core of which are
well explained on his webpage:

   http://radio.weblogs.com/0101454/stories/2002/09/16/spamDetection.html

This is theoretically cleaner, and in testing has performed at least as
well as our highly tuned Graham scheme did, often slightly better, and
sometimes much better.  It also has "a middle ground", which people like:
the scores under Paul's scheme were almost always very near 0 or very near
1, whether or not the classification was correct.  The false positives
and false negatives under Gary's basic scheme (use_gary_combining) generally
score in a narrow range around the corpus's best spam_cutoff value.
However, it doesn't appear possible to guess the best spam_cutoff value in
advance, and it's touchy.

The last version of the Gary-combining scheme can be retrieved from our
CVS repository via tag Last-Gary.

The chi-combining scheme used by default here gets closer to the theoretical
basis of Gary's combining scheme, and does give extreme scores, but also
has a very useful middle ground (small # of msgs spread across a large range
of scores, and good cutoff values aren't touchy).

This implementation is due to Tim Peters et alia.

"""
import itertools
import math

#: The natural logarithm of two; this is used frequently by a function
#: performing chi-combining.
LN2 = math.log(2)

PICKLE_VERSION = 5

#: The format string for creating a token from a bigram.
BIGRAM_FORMAT = 'bi:{} {}'

#: Generate both unigrams (words) and bigrams (pairs of words). However,
#: extending an idea originally from Gary Robinson, the message is 'tiled' into
#: non-overlapping unigrams and bigrams, approximating the strongest outcome
#: over all possible tilings.
#
#: Note that to really test this option you need to retrain with it on, so that
#: your database includes the bigrams - if you subsequently turn it off, these
#: tokens will have no effect.  This option will at least double your database
#: size given the same training data, and will probably at least triple it.
#
#: You may also wish to increase the max_discriminators (maximum number of
#: extreme words) option if you enable this option, perhaps doubling or
#: quadrupling it.  It's not yet clear.  Bigrams create many more hapaxes, and
#: that seems to increase the brittleness of minimalist training regimes;
#: increasing max_discriminators may help to soften that effect.  OTOH,
#: max_discriminators defaults to 150 in part because that makes it easy to
#: prove that the chi-squared math is immune from numeric problems.  Increase
#: it too much, and insane results will eventually result (including fatal
#: floating-point exceptions on some boxes).
#
#: This option is experimental, and may be removed in a future release.
#: We would appreciate feedback about it if you use it - email
#: spambayes@python.org with your comments and results.
USE_BIGRAMS = False

#: These two control the prior assumption about word probabilities.
#: unknown_word_prob is essentially the probability given to a word that has
#: never been seen before.  Nobody has reported an improvement via moving it
#: away from 1/2, although Tim has measured a mean spamprob of a bit over 0.5
#: (0.51-0.55) in 3 well-trained classifiers.
UNKNOWN_WORD_PROB = 0.5

#: This adjusts how much weight to give the prior assumption relative to the
#: probabilities estimated by counting.  At 0, the counting estimates are
#: believed 100%, even to the extent of assigning certainty (0 or 1) to a word
#: that has appeared in only ham or only spam.  This is a disaster.

#: As unknown_word_strength tends toward infinity, all probabilities tend
#: toward unknown_word_prob.  All reports were that a value near 0.4 worked
#: best, so this does not seem to be corpus-dependent.
UNKNOWN_WORD_STRENGTH = 0.45

#: When scoring a message, ignore all words with abs(word.spamprob - 0.5) <
#: minimum_prob_strength.  This may be a hack, but it has proved to reduce
#: error rates in many tests.  0.1 appeared to work well across all corpora.
MINIMUM_PROB_STRENGTH = 0.1

#: The maximum number of extreme words to look at in a message, where "extreme"
#: means with spam probability farthest away from 0.5.  150 appears to work
#: well across all corpora tested.
MAX_DISCRIMINATORS = 150


def chi2Q(x2, v):  # , exp=math.exp, min=min):
    """Return the probability that `chisq` is at least x2, with `v` degrees of
    freedom.

    If `v` is not even, :exc:`ValueError` is raised.

    """
    if v & 1 != 0:
        raise ValueError('v must be even')

    # XXX If x2 is very large, exp(-m) will underflow to 0.
    m = x2 / 2  # this is true division on Python 3
    result = math.exp(-m)
    term = result
    for i in range(1, v // 2):
        term *= m / i
        result += term
    # With small x2 and large v, accumulated roundoff error, plus error in
    # the platform exp(), can cause this to spill a few ULP above 1.0.  For
    # example, chi2Q(100, 300) on my box has sum == 1.0 + 2.0**-52 at this
    # point.  Returning a value even a teensy bit over 1.0 is no good.
    return min(result, 1.0)


class WordInfo(object):
    """Represents the number of occurences of a word in spam and in ham.

    An instance of this class is created for each distinct word. `spamcount` is
    the number of trained spam messages in which the word appears, and
    ``hamcount`` the number of trained ham messages.

    For use in a classifier database, at least one of `spamcount` and
    `hamcount` must be non-zero.

    .. note::

       This is a tiny object.  Use of ``__slots__`` is essential to conserve
       memory.

    """

    #: Only store the spam count and ham count in memory.
    __slots__ = 'spamcount', 'hamcount'

    def __init__(self, spamcount=0, hamcount=0):
        self.__setstate__((spamcount, hamcount))

    def __repr__(self):
        return 'WordInfo{!r}'.format(self.__getstate__())

    def __getstate__(self):
        return self.spamcount, self.hamcount

    def __setstate__(self, t):
        self.spamcount, self.hamcount = t


class Classifier:
    # Defining __slots__ here made Jeremy's life needlessly difficult when
    # trying to hook this all up to ZODB as a persistent object.  There's no
    # space benefit worth getting from slots in this class; slots were used
    # solely to help catch errors earlier, when this code was changing rapidly.

    # __slots__ = ('wordinfo',  # map word to WordInfo record
    #              'nspam',     # number of spam messages learn() has seen
    #              'nham',      # number of non-spam messages learn() has seen
    #             )

    # allow a subclass to use a different class for WordInfo
    WordInfoClass = WordInfo

    def __init__(self, use_bigrams=USE_BIGRAMS):
        self._use_bigrams = use_bigrams
        self.wordinfo = {}
        # This is an optimization; this contains the probability for each
        # (hamcount, spamcount) property. It is only set during the call to
        # probability().
        self._probcache = {}
        self.nspam = 0
        self.nham = 0

    def __getstate__(self):
        return (PICKLE_VERSION, self.wordinfo, self.nspam, self.nham)

    def __setstate__(self, t):
        if t[0] != PICKLE_VERSION:
            raise ValueError("Can't unpickle; version %s unknown".format(t[0]))
        self.wordinfo, self.nspam, self.nham = t[1:]
        self._probcache = {}

    # Implementation note: Across vectors of length n, containing random
    # uniformly-distributed probabilities, -2*sum(ln(p_i)) follows the
    # chi-squared distribution with 2*n degrees of freedom.  This has been
    # proven (in some appropriate sense) to be the most sensitive possible test
    # for rejecting the hypothesis that a vector of probabilities is uniformly
    # distributed.  Gary Robinson's original scheme was monotonic *with* this
    # test, but skipped the details.  Turns out that getting closer to the
    # theoretical roots gives a much sharper classification, with a very small
    # (in # of msgs), but also very broad (in range of scores), "middle
    # ground", where most of the mistakes live.  In particular, this scheme
    # seems immune to all forms of "cancellation disease": if there are many
    # strong ham *and* spam clues, this reliably scores close to 0.5.  Most
    # other schemes are extremely certain then -- and often wrong.
    def spamprob(self, wordstream, evidence=False):
        """Returns best-guess probability that `wordstream` is spam.

        `wordstream` is an iterable of strings. The return value is a float in
        the interval [0.0, 1.0].

        If `evidence` is ``True``, the return value is a pair in which the
        first element is the probability as described above and the second
        element is a list of (word, probability) pairs representing....

        """
        # We compute two chi-squared statistics, one for ham and one for spam.
        # The sum-of-the-logs business is more sensitive to probs near 0 than
        # to probs near 1, so the spam measure uses 1-p (so that high-spamprob
        # words have greatest effect), and the ham measure uses p directly (so
        # that lo-spamprob words have greatest effect).
        #
        # For optimization, sum-of-logs == log-of-product, and f.p.
        # multiplication is a lot cheaper than calling ln().  It's easy to
        # underflow to 0.0, though, so we simulate unbounded dynamic range via
        # frexp.  The real product H = this H * 2**Hexp, and likewise the real
        # product S = this S * 2**Sexp.
        H = 1
        S = 1
        Hexp = 0
        Sexp = 0

        clues = self._getclues(wordstream)
        for prob, word, record in clues:
            S *= 1 - prob
            H *= prob
            if S < 1e-200:  # prevent underflow
                S, e = math.frexp(S)
                Sexp += e
            if H < 1e-200:  # prevent underflow
                H, e = math.frexp(H)
                Hexp += e

        # Compute the natural log of the product = sum of the logs:
        # ln(x * 2**i) = ln(x) + i * ln(2).
        S = math.log(S) + Sexp * LN2
        H = math.log(H) + Hexp * LN2

        n = len(clues)
        if n > 0:
            S = 1 - chi2Q(-2 * S, 2 * n)
            H = 1 - chi2Q(-2 * H, 2 * n)

            # How to combine these into a single spam score?  We originally
            # used (S-H)/(S+H) scaled into [0., 1.], which equals S/(S+H).  A
            # systematic problem is that we could end up being near-certain
            # a thing was (for example) spam, even if S was small, provided
            # that H was much smaller.
            #
            # Rob Hooft stared at these problems and invented the measure
            # we use now, the simpler S-H, scaled into [0., 1.].
            prob = (S - H + 1) / 2
        else:
            prob = 0.5

        if evidence:
            clues = [(w, p) for p, w, _r in clues]
            clues.sort(key=lambda x: x[1])
            clues.insert(0, (b'*S*', S))
            clues.insert(0, (b'*H*', H))
            return prob, clues
        return prob

    def learn_spam(self, wordstream):
        """Convenience method for ``self.learn(wordstream, True)``."""
        self.learn(wordstream, True)

    def learn_ham(self, wordstream):
        """Convenience method for ``self.learn(wordstream, False)``."""
        self.learn(wordstream, False)

    def unlearn_spam(self, wordstream):
        """Convenience method for ``self.unlearn(wordstream, True)``."""
        self.unlearn(wordstream, True)

    def unlearn_ham(self, wordstream):
        """Convenience method for ``self.unlearn(wordstream, False)``."""
        self.unlearn(wordstream, False)

    def learn(self, wordstream, is_spam):
        """Teach the classifier that the words in `wordstream` are either
        definitely spam or definitely ham.

        `wordstream` is an iterable of strings representing a message. If
        `is_spam` is ``True``, the classifier will learn that this message is
        definitely spam, otherwise it will learn that it's definitely ham (that
        is, not spam).

        """
        if self._use_bigrams:
            wordstream = self._enhance_wordstream(wordstream)
        self._add_msg(wordstream, is_spam)

    def unlearn(self, wordstream, is_spam):
        """Un-learns the message represented by `wordstream`.

        In case of a mistaken invocation of :meth:`learn`, call this method as
        soon as possible afterwards. This should be called with the same
        arguments as in the invocatino of :meth:`learn`, representing the
        message that should be un-learned.

        """
        if self._use_bigrams:
            wordstream = self._enhance_wordstream(wordstream)
        self._remove_msg(wordstream, is_spam)

    def _enhance_wordstream(self, wordstream):
        """Add bigrams to the wordstream.

        For example, a b c -> a b "a b" c "b c"

        Note that these are *token* bigrams, and not *word* bigrams - i.e.
        'synthetic' tokens get bigram'ed, too.

        The bigram token is simply "bi:unigram1 unigram2" - a space should
        be sufficient as a separator, since spaces aren't in any other
        tokens, apart from 'synthetic' ones.  The "bi:" prefix is added
        to avoid conflict with tokens we generate (like "subject: word",
        which could be "word" in a subject, or a bigram of "subject:" and
        "word").

        If the "use_bigrams" functionality is removed, this function can be
        removed, too.

        """
        # For the sake of brevity, create an alias.
        chain = itertools.chain.from_iterable
        # Create an iterable of bigrams from `wordstream`.
        bigrams = zip(wordstream, itertools.islice(wordstream, 1, None))
        # This string interpolation must match the one in _getclues().
        to_string = lambda x, y: BIGRAM_FORMAT.format(x, y)
        # This interleaves the individual strings from `wordstream` with the
        # string representation of the bigrams.
        return chain(zip(wordstream, (to_string(x, y) for x, y in bigrams)))

    def probability(self, record):
        """Computes, stores, and returns the probability that a message is spam
        given that the message contains a specific word.

        `record` is an instance of :class:`WordInfo`, representing the word in
        a given message for which we are computing the conditional probability.

        Implementation note: this is the Graham calculation, but stripped of
        both biases and clamping into the interval [0.01, 0.99]. The Bayesian
        adjustment following keeps them in a sane range, and one that naturally
        grows the more evidence there is to back up a probability.

        """

        spamcount = record.spamcount
        hamcount = record.hamcount

        # Try the cache first
        try:
            return self._probcache[spamcount][hamcount]
        except KeyError:
            pass

        nham = self.nham or 1
        nspam = self.nspam or 1

        if hamcount > nham:
            raise Exception('Token seen in more ham than ham trained.')
        if spamcount > nspam:
            raise Exception('Token seen in more spam than spam trained.')

        hamratio = hamcount / nham
        spamratio = spamcount / nspam
        prob = spamratio / (hamratio + spamratio)

        S = UNKNOWN_WORD_STRENGTH
        StimesX = S * UNKNOWN_WORD_PROB

        # Now do Robinson's Bayesian adjustment.
        #
        #         s*x + n*p(w)
        # f(w) = --------------
        #           s + n
        #
        # I find this easier to reason about like so (equivalent when
        # s != 0):
        #
        #        x - p
        #  p +  -------
        #       1 + n/s
        #
        # In other words, it moves p a fraction of the distance from p to x,
        # and less so the larger n is, or the smaller s is.

        n = hamcount + spamcount
        prob = (StimesX + n * prob) / (S + n)

        # Update the cache
        try:
            self._probcache[spamcount][hamcount] = prob
        except KeyError:
            self._probcache[spamcount] = {hamcount: prob}

        return prob

    # NOTE: Graham's scheme had a strange asymmetry: when a word appeared n > 1
    # times in a single message, training added n to the word's hamcount or
    # spamcount, but predicting scored words only once.  Tests showed that
    # adding only 1 in training, or scoring more than once when predicting,
    # hurt under the Graham scheme.
    #
    # This isn't so under Robinson's scheme, though: results improve if
    # training also counts a word only once.  The mean ham score decreases
    # significantly and consistently, ham score variance decreases likewise,
    # mean spam score decreases (but less than mean ham score, so the spread
    # increases), and spam score variance increases.
    #
    # I (Tim) speculate that adding n times under the Graham scheme helped
    # because it acted against the various ham biases, giving frequently
    # repeated spam words (like "Viagra") a quick ramp-up in spamprob; else,
    # adding only once in training, a word like that was simply ignored until
    # it appeared in 5 distinct training spams.  Without the ham-favoring
    # biases, though, and never ignoring words, counting n times introduces a
    # subtle and unhelpful bias.
    #
    # There does appear to be some useful info in how many times a word appears
    # in a msg, but distorting spamprob doesn't appear a correct way to exploit
    # it.
    def _add_msg(self, wordstream, is_spam):
        self._probcache = {}    # nuke the prob cache
        if is_spam:
            self.nspam += 1
        else:
            self.nham += 1

        for word in set(wordstream):
            record = self._wordinfoget(word)
            if record is None:
                record = self.WordInfoClass()

            if is_spam:
                record.spamcount += 1
            else:
                record.hamcount += 1

            self._wordinfoset(word, record)

        self._post_training()

    def _remove_msg(self, wordstream, is_spam):
        self._probcache = {}    # nuke the prob cache
        if is_spam:
            if self.nspam <= 0:
                raise ValueError("spam count would go negative!")
            self.nspam -= 1
        else:
            if self.nham <= 0:
                raise ValueError("non-spam count would go negative!")
            self.nham -= 1

        for word in set(wordstream):
            record = self._wordinfoget(word)
            if record is not None:
                if is_spam:
                    if record.spamcount > 0:
                        record.spamcount -= 1
                else:
                    if record.hamcount > 0:
                        record.hamcount -= 1
                if record.hamcount == 0 == record.spamcount:
                    self._wordinfodel(word)
                else:
                    self._wordinfoset(word, record)

        self._post_training()

    def _post_training(self):
        """This is called after training on a wordstream.  Subclasses might
        want to ensure that their databases are in a consistent state at
        this point.  Introduced to fix bug #797890.

        """
        pass

    def _getclues(self, wordstream):
        """Return list of (probability, word, record) triples, sorted by
        increasing probability.

        In each triple "word" is a token from wordstream, "probability" is the
        word's spam probability (a float in 0.0 through 1.0), and "record" is
        the word's associated :class:`WordInfo` object if the word is in the
        training database, or ``None`` if the word is not in the database. No
        more than :const:`MAX_DISCRIMINATORS` items are returned, and have the
        strongest (that is, farthest from 0.5) spam probability of all tokens
        in `wordstream`. Tokens with probability less than
        :const:`MINIMUM_PROB_STRENGTH` from 0.5 aren't returned.

        """
        if self._use_bigrams:
            # This scheme mixes single tokens with pairs of adjacent tokens.
            # wordstream is "tiled" into non-overlapping unigrams and
            # bigrams.  Non-overlap is important to prevent a single original
            # token from contributing to more than one spamprob returned
            # (systematic correlation probably isn't a good thing).

            # First fill list raw with
            #     (distance, prob, word, record), indices
            # pairs, one for each unigram and bigram in wordstream.
            # indices is a tuple containing the indices (0-based relative to
            # the start of wordstream) of the tokens that went into word.
            # indices is a 1-tuple for an original token, and a 2-tuple for
            # a synthesized bigram token.  The indices are needed to detect
            # overlap later.
            raw = []
            pair = None
            # Keep track of which tokens we've already seen.
            seen = set()
            for i, token in enumerate(wordstream):
                if i:   # not the 1st loop trip, so there is a preceding token
                    # This string interpolation must match the one in
                    # _enhance_wordstream().
                    pair = BIGRAM_FORMAT.format(last_token, token)
                last_token = token
                for clue, indices in (token, (i,)), (pair, (i - 1, i)):
                    if clue not in seen:    # as always, skip duplicates
                        seen.add(clue)
                        tup = self._worddistanceget(clue)
                        if tup[0] >= MINIMUM_PROB_STRENGTH:
                            raw.append((tup, indices))

            # Sort raw, strongest to weakest spamprob.
            raw.sort(reverse=True)
            # raw.reverse()
            # Fill clues with the strongest non-overlapping clues.
            clues = []
            # Keep track of which indices have already contributed to a
            # clue in clues.
            seen = set()
            for tup, indices in raw:
                overlap = [i for i in indices if i in seen]
                if not overlap:  # no overlap with anything already in clues
                    seen.update(indices)
                    clues.append(tup)
            # Leave sorted from smallest to largest spamprob.
            clues.reverse()

        else:
            # The all-unigram scheme just scores the tokens as-is.  A set()
            # is used to weed out duplicates at high speed.
            # clues = []
            # for word in set(wordstream):
            #     tup = self._worddistanceget(word)
            #     if tup[0] >= MINIMUM_PROB_STRENGTH:
            #         clues.append(tup)
            # clues.sort()
            clues = sorted(tup for tup in
                           (self._worddistanceget(word)
                            for word in set(wordstream))
                           if tup[0] >= MINIMUM_PROB_STRENGTH)

        # If there are too many clues, remove the first few.
        if len(clues) > MAX_DISCRIMINATORS:
            del clues[0:-MAX_DISCRIMINATORS]

        # Return (prob, word, record).
        return [t[1:] for t in clues]

    def _worddistanceget(self, word):
        record = self._wordinfoget(word)
        if record is None:
            prob = UNKNOWN_WORD_PROB
        else:
            prob = self.probability(record)
        distance = abs(prob - 0.5)
        return distance, prob, word, record

    def _wordinfoget(self, word):
        return self.wordinfo.get(word)

    def _wordinfoset(self, word, record):
        self.wordinfo[word] = record

    def _wordinfodel(self, word):
        del self.wordinfo[word]

    def _wordinfokeys(self):
        return self.wordinfo.keys()
