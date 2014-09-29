HAM_CUTOFF = 0.2
SPAM_CUTOFF = 0.9

#: The maximum number of extreme words to look at in a message, where "extreme"
#: means with spam probability farthest away from 0.5.  150 appears to work
#: well across all corpora tested.
MAX_DISCRIMINATORS = 150

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

#: For vectors of random, uniformly distributed probabilities, -2*sum(ln(p_i))
#: follows the chi-squared distribution with 2*n degrees of freedom.  This is
#: the "provably most-sensitive" test the original scheme was monotonic with.
#: Getting closer to the theoretical basis appears to give an excellent
#: combining method, usually very extreme in its judgment, yet finding a tiny
#: (in of msgs, spread across a huge range of scores) middle ground where lots
#: of the mistakes live.  This is the best method so far. One systematic
#: benefit is is immunity to "cancellation disease". One systematic drawback is
#: sensitivity to *any* deviation from a uniform distribution, regardless of
#: whether actually evidence of ham or spam. Rob Hooft alleviated that by
#: combining the final S and H measures via (S-H+1)/2 instead of via S/(S+H)).
#: In practice, it appears that setting ham_cutoff=0.05, and spam_cutoff=0.95,
#: does well across test sets; while these cutoffs are rarely optimal, they get
#: close to optimal.  With more training data, Tim has had good luck with
#: ham_cutoff=0.30 and spam_cutoff=0.80 across three test data sets (original
#: c.l.p data, his own email, and newer general python.org traffic).
USE_CHI_SQUARED_COMBINING = True

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

#: If true, tokenizer.Tokenizer.tokenize_headers() will tokenize the contents
#: of each header field just like the text of the message body, using the name
#: of the header as a tag. Tokens look like "header:word". The basic approach
#: is simple and effective, but also very sensitive to biases in the ham and
#: spam collections. For example, if the ham and spam were collected at
#: different times, several headers with date/time information will become the
#: best discriminators. (Not just Date, but Received and X-From_.)
BASIC_HEADER_TOKENIZE = False

#: If true and basic_header_tokenize is also true, then basic_header_tokenize
#: is the only action performed.
BASIC_HEADER_TOKENIZE_ONLY = False
