# constants.py - constant variables used in multiple modules
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
HAM_CUTOFF = 0.2
SPAM_CUTOFF = 0.9

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
#USE_CHI_SQUARED_COMBINING = True
