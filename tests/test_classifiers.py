# test_classifiers.py - unit tests for the sbclassifier.classifiers package
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
from sbclassifier import Classifier
from sbclassifier.classifiers.constants import HAM_CUTOFF
from sbclassifier.classifiers.constants import SPAM_CUTOFF


def test_classifier():
    ham_strings = 'dog cat horse sloth koala'.split()
    spam_strings = 'shark raptor bear spider cockroach'.split()
    classifier = Classifier()
    classifier.learn_ham(ham_strings)
    classifier.learn_spam(spam_strings)
    probability = classifier.spamprob(['shark', 'bear', 'spider'])
    assert SPAM_CUTOFF <= probability
    probability = classifier.spamprob(['dog', 'sloth', 'koala'])
    assert probability <= HAM_CUTOFF


def test_bigrams():
    ham_strings = 'dog cat horse sloth koala'.split()
    spam_strings = 'shark raptor bear spider cockroach'.split()
    classifier = Classifier(use_bigrams=True)
    classifier.learn_ham(ham_strings)
    classifier.learn_spam(spam_strings)
    probability = classifier.spamprob(['shark', 'bear', 'spider'])
    assert SPAM_CUTOFF <= probability
    probability = classifier.spamprob(['dog', 'sloth', 'koala'])
    assert probability <= HAM_CUTOFF
