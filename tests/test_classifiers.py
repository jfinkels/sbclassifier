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
    classifier = Classifier()
    # Definitely not spam.
    classifier.learn('dog cat horse sloth koala', False)
    # Definitely spam.
    classifier.learn('shark raptor bear spider cockroach', True)
    probability = classifier.spamprob('shark bear spider')
    assert SPAM_CUTOFF <= probability
    probability = classifier.spamprob('dog sloth koala')
    assert probability <= HAM_CUTOFF
