from spambayes.classifier import Classifier
from spambayes.classifier import HAM_CUTOFF
from spambayes.classifier import SPAM_CUTOFF

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
