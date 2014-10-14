# trainers.py - objects which learn from corpora
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
"""
    Trainer is concrete class that observes a Corpus and trains a
    Classifier object based upon movement of messages between corpora  When
    an add message notification is received, the trainer trains the
    database with the message, as spam or ham as appropriate given the
    type of trainer (spam or ham).  When a remove message notification
    is received, the trainer untrains the database as appropriate.

    SpamTrainer and HamTrainer are convenience subclasses of Trainer, that
    initialize as the appropriate type of Trainer

"""
import logging

from sbclassifier.corpora import message_added
from sbclassifier.corpora import message_removed
from sbclassifier.tokenizer import tokenize


class Trainer(object):
    """Associates a Classifier object and one or more Corpora.

    `classifier` is an instance of :class:`Classifier` on which messages added
    to the corpora will be learned.

    If `is_spam` is ``True`` the messages added to the corpora are assumed to
    be spam, and this is indicated to the classifier when it learns the
    message. If `is_spam` is ``False``, the messages are assumed to be ham.

    `corpora` is an iterable of :class:`Corpus` objects to which this trainer
    will listen. When a message is added to any of these corpora, the
    :meth:`train` method will be called. When a message is removed from any of
    these corpora, the :meth:`untrain` method will be called. (The
    :meth:`train` and :meth:`untrain` methods are connected to the
    :data:`message_added` and :data:`message_removed` signals, respectively.)

    """

    def __init__(self, classifier, is_spam, corpora):
        self.classifier = classifier
        self.is_spam = is_spam
        for corpus in corpora:
            message_added.connect(self.train, sender=corpus)
            message_removed.connect(self.train, sender=corpus)

    def train(self, sender, message):
        """Train the database with the specified message.

        `sender` is the :class:`Corpus` object to which the message was added.

        `message` is an instance of :class:`Message`.

        """
        logging.debug('training with %s', message.key())
        self.classifier.learn(tokenize(message), self.is_spam)
        message.setId(message.key())
        message.RememberTrained(self.is_spam)

    def untrain(self, sender, message):
        """Untrain the database with the specified message.

        `sender` is the :class:`Corpus` object from which the message was
        removed.

        `message` is an instance of :class:`Message`.

        """
        logging.debug('untraining with %s', message.key())
        self.classifier.unlearn(tokenize(message), self.is_spam)
        # can raise ValueError if database is fouled.  If this is the case,
        # then retraining is the only recovery option.
        message.RememberTrained(None)

    # def train_corpus(self, corpus):
    #     """Train all the messages in the specified corpus."""
    #     for msg in corpus:
    #         self.train(msg)

    # def untrain_corpus(self, corpus):
    #     """Untrain all the messages in the specified corpus."""
    #     for msg in corpus:
    #         self.untrain(msg)


class SpamTrainer(Trainer):
    """Trainer that trains on messages that are assumed to be spam.

    This is a convenience class for ``Trainer(classifier, True, corpora)``.

    """

    def __init__(self, classifier, corpora):
        super().__init__(classifier, True, corpora)


class HamTrainer(Trainer):
    """Trainer that trains on messages that are assumed to be ham.

    This is a convenience class for ``Trainer(classifier, False, corpora)``.

    """

    def __init__(self, classifier, corpora):
        super().__init__(classifier, False, corpora)
