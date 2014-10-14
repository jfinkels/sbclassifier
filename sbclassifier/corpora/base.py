# base.py - classes for a corpus of messages
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
"""Corpus.py - Spambayes corpus management framework.

Classes:
    Corpus - a collection of Messages
    ExpiryCorpus - a "young" Corpus
    MessageFactory - creates a Message

Abstract:
    A corpus is defined as a set of messages that share some common
    characteristic relative to spamness.  Examples might be spam, ham,
    unsure, or untrained, or "bayes rating between .4 and .6".  A
    corpus is a collection of messages.  Corpus is a dictionary that
    is keyed by the keys of the messages within it.  It is iterable,
    and observable.  Observers are notified when a message is added
    to or removed from the corpus.

    Corpus is designed to cache message objects.  By default, it will
    only engage in lazy creation of message objects, keeping those
    objects in memory until the corpus instance itself is destroyed.
    In large corpora, this could consume a large amount of memory.  A
    cacheSize operand is implemented on the constructor, which is used
    to limit the *number* of messages currently loaded into memory.
    The instance variable that implements this cache is
    Corpus.Corpus.msgs, a dictionary.  Access to this variable should
    be through keys(), [key], or using an iterator.  Direct access
    should not be used, as subclasses that manage their cache may use
    this variable very differently.

    Iterating Corpus objects is potentially very expensive, as each
    message in the corpus will be brought into memory.  For large
    corpora, this could consume a lot of system resources.

    ExpiryCorpus is designed to keep a corpus of file messages that
    are guaranteed to be younger than a given age.  The age is
    specified on the constructor, as a number of seconds in the past.
    If a message file was created before that point in time, the a
    message is deemed to be "old" and thus ignored.  Access to a
    message that is deemed to be old will raise KeyError, which should
    be handled by the corpus user as appropriate.  While iterating,
    KeyError is handled by the iterator, and messages that raise
    KeyError are ignored.

    As messages pass their "expiration date," they are eligible for
    removal from the corpus. To remove them properly,
    removeExpiredMessages() should be called.  As messages are removed,
    observers are notified.

    ExpiryCorpus function is included into a concrete Corpus through
    multiple inheritance. It must be inherited before any inheritance
    that derives from Corpus.  For example:

        class RealCorpus(Corpus)
           ...

        class ExpiryRealCorpus(Corpus.ExpiryCorpus, RealCorpus)
           ...

    Messages have substance, which is is the textual content of the
    message. They also have a key, which uniquely defines them within
    the corpus.  This framework makes no assumptions about how or if
    messages persist.

    MessageFactory is a required factory class, because Corpus is
    designed to do lazy initialization of messages and, as an abstract
    class, must know how to create concrete instances of the correct
    class.

To Do:
    o Suggestions?

"""

__author__ = "Tim Stone <tim@fourstonesExpressions.com>"
__credits__ = "Richie Hindle, Tim Peters, all the spambayes contributors."

import logging

from blinker import signal

from sbclassifier.corpora.caches import NaiveCache
from sbclassifier.corpora.caches import INFINITY

SPAM = True
HAM = False

#: Flags that the Trainer will recognise.  These should be or'able integer
#: values (i.e. 1, 2, 4, 8, etc.).
NO_TRAINING_FLAG = 1


#: A signal that is emitted when a message is added to a corpus.
#:
#: Subscribers to this signal receive the corpus object that emitted the
#: signal, along with a ``message`` keyword argument, whose value contains the
#: message that was added.
message_added = signal('message-added')

#: A signal that is emitted when a message is removed from a corpus.
#:
#: Subscribers to this signal receive the corpus object that emitted the
#: signal, along with a ``message`` keyword argument, whose value contains the
#: message that was removed.
message_removed = signal('message-removed')


class Corpus:
    """A dictionary of :class:`Message` objects.

    The corpus is backed by an internal cache of messages, whose class is
    specified in :attr:`CacheClass`. When messages are added or removed via the
    :meth:`add_message` or :meth:`remove_message`, respectively, the
    ``message_added`` or ``message_removed`` signal is emitted. To connect a
    function to these signal, use code like the following::

        from sbclassifier import message_added
        from sbclassifier import message_removed

        @message_added.connect
        def on_message_added(corpus, message):
            print('Message {} was added to corpus {}'.format(message, corpus))

        @message_removed.connect
        def on_message_added(corpus, message):
            print('Message {} was added to corpus {}'.format(message, corpus))


    `cache` is the cache to use for caching messages accessed within this
    corpus. If not specified, a default :class:`NaiveCache` will be used.

    """

    def __init__(self, cache=None):
        self.message_cache = cache or NaiveCache(max_size=INFINITY)
        # dict of all messages in corpus; value is None if msg not currently
        # loaded
        #self.msgs = {}
        # keys of messages currently loaded this *could* be derived by
        # iterating msgs
        #self.keysInMemory = []
        #self.cacheSize = cacheSize  # max number of messages in memory
        #self.factory = factory    # factory for the correct Message subclass

    def add_message(self, message, message_id=None, emit_signal=True):
        """Adds the specified message to this corpus.

        If `emit_signal` is ``True``, the :data:`message_added` signal is
        emitted.

        """
        key = message.id() if message_id is None else message_id
        logging.debug('adding message %s to corpus', key)
        self.message_cache.put(key, message)
        if emit_signal:
            message_added.send(self, message=message)

    def remove_message(self, message, emit_signal=True):
        """Removes the specified message from this corpus.

        If `emit_signal` is ``True``, the :data:`message_removed` signal is
        emitted.

        """
        key = message.id()
        logging.debug('removing message %s from corpus', key)
        self.message_cache.pop(key)
        #del self.msgs[key]
        if emit_signal:
            message_removed.send(self, message=message)

    # def cache_message(self, message):
    #     """Adds a message to the in-memory cache."""
    #     # This method should probably not be overridden
    #     key = message.key()
    #     logging.debug('placing %s in corpus cache', key)
    #     self.msgs[key] = message
    #     # Here is where we manage the in-memory cache size...
    #     self.keysInMemory.append(key)
    #     if self.cacheSize > 0:       # performance optimization
    #         if len(self.keysInMemory) > self.cacheSize:
    #             keyToFlush = self.keysInMemory[0]
    #             self.uncache_message(keyToFlush)

    # def uncache_message(self, key):
    #     """Removes the message with the specified key from the in-memory cache.

    #     """
    #     # This method should probably not be overridden
    #     logging.debug('Flushing %s from corpus cache', key)
    #     try:
    #         ki = self.keysInMemory.index(key)
    #     except ValueError:
    #         pass
    #     else:
    #         del self.keysInMemory[ki]
    #     self.msgs[key] = None

    # def takeMessage(self, key, fromcorpus, fromCache=False):
    #     '''Move a Message from another corpus to this corpus'''
    #     msg = fromcorpus[key]
    #     msg.load()  # ensure that the substance has been loaded
    #     # Remove needs to be first, because add changes the directory
    #     # of the message, and so remove won't work then.
    #     fromcorpus.removeMessage(msg)
    #     self.addMessage(msg)

    # def make_message(self, key, content=None):
    #     # This method will likely be overridden
    #     return self.factory.create(key, content)

    def get(self, key, default=None):
        # if key not in self.msgs:
        #     return default
        # return self[key]
        return self.message_cache.get(key, default)

    def __getitem__(self, key):
        # amsg = self.msgs[key]
        # if amsg is None:
        #     amsg = self.make_message(key)     # lazy init, saves memory
        #     self.cache_message(amsg)
        # return amsg
        return self.message_cache[key]

    def keys(self):
        return self.message_cache.keys()

    def values(self):
        return self.message_cache.values()

    def items(self):
        return self.message_cache.items()

    def __contains__(self, key):
        return key in self.message_cache

    def __len__(self):
        return len(self.message_cache)

    def __iter__(self):
        return iter(self.message_cache)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        raise NotImplementedError


# class MessageFactory(object):
#     '''Abstract Message Factory'''
#     def create(self, key, content=None):
#         '''Create a message instance'''
#         raise NotImplementedError
