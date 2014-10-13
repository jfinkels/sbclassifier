# test_corpora_base.py - unit tests for the sbclassifier.corpora.base module
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
import time
import unittest

from sbclassifier.corpora import message_added
from sbclassifier.corpora import message_removed
from sbclassifier.corpora import Corpus
#from sbclassifier.corpora import MessageFactory

# One example of spam and one of ham - both are used to train, and are
# then classified.  Not a good test of the classifier, but a perfectly
# good test of the POP3 proxy.  The bodies of these came from the
# spambayes project, and Richie added the headers because the
# originals had no headers.

spam1 = """From: friend@public.com
Subject: Make money fast

Hello tim_chandler , Want to save money ?
Now is a good time to consider refinancing. Rates are low so you can cut
your current payments and save money.

http://64.251.22.101/interest/index%38%30%300%2E%68t%6D

Take off list on site [s5]
"""

good1 = """From: chris@example.com
Subject: ZPT and DTML

Jean Jordaan wrote:
> 'Fraid so ;>  It contains a vintage dtml-calendar tag.
>   http://www.zope.org/Members/teyc/CalendarTag
>
> Hmm I think I see what you mean: one needn't manually pass on the
> namespace to a ZPT?

Yeah, Page Templates are a bit more clever, sadly, DTML methods aren't :-(

Chris
"""

# An example of a particularly nasty malformed message - where there is
# no body, and no separator, which would at one point slip through
# SpamBayes.  This is an example that Tony made up.

malformed1 = """From: ta-meyer@ihug.co.nz
Subject: No body, and no separator"""


class simple_msg(object):
    def __init__(self, key):
        self._key = key
        self.creation_time = time.time()
        self.loaded = False

    def createTimestamp(self):
        return self.creation_time

    def id(self):
        return self._key

    def load(self):
        self.loaded = True


class CorpusTest(unittest.TestCase):
    def setUp(self):
        #self.factory = MessageFactory()
        self.cacheSize = 100
        self.corpus = Corpus(self.cacheSize)

    # def test___init__(self):
    #     self.assertEqual(self.corpus.cache_size, self.cacheSize)
    #     self.assertEqual(self.corpus.msgs, {})
    #     self.assertEqual(self.corpus.keysInMemory, [])
    #     #self.assertEqual(self.corpus.factory, self.factory)

    def test_addObserver(self):
        @message_added.connect
        def add_listener(*args, **kw):
            raise ValueError

        @message_removed.connect
        def remove_listener(*args, **kw):
            raise TypeError
        self.assertRaises(ValueError, self.corpus.add_message,
                          simple_msg(0))
        self.assertRaises(TypeError, self.corpus.remove_message,
                          simple_msg(1))

    def test_addMessage(self):
        msg = simple_msg(0)
        self.assertEqual(self.corpus.get(0), None)
        self.corpus.add_message(msg)
        self.assertEqual(self.corpus[0], msg)

    def test_removeMessage(self):
        msg = simple_msg(0)
        self.assertEqual(self.corpus.get(0), None)
        self.corpus.add_message(msg)
        self.assertEqual(self.corpus[0], msg)
        self.corpus.remove_message(msg)
        self.assertEqual(self.corpus.get(0), None)

    @unittest.skip('The internal cache should not be tested here')
    def test_cacheMessage(self):
        msg = simple_msg(0)
        self.corpus.cache_message(msg)
        self.assertEqual(self.corpus.msgs[0], msg)
        self.assert_(0 in self.corpus.keysInMemory)

    @unittest.skip('The internal cache should not be tested here')
    def test_flush_cache(self):
        self.corpus.cacheSize = 1
        msg = simple_msg(0)
        self.corpus.cache_message(msg)
        self.assertEqual(self.corpus.msgs[0], msg)
        self.assert_(0 in self.corpus.keysInMemory)
        msg = simple_msg(1)
        self.corpus.cache_message(msg)
        self.assertEqual(self.corpus.msgs[1], msg)
        self.assert_(1 in self.corpus.keysInMemory)
        self.assert_(0 not in self.corpus.keysInMemory)

    @unittest.skip('The internal cache should not be tested here')
    def test_unCacheMessage(self):
        msg = simple_msg(0)
        self.corpus.cache_message(msg)
        self.assertEqual(self.corpus.msgs[0], msg)
        self.assert_(0 in self.corpus.keysInMemory)
        self.corpus.uncache_message(msg)
        self.assert_(0 in self.corpus.keysInMemory)

    # def test_takeMessage(self):
    #     other_corpus = Corpus(self.factory, self.cacheSize)
    #     msg = simple_msg(0)
    #     other_corpus.add_message(msg)
    #     self.assertEqual(self.corpus.get(0), None)
    #     self.corpus.take_message(0, other_corpus)
    #     self.assertEqual(msg.loaded, True)
    #     self.assertEqual(other_corpus.get(0), None)
    #     self.assertEqual(self.corpus.get(0), msg)

    def test_get(self):
        ids = [0, 1, 2]
        for id in ids:
            self.corpus.add_message(simple_msg(id))
        self.assertEqual(self.corpus.get(0).id(), 0)

    def test_get_fail(self):
        ids = [0, 1, 2]
        for id in ids:
            self.corpus.add_message(simple_msg(id))
        self.assertEqual(self.corpus.get(4), None)

    def test_get_default(self):
        ids = [0, 1, 2]
        for id in ids:
            self.corpus.add_message(simple_msg(id))
        self.assertEqual(self.corpus.get(4, "test"), "test")

    def test___getitem__(self):
        ids = [0, 1, 2]
        for id in ids:
            self.corpus.add_message(simple_msg(id))
        self.assertEqual(self.corpus[0].id(), 0)

    def test___getitem___fail(self):
        ids = [0, 1, 2]
        for id in ids:
            self.corpus.add_message(simple_msg(id))
        self.assertRaises(KeyError, self.corpus.__getitem__, 4)

    def test_keys(self):
        self.assertEqual(list(self.corpus.keys()), [])
        ids = [0, 1, 2]
        for id in ids:
            self.corpus.add_message(simple_msg(id))
        self.assertEqual(list(self.corpus.keys()), ids)

    def test___iter__(self):
        self.assertEqual(tuple(self.corpus), ())
        msgs = (simple_msg(0), simple_msg(1), simple_msg(2))
        for msg in msgs:
            self.corpus.add_message(msg)
        self.assertEqual(tuple(self.corpus.values()), msgs)

    # def test_makeMessage_no_content(self):
    #     key = "testmessage"
    #     self.assertRaises(NotImplementedError, self.corpus.make_message, key)

    # def test_makeMessage_with_content(self):
    #     key = "testmessage"
    #     content = good1
    #     self.assertRaises(NotImplementedError, self.corpus.make_message,
    #                       key, content)
