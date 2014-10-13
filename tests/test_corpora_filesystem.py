# test_corpora.py - unit tests for the sbclassifier.corpora.filesystem module
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
import os
import sys
import time
import gzip
import errno
import unittest

from sbclassifier import message
from sbclassifier.corpora import ExpiryFileCorpus
from sbclassifier.corpora import FileCorpus
#from sbclassifier.corpora import FileMessage
#from sbclassifier.corpora import FileMessageFactory
#from sbclassifier.corpora import GzipFileMessage
#from sbclassifier.corpora import GzipFileMessageFactory

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

# class _FactoryBaseTest(unittest.TestCase):
#     # Subclass must define a concrete factory.
#     factory = None
#     def test_create_no_content(self):
#         f = self.factory()
#         key = "testmessage"
#         directory = "fctesthamcorpus"
#         msg = f.create(key, directory)
#         self.assertEqual(msg.file_name, key)
#         self.assertEqual(msg.directory, directory)
#         self.assertEqual(msg.loaded, False)

#     def test_create_with_content(self):
#         f = self.factory()
#         key = "testmessage"
#         directory = "fctesthamcorpus"
#         content = good1
#         msg = f.create(key, directory, content=good1)
#         self.assertEqual(msg.file_name, key)
#         self.assertEqual(msg.directory, directory)
#         self.assertEqual(msg.loaded, True)
#         self.assertEqual(msg.as_string(), good1.replace("\n", "\r\n"))


# class FileMessageFactoryTest(_FactoryBaseTest):
#     factory = FileMessageFactory
#     def test_klass(self):
#         self.assertEqual(self.factory.klass, FileMessage)


# class GzipFileMessageFactoryTest(_FactoryBaseTest):
#     factory = GzipFileMessageFactory
#     def test_klass(self):
#         self.assertEqual(self.factory.klass, GzipFileMessage)


class _FileCorpusBaseTest(unittest.TestCase):
    def _setUpDirectory(self, dirname):
        try:
            os.mkdir(dirname)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    def setUp(self):
        # Make corpus directories.
        self._setUpDirectory('fctestspamcorpus')
        self._setUpDirectory('fctesthamcorpus')
        self._setUpDirectory('fctestunsurecorpus')

    def _tearDownDirectory(self, dirname):
        try:
            flist = os.listdir(dirname)
        except OSError as e:
            if e.errno != 3:
                raise
        else:
            for filename in flist:
                fn = os.path.join(dirname, filename)
                os.unlink(fn)
        try:
            os.rmdir(dirname)
        except OSError as e:
            if e.errno != 2:
                raise

    def tearDown(self):
        self._tearDownDirectory('fctestspamcorpus')
        self._tearDownDirectory('fctesthamcorpus')
        self._tearDownDirectory('fctestunsurecorpus')

        try:
            os.unlink('fctestmisc.bayes')
        except OSError as e:
            if e.errno != 2:
                raise
        try:
            os.unlink('fctestclass.bayes')
        except OSError as e:
            if e.errno != 2:
                raise


# class _FileMessageBaseTest(_FileCorpusBaseTest):
#     # Subclass must define a concrete message klass, and wrong_klass.
#     klass = None
#     wrong_klass = None

#     def setUp(self):
#         _FileCorpusBaseTest.setUp(self)
#         self.filename = "testmessage"
#         self.directory = "fctestspamcorpus"
#         fn = os.path.join(self.directory, self.filename)
#         try:
#             os.remove(fn)
#         except OSError:
#             pass
#         with open(fn, "w") as f:
#             self.created_time = time.time()
#             f.write(spam1)
#         self.msg = self.klass(self.filename, self.directory)
#         # Message of wrong type, to test mixed corpus.
#         self.wrongname = "wrongmessage"
#         def good_as_string():
#             return good1
#         wrong_msg = self.wrong_klass(self.wrongname, self.directory)
#         wrong_msg.as_string = good_as_string
#         wrong_msg.store()

#     def tearDown(self):
#         fn = os.path.join(self.directory, self.filename)
#         try:
#             os.remove(fn)
#         except OSError:
#             pass
#             fn = os.path.join(self.directory, self.wrongname)
#         try:
#             os.remove(fn)
#         except OSError:
#             pass
#         _FileCorpusBaseTest.tearDown(self)

#     def test___init__(self):
#         self.assertEqual(self.msg.file_name, self.filename)
#         self.assertEqual(self.msg.directory, self.directory)
#         self.assertEqual(self.msg.loaded, False)

#     def test_as_string(self):
#         self.assertEqual(self.msg.as_string(), spam1.replace("\n", "\r\n"))

#     def test_pathname(self):
#         self.assertEqual(self.msg.pathname(), os.path.join(self.directory,
#                                                            self.filename))

#     def test_name(self):
#         self.assertEqual(self.msg.name(), self.filename)

#     def test_key(self):
#         self.assertEqual(self.msg.key(), self.filename)

#     def test_createTimestamp(self):
#         timestamp = self.msg.createTimestamp()
#         # As long as they are equal to the nearest second, that will do.
#         self.assertEqual(int(timestamp), int(self.created_time))

#     def test_remove(self):
#         pathname = os.path.join(self.directory, self.filename)
#         self.assertEqual(os.path.exists(pathname), True)
#         self.msg.remove()
#         self.assertEqual(os.path.exists(pathname), False)

#     def test_remove_not_there(self):
#         pathname = os.path.join(self.directory, self.filename)
#         self.assertEqual(os.path.exists(pathname), True)
#         os.remove(pathname)
#         self.msg.remove()
#         self.assertEqual(os.path.exists(pathname), False)

#     def test_load(self):
#         # Load correct type.
#         self.assertEqual(self.msg.loaded, False)
#         self.msg.load()
#         self.assertEqual(self.msg.loaded, True)
#         self.assertEqual(self.msg.as_string(), spam1.replace("\n", "\r\n"))

#     def test_load_wrong(self):
#         # Load incorrect type.
#         self.msg.file_name = self.wrongname
#         self.assertEqual(self.msg.loaded, False)
#         self.msg.load()
#         self.assertEqual(self.msg.loaded, True)
#         self.assertEqual(self.msg.as_string(), good1.replace("\n", "\r\n"))

#     def test_load_already_loaded(self):
#         # Shouldn't do anything if already loaded.
#         self.msg.file_name = None
#         self.msg.loaded = True
#         # This will raise an error if a load from storage is attempted.
#         self.msg.load()


# class FileMessageTest(_FileMessageBaseTest):
#     klass = FileMessage
#     wrong_klass = GzipFileMessage

#     def test_store(self):
#         def good_as_string():
#             return good1
#         self.msg.as_string = good_as_string
#         self.msg.store()
#         pathname = os.path.join(self.directory, self.filename)
#         with open(pathname) as f:
#             content = f.read()
#         self.assertEqual(content, good1)


# class GzipFileMessageTest(_FileMessageBaseTest):
#     klass = GzipFileMessage
#     wrong_klass = FileMessage

#     def test_store(self):
#         def good_as_string():
#             return good1
#         self.msg.as_string = good_as_string
#         self.msg.store()
#         pathname = os.path.join(self.directory, self.filename)
#         with gzip.open(pathname) as f:
#             content = f.read()
#         self.assertEqual(content, bytes(good1, 'utf-8'))


class FileCorpusTest(_FileCorpusBaseTest):
    def setUp(self):
        _FileCorpusBaseTest.setUp(self)
        self.directory = 'fctesthamcorpus'
        self.cache_size = 100
        #self.factory = FileMessageFactory()
        self._stuff_corpus()
        self.corpus = FileCorpus(self.directory, '?', self.cache_size)

    def _create_and_write(self, message_id, content):
        msg = message.from_string(content, message_id=message_id)
        filename = os.path.join(self.directory, msg.id())
        with open(filename, 'wb') as f:
            f.write(msg.as_bytes())
        return msg

    def _stuff_corpus(self):
        """Put messages in the corpus"""
        for i, content in enumerate([good1, spam1, malformed1]):
            self.msg = self._create_and_write(str(i), content)

        # Put in a message that won't match the filter.
        self._create_and_write(str(10), good1)

    # def test___init__(self):
    #     self.assertEqual(self.corpus.directory, self.directory)
    #     self.assertEqual(self.corpus.filter, '?')
    #     #self.assertEqual(self.corpus.cacheSize, self.cache_size)

    def test_filter(self):
        self.assertEqual(len(self.corpus), 3)
        # Try again, with all messages.
        self.corpus = FileCorpus(self.directory, '*', self.cache_size)
        self.assertEqual(len(self.corpus), 4)

    # def test_makeMessage_no_content(self):
    #     key = "testmake"
    #     self.corpus.make_message(key)

    # def test_makeMessage_with_content(self):
    #     key = "testmake"
    #     content = spam1
    #     msg = self.corpus.make_message(key, content)
    #     self.assertEqual(msg.key(), key)
    #     self.assertEqual(msg.as_string(), content.replace("\n", "\r\n"))

    def test_addMessage_invalid(self):
        class msg(object):
            def id(self):
                return 'aa'
        self.assertRaises(ValueError, self.corpus.add_message, msg())

    def test_addMessage(self):
        msg = self._create_and_write('9', good1)
        self.corpus.add_message(msg)
        #self.assertEqual(msg.directory, self.directory)
        fn = os.path.join(self.directory, "9")
        with open(fn, "rU") as f:
            content = f.read()
        self.assertEqual(content, good1)

    def test_removeMessage(self):
        fn = self.corpus._message_path(self.msg)
        self.assertEqual(os.path.exists(fn), True)
        self.corpus.remove_message(self.msg)
        self.assertEqual(os.path.exists(fn), False)


class ExpiryFileCorpusTest(_FileCorpusBaseTest):
    def setUp(self):
        _FileCorpusBaseTest.setUp(self)
        self.cache_size = 100
        self.directory = 'fctesthamcorpus'

        class SimpleFileMessage(FileMessage):
            def __init__(self, *args, **kw):
                super().__init__(*args, **kw)
                self.creation_time = time.time()

            def creationTime(self):
                return self.creation_time

        class SimpleFactory(FileMessageFactory):
            klass = SimpleFileMessage

        self.factory = SimpleFactory()
        #self.stuff_corpus()
        self.corpus = ExpiryFileCorpus(10.0, self.directory,
                                       '?', self.cache_size)

    @unittest.skip('This fails occasionally due to timing issues...')
    def test_removeExpiredMessages(self):
        # Put messages in to expire.
        expire = [self.factory.create(str(i), self.directory, '')
                  for i in (0, 1)]
        for msg in expire:
            msg.store()
            self.corpus.add_message(msg)

        # Ensure that we don't expire the wrong ones.
        #
        # Need to sleep for 1 second here because the default timestamps
        # generated for messages backed by files on the filesystem are based on
        # the creation time as read by os.stat, and those times are measured in
        # seconds, not milliseconds.
        self.corpus.expireBefore = 0.5
        time.sleep(1)

        # Put messages in to not expire.
        not_expire = [self.factory.create(str(i), self.directory, '')
                      for i in (2, 3)]
        for msg in not_expire:
            msg.store()
            self.corpus.add_message(msg)

        # Run expiry.
        print(self.corpus.msgs)
        self.corpus.remove_expired_messages()
        print(self.corpus.msgs)


        # Check that expired messages are gone.
        for msg in expire:
            self.assertFalse(msg in self.corpus)

        # Check that not expired messages are still there.
        for msg in not_expire:
            self.assertTrue(msg in self.corpus)
