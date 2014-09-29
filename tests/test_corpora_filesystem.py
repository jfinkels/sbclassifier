# Test the FileCorpus module.

import os
import sys
import time
import gzip
import errno
import unittest

from sbclassifier import storage
from sbclassifier.corpora import ExpiryFileCorpus
from sbclassifier.corpora import FileCorpus
from sbclassifier.corpora import FileMessage
from sbclassifier.corpora import GzipFileMessage
from sbclassifier.corpora import FileMessageFactory
from sbclassifier.corpora import GzipFileMessageFactory

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

class _FactoryBaseTest(unittest.TestCase):
    # Subclass must define a concrete factory.
    factory = None
    def test_create_no_content(self):
        f = self.factory()
        key = "testmessage"
        directory = "fctesthamcorpus"
        msg = f.create(key, directory)
        self.assertEqual(msg.file_name, key)
        self.assertEqual(msg.directory, directory)
        self.assertEqual(msg.loaded, False)

    def test_create_with_content(self):
        f = self.factory()
        key = "testmessage"
        directory = "fctesthamcorpus"
        content = good1
        msg = f.create(key, directory, content=good1)
        self.assertEqual(msg.file_name, key)
        self.assertEqual(msg.directory, directory)
        self.assertEqual(msg.loaded, True)
        self.assertEqual(msg.as_string(), good1.replace("\n", "\r\n"))


class FileMessageFactoryTest(_FactoryBaseTest):
    factory = FileMessageFactory
    def test_klass(self):
        self.assertEqual(self.factory.klass, FileMessage)


class GzipFileMessageFactoryTest(_FactoryBaseTest):
    factory = GzipFileMessageFactory
    def test_klass(self):
        self.assertEqual(self.factory.klass, GzipFileMessage)


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


class _FileMessageBaseTest(_FileCorpusBaseTest):
    # Subclass must define a concrete message klass, and wrong_klass.
    klass = None
    wrong_klass = None

    def setUp(self):
        _FileCorpusBaseTest.setUp(self)
        self.filename = "testmessage"
        self.directory = "fctestspamcorpus"
        fn = os.path.join(self.directory, self.filename)
        try:
            os.remove(fn)
        except OSError:
            pass
        with open(fn, "w") as f:
            self.created_time = time.time()
            f.write(spam1)
        self.msg = self.klass(self.filename, self.directory)
        # Message of wrong type, to test mixed corpus.
        self.wrongname = "wrongmessage"
        def good_as_string():
            return good1
        wrong_msg = self.wrong_klass(self.wrongname, self.directory)
        wrong_msg.as_string = good_as_string
        wrong_msg.store()

    def tearDown(self):
        fn = os.path.join(self.directory, self.filename)
        try:
            os.remove(fn)
        except OSError:
            pass
            fn = os.path.join(self.directory, self.wrongname)
        try:
            os.remove(fn)
        except OSError:
            pass
        _FileCorpusBaseTest.tearDown(self)

    def test___init__(self):
        self.assertEqual(self.msg.file_name, self.filename)
        self.assertEqual(self.msg.directory, self.directory)
        self.assertEqual(self.msg.loaded, False)

    def test_as_string(self):
        self.assertEqual(self.msg.as_string(), spam1.replace("\n", "\r\n"))

    def test_pathname(self):
        self.assertEqual(self.msg.pathname(), os.path.join(self.directory,
                                                           self.filename))

    def test_name(self):
        self.assertEqual(self.msg.name(), self.filename)

    def test_key(self):
        self.assertEqual(self.msg.key(), self.filename)

    def test_createTimestamp(self):
        timestamp = self.msg.createTimestamp()
        # As long as they are equal to the nearest second, that will do.
        self.assertEqual(int(timestamp), int(self.created_time))

    def test_remove(self):
        pathname = os.path.join(self.directory, self.filename)
        self.assertEqual(os.path.exists(pathname), True)
        self.msg.remove()
        self.assertEqual(os.path.exists(pathname), False)

    def test_remove_not_there(self):
        pathname = os.path.join(self.directory, self.filename)
        self.assertEqual(os.path.exists(pathname), True)
        os.remove(pathname)
        self.msg.remove()
        self.assertEqual(os.path.exists(pathname), False)

    def test_load(self):
        # Load correct type.
        self.assertEqual(self.msg.loaded, False)
        self.msg.load()
        self.assertEqual(self.msg.loaded, True)
        self.assertEqual(self.msg.as_string(), spam1.replace("\n", "\r\n"))

    def test_load_wrong(self):
        # Load incorrect type.
        self.msg.file_name = self.wrongname
        self.assertEqual(self.msg.loaded, False)
        self.msg.load()
        self.assertEqual(self.msg.loaded, True)
        self.assertEqual(self.msg.as_string(), good1.replace("\n", "\r\n"))

    def test_load_already_loaded(self):
        # Shouldn't do anything if already loaded.
        self.msg.file_name = None
        self.msg.loaded = True
        # This will raise an error if a load from storage is attempted.
        self.msg.load()


class FileMessageTest(_FileMessageBaseTest):
    klass = FileMessage
    wrong_klass = GzipFileMessage

    def test_store(self):
        def good_as_string():
            return good1
        self.msg.as_string = good_as_string
        self.msg.store()
        pathname = os.path.join(self.directory, self.filename)
        with open(pathname) as f:
            content = f.read()
        self.assertEqual(content, good1)


class GzipFileMessageTest(_FileMessageBaseTest):
    klass = GzipFileMessage
    wrong_klass = FileMessage

    def test_store(self):
        def good_as_string():
            return good1
        self.msg.as_string = good_as_string
        self.msg.store()
        pathname = os.path.join(self.directory, self.filename)
        with gzip.open(pathname) as f:
            content = f.read()
        self.assertEqual(content, bytes(good1, 'utf-8'))


class FileCorpusTest(_FileCorpusBaseTest):
    def setUp(self):
        _FileCorpusBaseTest.setUp(self)
        self.directory = 'fctesthamcorpus'
        self.cache_size = 100
        self.factory = FileMessageFactory()
        self.stuff_corpus()
        self.corpus = FileCorpus(self.factory, self.directory,
                                 '?', self.cache_size)

    def stuff_corpus(self):
        """Put messages in the corpus"""
        i = 0
        for content in [good1, spam1, malformed1]:
            self.msg = self.factory.create(str(i), self.directory, content)
            self.msg.store()
            i += 1

        # Put in a message that won't match the filter.
        msg = self.factory.create("10", self.directory, good1)
        msg.store()
        
    def test___init__(self):
        self.assertEqual(self.corpus.directory, self.directory)
        self.assertEqual(self.corpus.filter, '?')
        self.assertEqual(self.corpus.cacheSize, self.cache_size)

    def test_filter(self):
        self.assertEqual(len(self.corpus.msgs), 3)
        # Try again, with all messages.
        self.corpus = FileCorpus(self.factory, self.directory,
                                 '*', self.cache_size)
        self.assertEqual(len(self.corpus.msgs), 4)

    def test_makeMessage_no_content(self):
        key = "testmake"
        self.corpus.makeMessage(key)

    def test_makeMessage_with_content(self):
        key = "testmake"
        content = spam1
        msg = self.corpus.makeMessage(key, content)
        self.assertEqual(msg.key(), key)
        self.assertEqual(msg.as_string(), content.replace("\n", "\r\n"))

    def test_addMessage_invalid(self):
        class msg(object):
            def key(self):
                return 'aa'
        self.assertRaises(ValueError, self.corpus.addMessage, msg())

    def test_addMessage(self):
        msg = self.factory.create("9", 'fctestspamcorpus', good1)
        self.corpus.addMessage(msg)
        self.assertEqual(msg.directory, self.directory)
        fn = os.path.join(self.directory, "9")
        f = open(fn, "rU")
        content = f.read()
        f.close()
        self.assertEqual(content, good1)

    def test_removeMessage(self):
        fn = self.msg.pathname()
        self.assertEqual(os.path.exists(fn), True)
        self.corpus.removeMessage(self.msg)
        self.assertEqual(os.path.exists(fn), False)


class ExpiryFileCorpusTest(FileCorpusTest):
    def setUp(self):
        _FileCorpusBaseTest.setUp(self)
        self.cache_size = 100
        self.directory = 'fctesthamcorpus'
        self.factory = FileMessageFactory()
        self.stuff_corpus()
        self.corpus = ExpiryFileCorpus(1.0, self.factory, self.directory,
                                       '?', self.cache_size)


def suite():
    suite = unittest.TestSuite()
    clses = (FileMessageFactoryTest,
             GzipFileMessageFactoryTest,
             FileMessageTest,
             GzipFileMessageTest,
             FileCorpusTest,
             ExpiryFileCorpusTest,
             )
    for cls in clses:
        suite.addTest(unittest.makeSuite(cls))
    return suite


if __name__=='__main__':
    sb_test_support.unittest_main(argv=sys.argv + ['suite'])
