# storage.py - Bayesian classifiers backed by various databases
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
'''storage.py - Spambayes database management framework.

Classes:
    PickledClassifier - Classifier that uses a pickle db
    DBDictClassifier - Classifier that uses a shelve db
    PGClassifier - Classifier that uses postgres
    mySQLClassifier - Classifier that uses mySQL
    CBDClassifier - Classifier that uses CDB
    ZODBClassifier - Classifier that uses ZODB
    ZEOClassifier - Classifier that uses ZEO
    Trainer - Classifier training observer
    SpamTrainer - Trainer for spam
    HamTrainer - Trainer for ham

Abstract:
    *Classifier are subclasses of Classifier (classifier.Classifier)
    that add automatic state store/restore function to the Classifier class.
    All SQL based classifiers are subclasses of SQLClassifier, which is a
    subclass of Classifier.

    PickledClassifier is a Classifier class that uses a cPickle
    datastore.  This database is relatively small, but slower than other
    databases.

    DBDictClassifier is a Classifier class that uses a database
    store.

To Do:
    o Suggestions?

    '''

# Note to authors - please direct all prints to sys.stderr.  In some situations
# prints to sys.stdout will garble the message (e.g., in hammiefilter).

__author__ = ("Neale Pickett <neale@woozle.org>,"
              "Tim Stone <tim@fourstonesExpressions.com>")
__credits__ = "All the spambayes contributors."

# import dbm.gnu
import logging
import os
# import time
# import tempfile
# import errno
import shelve
from sbclassifier.classifiers.basic import Classifier
from sbclassifier.classifiers.basic import PICKLE_VERSION
from sbclassifier.classifiers.basic import WordInfo
# from sbclassifier import cdb
from sbclassifier.safepickle import pickle_read
from sbclassifier.safepickle import pickle_write

try:
    from cdb import cdb_read
    from cdb import cdb_write
    cdb_is_available = True
except ImportError:
    cdb_is_available = False


# A little magic.  We'd like to use ZODB as the default storage,
# because we've had so many problems with bsddb, and we'd like to swap
# to new ZODB problems <wink>.  However, apart from this, we only need
# a standard Python install - if the default was ZODB then we would
# need ZODB to be installed as well (which it will br for binary users,
# but might not be for source users).  So what we do is check whether
# ZODB is importable and if it is, default to that, and if not, default
# to dbm.  If ZODB is sometimes importable and sometimes not (e.g. you
# muck around with the PYTHONPATH), then this may not work well - the
# best idea would be to explicitly put the type in your configuration
# file.
try:
    import ZODB
except ImportError:
    DB_TYPE = ("dbm", "hammie.db", "spambayes.messageinfo.db")
else:
    del ZODB
    DB_TYPE = ("zodb", "hammie.fs", "messageinfo.fs")

#: SpamBayes can use either a ZODB or dbm database (quick to score one message)
#: or a pickle (quick to train on huge amounts of messages).  There is also
#: (experimental) ability to use a mySQL or PostgresSQL database.
#:
#: Must be one of "zeo", "zodb", "cdb", "mysql", "pgsql", "dbm", or "pickle".
PERSISTENT_USE_DATABASE = DB_TYPE[0]

#: Spambayes builds a database of information that it gathers from incoming
#: emails and from you, the user, to get better and better at classifying your
#: email.  This option specifies the name of the database file.  If you don't
#: give a full pathname, the name will be taken to be relative to the location
#: of the most recent configuration file loaded.
PERSISTENT_STORAGE_FILE = DB_TYPE[1]

# Values for our changed words map
WORD_DELETED = "D"
WORD_CHANGED = "C"

STATE_KEY = 'saved state'

# # Make shelve use binary pickles by default.
# oldShelvePickler = shelve.Pickler


# def binaryDefaultPickler(f, binary=1):
#     return oldShelvePickler(f, binary)
# shelve.Pickler = binaryDefaultPickler

# PICKLE_TYPE = 1

class StoredClassifierBase(Classifier):

    def load(self):
        pass

    def store(self):
        pass

    def close(self):
        pass


class PickleClassifier(StoredClassifierBase):
    """Classifier object persisted in a pickle.

    `filename` is the location of the pickle file. Call to :meth:`load` and
    :meth:`store` will read and write to this location.

    """

    def __init__(self, filename):
        super().__init__()
        self.filename = filename
        self.load()

    def load(self):
        """Load this instance from the pickle."""
        # This is a bit strange, because the loading process creates a
        # temporary instance of PickledClassifier, from which this object's
        # state is copied.  This is a nuance of the way that pickle does its
        # job.
        #
        # Tim sez:  that's because this is an unusual way to use pickle.
        # Note that nothing non-trivial is actually copied, though:
        # assignment merely copies a pointer.  The actual wordinfo etc
        # objects are shared between tempbayes and self, and the tiny
        # tempbayes object is reclaimed when load() returns.
        logging.debug('Loading state from %s pickle', self.filename)

        try:
            tempbayes = pickle_read(self.filename)
        except:
            # new pickle
            logging.debug('%s is a new pickle', self.filename)
            self.wordinfo = {}
            self.nham = 0
            self.nspam = 0
            return

        # Copy state from tempbayes.  The use of our base-class __setstate__ is
        # forced, in case self is of a subclass of PickledClassifier that
        # overrides __setstate__.
        super().__setstate__(tempbayes.__getstate__())
        logging.debug('%s is an existing pickle, with %d ham and %d spam',
                      self.filename, self.nham, self.nspam)

    def store(self):
        """Pickles this object."""
        logging.debug('Persisting %s as pickle', self.filename)
        pickle_write(self.filename, self)  # , PICKLE_TYPE)


class ShelveClassifier(StoredClassifierBase):
    """Classifier object persisted in a shelved DBM database.

    `filename` is the location of the pickle file. Call to :meth:`load` and
    :meth:`store` will read and write to this location.

    `mode` is the same as the ``flag`` parameter in :func:`shelve.open`.

    """

    def __init__(self, filename, flag='c'):
        super().__init__()
        self.statekey = STATE_KEY
        self.flag = flag
        self.filename = filename
        self.load()

    def close(self):
        self.db.close()
        logging.debug('Closed %s database', self.filename)

    def load(self):
        logging.debug('Loading state from %s database', self.filename)
        # TODO why was this originally written like this?
        #
        #     self.dbm = dbm.open(self.filename, self.flag)
        #     self.db = shelve.Shelf(self.dbm)
        #
        # Does having a shelved DBM afford any benefit over just a shelf?
        self.db = shelve.open(self.filename, self.flag)
        if self.statekey in self.db:
            t = self.db[self.statekey]
            if t[0] != PICKLE_VERSION:
                msg = "Can't unpickle: version {} unknown".format(t[0])
                raise ValueError(msg)
            self.nspam, self.nham = t[1:]
            logging.debug('%s is an existing database with %d spam and %d ham',
                          self.filename, self.nspam, self.nham)
        else:
            # new database
            logging.debug('%s is a new database', self.filename)
            self.nspam = 0
            self.nham = 0
        self.wordinfo = {}
        self.deleted_words = set()
        self.changed_words = set()

    def store(self):
        logging.debug('Persisting %s state in database', self.filename)
        # Iterate over our changed word list.
        #
        # This is *not* thread-safe - another thread changing our changed_words
        # could mess us up a little.  Possibly a little lock while we copy and
        # reset self.changed_words would be appropriate.  For now, just do it
        # the naive way.
        for word in self.changed_words:
            val = self.wordinfo[word]
            self.db[word] = val.__getstate__()
        for word in self.deleted_words:
            if word in self.wordinfo:
                msg = ('Should not have a wordinfo for "{}", flagged for'
                       ' deletion'.format(word))
                raise Exception(msg)
            # Word may be deleted before it was ever written.
            try:
                del self.db[word]
            except KeyError:
                pass

        # Reset the changed and deleted word lists.
        self.deleted_words.clear()
        self.changed_words.clear()
        # Update the global state, then do the actual save.
        self._write_state_key()
        self.db.sync()

    def _write_state_key(self):
        self.db[self.statekey] = (PICKLE_VERSION, self.nspam, self.nham)

    def _post_training(self):
        """This is called after training on a wordstream.  We ensure that the
        database is in a consistent state at this point by writing the state
        key."""
        self._write_state_key()

    def _wordinfoget(self, word):
        # if isinstance(word, unicode):
        #     word = word.encode("utf-8")

        # If the word is not in memory (in the self.wordinfo dictionary), then
        # load it from the database.
        try:
            return self.wordinfo[word]
        except KeyError:
            ret = None
            if word not in self.deleted_words:
                r = self.db.get(word)
                if r:
                    ret = self.WordInfoClass()
                    ret.__setstate__(r)
                    self.wordinfo[word] = ret
            return ret

    def _wordinfoset(self, word, record):
        # Optimization
        # ------------
        #
        # "Singleton" words (i.e. words that only have a single instance)
        # take up more than 1/2 of the database, but are rarely used
        # so we don't put them into the wordinfo cache, but write them
        # directly to the database
        #
        # If the word occurs again, then it will be brought back in and
        # never be a singleton again.
        #
        # This seems to reduce the memory footprint of the DBDictClassifier by
        # as much as 60%!!!  This also has the effect of reducing the time it
        # takes to store the database

        # if isinstance(word, unicode):
        #     word = word.encode("utf-8")
        if record.spamcount + record.hamcount <= 1:
            self.db[word] = record.__getstate__()
            for wordset in self.changed_words, self.deleted_words:
                try:
                    wordset.remove(word)
                except KeyError:
                    # This can happen if, e.g., a new word is trained as ham
                    # twice, then untrained once, all before a store().
                    pass

            try:
                del self.wordinfo[word]
            except KeyError:
                pass

        else:
            self.wordinfo[word] = record
            self.changed_words.add(word)

    def _wordinfodel(self, word):
        # if isinstance(word, unicode):
        #     word = word.encode("utf-8")
        del self.wordinfo[word]
        self.deleted_words.add(word)

    def _wordinfokeys(self):
        wordinfokeys = list(self.db.keys())
        del wordinfokeys[wordinfokeys.index(self.statekey)]
        return wordinfokeys


# TODO this should be replaced with a SQLAlchemy-backed classifier.

# class SQLClassifier(Classifier):

#     def __init__(self, filename):
#         super().__init__()
#         self.statekey = STATE_KEY
#         self.filename = filename
#         self.load()

#     def load(self):
#         '''Load state from the database'''
#         raise NotImplementedError("must be implemented in subclass")

#     def store(self):
#         '''Save state to the database'''
#         self._set_row(self.statekey, self.nspam, self.nham)

#     def cursor(self):
#         '''Return a new db cursor'''
#         raise NotImplementedError("must be implemented in subclass")

#     def fetchall(self, c):
#         '''Return all rows as a dict'''
#         raise NotImplementedError("must be implemented in subclass")

#     def commit(self, c):
#         '''Commit the current transaction - may commit at db or cursor'''
#         raise NotImplementedError("must be implemented in subclass")

#     def create_bayes(self):
#         '''Create a new bayes table'''
#         c = self.cursor()
#         c.execute(self.table_definition)
#         self.commit(c)

#     def _get_row(self, word):
#         '''Return row matching word'''
#         try:
#             c = self.cursor()
#             c.execute("select * from bayes"
#                       "  where word=%s",
#                       (word,))
#         except Exception as e:
#             logging.error("error: (%s, %s)", e, word)
#             raise
#         rows = self.fetchall(c)

#         if rows:
#             return rows[0]
#         else:
#             return {}

#     def _set_row(self, word, nspam, nham):
#         c = self.cursor()
#         if self._has_key(word):
#             c.execute("update bayes"
#                       "  set nspam=%s,nham=%s"
#                       "  where word=%s",
#                       (nspam, nham, word))
#         else:
#             c.execute("insert into bayes"
#                       "  (nspam, nham, word)"
#                       "  values (%s, %s, %s)",
#                       (nspam, nham, word))
#         self.commit(c)

#     def _delete_row(self, word):
#         c = self.cursor()
#         c.execute("delete from bayes"
#                   "  where word=%s",
#                   (word,))
#         self.commit(c)

#     def _has_key(self, key):
#         c = self.cursor()
#         c.execute("select word from bayes"
#                   "  where word=%s",
#                   (key,))
#         return len(self.fetchall(c)) > 0

#     def _wordinfoget(self, word):
#         # if isinstance(word, unicode):
#         #     word = word.encode("utf-8")

#         row = self._get_row(word)
#         if row:
#             item = self.WordInfoClass()
#             item.__setstate__((row["nspam"], row["nham"]))
#             return item
#         else:
#             return self.WordInfoClass()

#     def _wordinfoset(self, word, record):
#         # if isinstance(word, unicode):
#         #     word = word.encode("utf-8")
#         self._set_row(word, record.spamcount, record.hamcount)

#     def _wordinfodel(self, word):
#         # if isinstance(word, unicode):
#         #     word = word.encode("utf-8")
#         self._delete_row(word)

#     def _wordinfokeys(self):
#         c = self.cursor()
#         c.execute("select word from bayes")
#         rows = self.fetchall(c)
#         return [r[0] for r in rows]


# class PGClassifier(SQLClassifier):
#     '''Classifier object persisted in a Postgres database'''
#     def __init__(self, db_name):
#         self.table_definition = ("create table bayes ("
#                                  "  word bytea not null default '',"
#                                  "  nspam integer not null default 0,"
#                                  "  nham integer not null default 0,"
#                                  "  primary key(word)"
#                                  ")")
#         SQLClassifier.__init__(self, db_name)

#     def cursor(self):
#         return self.db.cursor()

#     def fetchall(self, c):
#         return c.dictfetchall()

#     def commit(self, _c):
#         self.db.commit()

#     def load(self):
#         '''Load state from database'''

#         import psycopg

#         logging.debug('Loading state from %s database', self.db_name)

#         self.db = psycopg.connect('dbname=' + self.db_name)

#         c = self.cursor()
#         try:
#             c.execute("select count(*) from bayes")
#         except psycopg.ProgrammingError:
#             self.db.rollback()
#             self.create_bayes()

#         if self._has_key(self.statekey):
#             row = self._get_row(self.statekey)
#             self.nspam = row["nspam"]
#             self.nham = row["nham"]
#             logging.debug('%s is an existing database with %d spam and %d ham',
#                           self.db_name, self.nspam, self.nham)
#         else:
#             # new database
#             logging.debug('%s is a new database', self.db_name)
#             self.nspam = 0
#             self.nham = 0


# class mySQLClassifier(SQLClassifier):
#     '''Classifier object persisted in a mySQL database

#     It is assumed that the database already exists, and that the mySQL
#     server is currently running.'''

#     def __init__(self, data_source_name):
#         self.table_definition = ("create table bayes ("
#                                  "  word varchar(255) not null default '',"
#                                  "  nspam integer not null default 0,"
#                                  "  nham integer not null default 0,"
#                                  "  primary key(word)"
#                                  ");")
#         self.host = "localhost"
#         self.username = "root"
#         self.password = ""
#         db_name = "spambayes"
#         self.charset = None
#         source_info = data_source_name.split()
#         for info in source_info:
#             if info.startswith("host"):
#                 self.host = info[5:]
#             elif info.startswith("user"):
#                 self.username = info[5:]
#             elif info.startswith("pass"):
#                 self.password = info[5:]
#             elif info.startswith("dbname"):
#                 db_name = info[7:]
#             elif info.startswith("charset"):
#                 self.charset = info[8:]
#         SQLClassifier.__init__(self, db_name)

#     def cursor(self):
#         return self.db.cursor()

#     def fetchall(self, c):
#         return c.fetchall()

#     def commit(self, _c):
#         self.db.commit()

#     def load(self):
#         '''Load state from database'''

#         import MySQLdb

#         logging.debug('Loading state from %s database', self.db_name)

#         params = {
#             'host': self.host, 'db': self.db_name,
#             'user': self.username, 'passwd': self.password,
#             'charset': self.charset
#             }
#         self.db = MySQLdb.connect(**params)

#         c = self.cursor()
#         try:
#             c.execute("select count(*) from bayes")
#         except MySQLdb.ProgrammingError:
#             try:
#                 self.db.rollback()
#             except MySQLdb.NotSupportedError:
#                 # Server doesn't support rollback, so just assume that
#                 # we can keep going and create the db.  This should only
#                 # happen once, anyway.
#                 pass
#             self.create_bayes()

#         if self._has_key(self.statekey):
#             row = self._get_row(self.statekey)
#             self.nspam = int(row[1])
#             self.nham = int(row[2])
#             logging.debug('%s is an existing database with %d spam and %d ham',
#                           self.db_name, self.nspam, self.nham)
#         else:
#             # new database
#             logging.debug('%s is a new database', self.db_name)
#             self.nspam = 0
#             self.nham = 0

#     def _wordinfoget(self, word):
#         # if isinstance(word, unicode):
#         #     word = word.encode("utf-8")

#         row = self._get_row(word)
#         if row:
#             item = self.WordInfoClass()
#             item.__setstate__((row[1], row[2]))
#             return item
#         else:
#             return None


class CDBClassifier(StoredClassifierBase):
    """A classifier that uses a CDB database.

    A CDB wordinfo database is quite small and fast but is slow to update.  It
    is appropriate if training is done rarely (for example, monthly or weekly
    using archived ham and spam).

    """

    def __init__(self, filename):
        super().__init__()
        self.filename = filename
        self.statekey = STATE_KEY
        self.load()

    # def _WordInfoFactory(self, counts):
    #     # For whatever reason, WordInfo's cannot be created with
    #     # constructor ham/spam counts, so we do the work here.
    #     # Since we're doing the work, we accept the ham/spam count
    #     # in the form of a comma-delimited string, as that's what
    #     # we get.
    #     ham, spam = counts.split(',')
    #     wi = WordInfo()
    #     wi.hamcount = int(ham)
    #     wi.spamcount = int(spam)
    #     return wi

    # Stolen from sb_dbexpimp.py
    # Heaven only knows what encoding non-ASCII stuff will be in
    # Try a few common western encodings and punt if they all fail
    # def uunquote(self, s):
    #     for encoding in ("utf-8", "cp1252", "iso-8859-1"):
    #         try:
    #             return s.decode(encoding)
    #         except UnicodeDecodeError:
    #             pass
    #     # punt
    #     return s

    def load(self):
        if os.path.exists(self.filename):
            data = cdb.read(self.filename)
            self.nham, self.nspam = [int(i) for i in
                                     data[self.statekey].split(',')]
            # self.wordinfo = {self.uunquote(k): self._WordInfoFactory(v)
            #                  for k, v in data.items()
            #                  if k != self.statekey}
            from_string = lambda s: WordInfo(*(int(n) for n in s.split(',')))
            self.wordinfo = {k: from_string(v) for k, v in data.items()
                             if k != self.statekey}
            logging.debug('%s is an existing CDB, with %d ham and %d spam',
                          self.filename, self.nham, self.nspam)
        else:
            logging.debug('%s is a new CDB', self.filename)
            self.wordinfo = {}
            self.nham = 0
            self.nspam = 0

    def store(self):
        items = [(self.statekey, "{:d},{:d}".format(self.nham, self.nspam))]
        items.extend((word, '{:d},{:d}'.format(info.hamcount, info.spamcount))
                     for word, info in self.wordinfo.items())
        cdb.write(self.filename, items)


# # If ZODB isn't available, then this class won't be useable, but we
# # still need to be able to import this module.  So we pretend that all
# # is ok.
# try:
#     from persistent import Persistent
# except ImportError:
#     try:
#         from ZODB import Persistent
#     except ImportError:
#         Persistent = object


# class _PersistentClassifier(Classifier, Persistent):
#     def __init__(self):
#         # import ZODB
#         from BTrees.OOBTree import OOBTree

#         Classifier.__init__(self)
#         self.wordinfo = OOBTree()


# class ZODBClassifier(object):
#     # Allow subclasses to override classifier class.
#     ClassifierClass = _PersistentClassifier

#     def __init__(self, db_name, mode='c'):
#         self.db_filename = db_name
#         self.db_name = os.path.basename(db_name)
#         self.closed = True
#         self.mode = mode
#         self.load()

#     def __getattr__(self, att):
#         # We pretend that we are a classifier subclass.
#         if hasattr(self, "classifier") and hasattr(self.classifier, att):
#             return getattr(self.classifier, att)
#         raise AttributeError("ZODBClassifier object has no attribute '%s'"
#                              % (att,))

#     def __setattr__(self, att, value):
#         # For some attributes, we change the classifier instead.
#         if att in ("nham", "nspam") and hasattr(self, "classifier"):
#             setattr(self.classifier, att, value)
#         else:
#             object.__setattr__(self, att, value)

#     def create_storage(self):
#         from ZODB.FileStorage import FileStorage
#         try:
#             self.storage = FileStorage(self.db_filename,
#                                        read_only=self.mode == 'r')
#         except IOError:
#             logging.error("Could not create FileStorage from %s",
#                           self.db_filename)
#             raise

#     def load(self):
#         '''Load state from database'''
#         import ZODB

#         logging.debug("Loading state from %s (%s) database",
#                       self.db_filename, self.db_name)

#         # If we are not closed, then we need to close first before we
#         # reload.
#         if not self.closed:
#             self.close()

#         self.create_storage()
#         self.DB = ZODB.DB(self.storage, cache_size=10000)
#         self.conn = self.DB.open()
#         root = self.conn.root()

#         self.classifier = root.get(self.db_name)
#         if self.classifier is None:
#             # There is no classifier, so create one.
#             logging.debug('%s is a new ZODB', self.db_name)
#             self.classifier = root[self.db_name] = self.ClassifierClass()
#         else:
#             logging.debug('%s is an existing ZODB, with %d ham and %d spam',
#                           self.db_name, self.nham, self.nspam)
#         self.closed = False

#     def store(self):
#         '''Place state into persistent store'''
#         try:
#             import ZODB.Transaction
#         except ImportError:
#             import transaction
#             commit = transaction.commit
#             abort = transaction.abort
#         else:
#             commit = ZODB.Transaction.get_transaction().commit
#             abort = ZODB.Transaction.get_transaction().abort
#         from ZODB.POSException import ConflictError
#         try:
#             from ZODB.POSException import TransactionFailedError
#         except:
#             from ZODB.POSException \
#                 import TransactionError as TransactionFailedError
#         from ZODB.POSException import ReadOnlyError

#         assert not self.closed, "Can't store a closed database"

#         logging.debug('Persisting %s state in database', self.db_name)

#         try:
#             commit()
#         except ConflictError:
#             # We'll save it next time, or on close.  It'll be lost if we
#             # hard-crash, but that's unlikely, and not a particularly big
#             # deal.
#             logging.debug("Conflict on commit: %s", self.db_name)
#             abort()
#         except TransactionFailedError:
#             # Saving isn't working.  Try to abort, but chances are that
#             # restarting is needed.
#             logging.error("Storing failed.  Need to restart: %s", self.db_name)
#             abort()
#         except ReadOnlyError:
#             logging.error("Can't store transaction to read-only db.")
#             abort()

#     def close(self, pack=True, retain_backup=True):
#         # Ensure that the db is saved before closing.  Alternatively, we
#         # could abort any waiting transaction.  We need to do *something*
#         # with it, though, or it will be still around after the db is
#         # closed and cause problems.  For now, saving seems to make sense
#         # (and we can always add abort methods if they are ever needed).
#         if self.mode != 'r':
#             self.store()

#         # We don't make any use of the 'undo' capabilities of the
#         # FileStorage at the moment, so might as well pack the database
#         # each time it is closed, to save as much disk space as possible.
#         # Pack it up to where it was 'yesterday'.
#         if pack and self.mode != 'r':
#             self.pack(time.time()-60*60*24, retain_backup)

#         # Do the closing.
#         self.DB.close()
#         self.storage.close()

#         # Ensure that we cannot continue to use this classifier.
#         delattr(self, "classifier")

#         self.closed = True
#         logging.debug('Closed %s database', self.db_name)

#     def pack(self, t, retain_backup=True):
#         """Like FileStorage pack(), but optionally remove the .old
#         backup file that is created.  Often for our purposes we do
#         not care about being able to recover from this.  Also
#         ignore the referencesf parameter, which appears to not do
#         anything."""
#         if hasattr(self.storage, "pack"):
#             self.storage.pack(t, None)
#         if not retain_backup:
#             old_name = self.db_filename + ".old"
#             if os.path.exists(old_name):
#                 os.remove(old_name)


# class ZEOClassifier(ZODBClassifier):
#     def __init__(self, data_source_name):
#         source_info = data_source_name.split()
#         self.host = "localhost"
#         self.port = None
#         db_name = "SpamBayes"
#         self.username = ''
#         self.password = ''
#         self.storage_name = '1'
#         self.wait = None
#         self.wait_timeout = None
#         for info in source_info:
#             if info.startswith("host"):
#                 try:
#                     # ZEO only accepts strings, not unicode.
#                     self.host = str(info[5:])
#                 except UnicodeDecodeError as e:
#                     logging.error("Couldn't set host: %s (%s)", info[5:],
#                                   str(e))
#             elif info.startswith("port"):
#                 self.port = int(info[5:])
#             elif info.startswith("dbname"):
#                 db_name = info[7:]
#             elif info.startswith("user"):
#                 self.username = info[5:]
#             elif info.startswith("pass"):
#                 self.password = info[5:]
#             elif info.startswith("storage_name"):
#                 self.storage_name = info[13:]
#             elif info.startswith("wait_timeout"):
#                 self.wait_timeout = int(info[13:])
#             elif info.startswith("wait"):
#                 self.wait = info[5:] == "True"
#         ZODBClassifier.__init__(self, db_name)

#     def create_storage(self):
#         from ZEO.ClientStorage import ClientStorage
#         if self.port:
#             addr = self.host, self.port
#         else:
#             addr = self.host
#         logging.debug("Connecting to ZEO server %s %s %s", addr,
#                       self.username, self.password)
#         # Use persistent caches, with the cache in the temp directory.
#         # If the temp directory is cleared out, we lose the cache, but
#         # that doesn't really matter, and we should always be able to
#         # write to it.
#         try:
#             self.storage = ClientStorage(addr, name=self.db_name,
#                                          read_only=self.mode == 'r',
#                                          username=self.username,
#                                          client=self.db_name,
#                                          wait=self.wait,
#                                          wait_timeout=self.wait_timeout,
#                                          storage=self.storage_name,
#                                          var=tempfile.gettempdir(),
#                                          password=self.password)
#         except ValueError:
#             # Probably bad cache; remove it and try without the cache.
#             try:
#                 os.remove(os.path.join(tempfile.gettempdir(),
#                                        self.db_name +
#                                        self.storage_name + ".zec"))
#             except OSError:
#                 pass
#             self.storage = ClientStorage(addr, name=self.db_name,
#                                          read_only=self.mode == 'r',
#                                          username=self.username,
#                                          wait=self.wait,
#                                          wait_timeout=self.wait_timeout,
#                                          storage=self.storage_name,
#                                          password=self.password)

#     def is_connected(self):
#         return self.storage.is_connected()

# class NoSuchClassifierError(Exception):
#     def __init__(self, invalid_name):
#         Exception.__init__(self, invalid_name)
#         self.invalid_name = invalid_name

#     def __str__(self):
#         return repr(self.invalid_name)


# class MutuallyExclusiveError(Exception):
#     def __str__(self):
#         return "Only one type of database can be specified"

# # values are classifier class, True if it accepts a mode
# # arg, and True if the argument is a pathname
# _storage_types = {"dbm": (DBDictClassifier, True, True),
#                   "pickle": (PickledClassifier, False, True),
#                   "pgsql": (PGClassifier, False, False),
#                   "mysql": (mySQLClassifier, False, False),
#                   "cdb": (CDBClassifier, False, True),
#                   "zodb": (ZODBClassifier, True, True),
#                   "zeo": (ZEOClassifier, False, False),
#                   }


# def open_storage(data_source_name, db_type="dbm", mode=None):
#     """Return a storage object appropriate to the given parameters.

#     By centralizing this code here, all the applications will behave
#     the same given the same options.
#     """
#     try:
#         klass, supports_mode, unused = _storage_types[db_type]
#     except KeyError:
#         raise NoSuchClassifierError(db_type)
#     try:
#         if supports_mode and mode is not None:
#             return klass(data_source_name, mode)
#         else:
#             return klass(data_source_name)
#     except dbm.error as e:
#         if str(e) == "No dbm modules available!":
#             # We expect this to hit a fair few people, so warn them nicely,
#             # rather than just printing the trackback.
#             logging.critical("\nYou do not have a dbm module available to use."
#                              " You need to either use a pickle (see the FAQ),"
#                              " use Python 2.3 (or above), or install a dbm"
#                              " module such as bsddb (see"
#                              " http://sf.net/projects/pybsddb).")
#             sys.exit()
#         raise

# # The different database types that are available.
# # The key should be the command-line switch that is used to select this
# # type, and the value should be the name of the type (which
# # must be a valid key for the _storage_types dictionary).
# _storage_options = {"-p": "pickle",
#                     "-d": "dbm",
#                     }


# def database_type(opts, default_type=PERSISTENT_USE_DATABASE,
#                   default_name=PERSISTENT_STORAGE_FILE):
#     """Return the name of the database and the type to use.  The output of
#     this function can be used as the db_type parameter for the open_storage
#     function, for example:

#         [standard getopts code]
#         db_name, db_type = database_type(opts)
#         storage = open_storage(db_name, db_type)

#     The selection is made based on the options passed, or, if the
#     appropriate options are not present, the options in the global
#     options object.

#     Currently supports:
#        -p  :  pickle
#        -d  :  dbm
#     """
#     nm, typ = None, None
#     for opt, arg in opts:
#         if opt in _storage_options:
#             if nm is None and typ is None:
#                 nm, typ = arg, _storage_options[opt]
#             else:
#                 raise MutuallyExclusiveError()
#     if nm is None and typ is None:
#         typ = options[default_type]
#         try:
#             unused, unused, is_path = _storage_types[typ]
#         except KeyError:
#             raise NoSuchClassifierError(typ)
#         if is_path:
#             #nm = get_pathname_option(*default_name)
#             nm = default_name
#         else:
#             nm = options[default_name]
#     return nm, typ


# def convert(old_name=None, old_type=None, new_name=None, new_type=None):
#     # The expected need is to convert the existing hammie.db dbm
#     # database to a hammie.fs ZODB database.
#     if old_name is None:
#         old_name = "hammie.db"
#     if old_type is None:
#         old_type = "dbm"
#     if new_name is None or new_type is None:
#         auto_name, auto_type = database_type({})
#         if new_name is None:
#             new_name = auto_name
#         if new_type is None:
#             new_type = auto_type

#     old_bayes = open_storage(old_name, old_type, 'r')
#     new_bayes = open_storage(new_name, new_type)
#     words = old_bayes._wordinfokeys()

#     try:
#         new_bayes.nham = old_bayes.nham
#     except AttributeError:
#         new_bayes.nham = 0
#     try:
#         new_bayes.nspam = old_bayes.nspam
#     except AttributeError:
#         new_bayes.nspam = 0

#     logging.info("Converting %s (%s database) to %s (%s database).", old_name,
#                  old_type, new_name, new_type)
#     logging.info("Database has %s ham, %s spam, and %s words.",
#                  new_bayes.nham, new_bayes.nspam, len(words))

#     for word in words:
#         new_bayes._wordinfoset(word, old_bayes._wordinfoget(word))
#     old_bayes.close()

#     logging.info("Storing database, please be patient...")
#     new_bayes.store()
#     logging.info("Conversion complete.")
#     new_bayes.close()


# def ensureDir(dirname):
#     """Ensure that the given directory exists - in other words, if it
#     does not exist, attempt to create it."""
#     try:
#         os.mkdir(dirname)
#         logging.debug("Creating directory %s", dirname)
#     except OSError as e:
#         if e.errno != errno.EEXIST:
#             raise
