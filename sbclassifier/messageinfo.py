import dbm.gnu
import logging
import os
import pickle
import shelve
import sys
import time

from sbclassifier.safepickle import pickle_read
from sbclassifier.safepickle import pickle_write

from sbclassifier.message import STATS_START_KEY
from sbclassifier.message import STATS_STORAGE_KEY


class MessageInfoBase(object):
    def __init__(self, db_name=None):
        self.db_name = db_name

    def __len__(self):
        return len(list(self.keys()))

    def get_statistics_start_date(self):
        if STATS_START_KEY in self.db:
            return self.db[STATS_START_KEY]
        else:
            return None

    def set_statistics_start_date(self, date):
        self.db[STATS_START_KEY] = date
        self.store()

    def get_persistent_statistics(self):
        if STATS_STORAGE_KEY in self.db:
            return self.db[STATS_STORAGE_KEY]
        else:
            return None

    def set_persistent_statistics(self, stats):
        self.db[STATS_STORAGE_KEY] = stats
        self.store()

    def __getstate__(self):
        return self.db

    def __setstate__(self, state):
        self.db = state

    def load_msg(self, msg):
        if self.db is not None:
            key = msg.getDBKey()
            assert key is not None, "None is not a valid key."
            try:
                try:
                    attributes = self.db[key]
                except pickle.UnpicklingError:
                    # The old-style Outlook message info db didn't use
                    # shelve, so get it straight from the dbm.
                    if hasattr(self, "dbm"):
                        attributes = self.dbm[key]
                    else:
                        raise
            except KeyError:
                # Set to None, as it's not there.
                for att in msg.stored_attributes:
                    # Don't overwrite.
                    if not hasattr(msg, att):
                        setattr(msg, att, None)
            else:
                if not isinstance(attributes, list):
                    # Old-style message info db
                    if isinstance(attributes, tuple):
                        # sb_server/sb_imapfilter, which only handled
                        # storing 'c' and 't'.
                        (msg.c, msg.t) = attributes
                        return
                    elif isinstance(attributes, str):
                        # Outlook plug-in, which only handled storing 't',
                        # and did it as a string.
                        msg.t = {"0": False, "1": True}[attributes]
                        return
                    else:
                        logging.error("Unknown message info type: {}",
                                      attributes)
                        sys.exit(1)
                for att, val in attributes:
                    setattr(msg, att, val)

    def store_msg(self, msg):
        if self.db is not None:
            msg.date_modified = time.time()
            attributes = []
            for att in msg.stored_attributes:
                attributes.append((att, getattr(msg, att)))
            key = msg.getDBKey()
            assert key is not None, "None is not a valid key."
            self.db[key] = attributes
            self.store()

    def remove_msg(self, msg):
        if self.db is not None:
            del self.db[msg.getDBKey()]
            self.store()

    def keys(self):
        return list(self.db.keys())


class MessageInfoPickle(MessageInfoBase):
    def __init__(self, db_name, pickle_type=1):
        MessageInfoBase.__init__(self, db_name)
        self.mode = pickle_type
        self.load()

    def load(self):
        # If the database file doesn't exist or exists but is empty, then
        # create a new pickle. Otherwise, load the existing pickle file.
        db_exists = (os.path.exists(self.db_name)
                     and os.stat(self.db_name).st_size > 0)
        self.db = pickle_read(self.db_name) if db_exists else {}

    def close(self):
        # we keep no resources open - nothing to do
        pass

    def store(self):
        pickle_write(self.db_name, self.db, self.mode)


class MessageInfoDB(MessageInfoBase):
    def __init__(self, db_name, mode='c'):
        MessageInfoBase.__init__(self, db_name)
        self.mode = mode
        self.load()

    def load(self):
        try:
            self.dbm = dbm.gnu.open(self.db_name, self.mode)
            self.db = shelve.Shelf(self.dbm)
        except dbm.gnu.error:
            # This probably means that we don't have a dbm module
            # available.  Print out a warning, and continue on
            # (not persisting any of this data).
            logging.warning("no dbm modules available for MessageInfoDB")
            self.dbm = self.db = None

    def __del__(self):
        self.close()

    def close(self):
        # Close our underlying database.  Better not assume all databases
        # have close functions!
        def noop():
            pass
        getattr(self.db, "close", noop)()
        getattr(self.dbm, "close", noop)()

    def store(self):
        if self.db is not None:
            self.db.sync()

# # If ZODB isn't available, then this class won't be useable, but we
# # still need to be able to import this module.  So we pretend that all
# # is ok.
# try:
#     from persistent import Persistent
# except ImportError:
#     Persistent = object


# class _PersistentMessageInfo(MessageInfoBase, Persistent):
#     def __init__(self):
#         # import ZODB
#         from BTrees.OOBTree import OOBTree

#         MessageInfoBase.__init__(self)
#         self.db = OOBTree()


# class MessageInfoZODB(storage.ZODBClassifier):
#     ClassifierClass = _PersistentMessageInfo

#     def __init__(self, db_name, mode='c'):
#         self.nham = self.nspam = 0  # Only used for debugging prints
#         storage.ZODBClassifier.__init__(self, db_name, mode)
#         self.classifier.store = self.store
#         self.db = self.classifier

#     def __setattr__(self, att, value):
#         # Override ZODBClassifier.__setattr__
#         object.__setattr__(self, att, value)


# # values are classifier class, True if it accepts a mode
# # arg, and True if the argument is a pathname
# _storage_types = {"dbm": (MessageInfoDB, True, True),
#                   "pickle": (MessageInfoPickle, False, True),
#                   # "pgsql": (MessageInfoPG, False, False),
#                   # "mysql": (MessageInfoMySQL, False, False),
#                   # "cdb": (MessageInfoCDB, False, True),
#                   "zodb": (MessageInfoZODB, True, True),
#                   # "zeo": (MessageInfoZEO, False, False),
#                   }


# def open_storage(data_source_name, db_type="dbm", mode=None):
#     """Return a storage object appropriate to the given parameters."""
#     try:
#         klass, supports_mode, unused = _storage_types[db_type]
#     except KeyError:
#         raise storage.NoSuchClassifierError(db_type)
#     if supports_mode and mode is not None:
#         return klass(data_source_name, mode)
#     else:
#         return klass(data_source_name)


# def database_type():
#     dn = ("Storage", "messageinfo_storage_file")
#     # The storage options here may lag behind those in storage.py,
#     # so we try and be more robust.  If we can't use the same storage
#     # method, then we fall back to pickle.
#     nm, typ = storage.database_type((), default_name=dn)
#     if typ not in list(_storage_types.keys()):
#         typ = "pickle"
#     return nm, typ
