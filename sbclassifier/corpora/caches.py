# caches.py - cache class for corpora
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
import fnmatch
import logging
import os
import os.path

from sbclassifier.message import from_path

#: Infinity; used to indicate no upper bound on the size of a cache.
INFINITY = float('inf')


class Cache:
    """Interface definition for a cache.

    This class should not be instantiated (as it would be entirely useless).
    Client code should only implement subclasses of this class that implement
    all the required methods.

    """

    def __len__(self):
        raise NotImplemented

    def __iter__(self):
        raise NotImplemented

    def __getitem__(self, key):
        raise NotImplemented

    def keys(self):
        raise NotImplemented

    def values(self):
        raise NotImplemented

    def put(self, key, value):
        raise NotImplemented

    def get(self, key, default=None):
        raise NotImplemented

    def pop(self, key):
        raise NotImplemented


class NaiveCache(Cache):
    """A simple in-memory cache implemented as a dictionary.

    When the number of entries reaches the size limit specified by `max_size`,
    entries are removed in the order in which they were first added. The
    default size limit is infinity, so there is no size limit unless this
    keyword argument is set to a positive integer. `max_size` indicates the
    maximum **number of entries** in the database, not necessarily the maximum
    number of bytes.

    """

    def __init__(self, max_size=INFINITY):
        # The _keys list maintains the order in which (key, value) pairs were
        # added to the cache. Throughout the lifetime of this object,
        # `self._keys` must equal `self.data.keys()`.
        self._keys = []
        self.data = {}
        self.max_size = max_size

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        return iter(self.data)

    def __getitem__(self, key):
        return self.data[key]

    def keys(self):
        return self.data.keys()

    def values(self):
        return self.data.values()

    def put(self, key, value):
        logging.debug('Caching %s', key)
        self.data[key] = value
        # Here is where we manage the in-memory cache size...
        self._keys.append(key)
        # Optimization: only keep the `self.max_size` entries put into the
        # cache most recently.
        if len(self._keys) > self.max_size:
            key_to_flush = self._keys[0]
            self.pop(key_to_flush)

    def get(self, key, default=None):
        return self.data.get(key, default)

    def pop(self, key):
        logging.debug('Flushing %s from cache', key)
        try:
            ki = self._keys.index(key)
        except ValueError:
            pass
        else:
            self._keys.pop(ki)
        # TODO should this set the key to None, or remove it entirely?
        return self.data.pop(key, None)


class FileCache(NaiveCache):
    # This is essentially a two-level cache: one level is the dictionary in
    # memory, and the second level is the files stored on disk.

    def __init__(self, directory, namefilter, *args, **kw):
        super().__init__(*args, **kw)
        self.directory = directory
        # Only allow messages whose IDs match the specified filter.
        self.namefilter = namefilter
        # Maintain a counter of the number of messages currently stored in the
        # directory. Scan the directory for existing message files.
        self.num_files = len(list(iter(self)))

    def _is_message(self, filename):
        return (os.path.isfile(os.path.join(self.directory, filename))
                and fnmatch.fnmatch(filename, self.namefilter))

    def _message_from_path(self, filename, *args, **kw):
        return from_path(os.path.join(self.directory, filename), *args, **kw)

    def __len__(self):
        return self.num_files

    def __iter__(self):
        return self.keys()

    def __getitem__(self, key):
        if key in self.data:
            return self.data[key]
        if key in os.listdir(self.directory) and self._is_message(key):
            return self._message_from_path(key)
        raise KeyError('{} not in cache or directory'.format(key))

    def keys(self):
        return (f for f in os.listdir(self.directory) if self._is_message(f))

    def values(self):
        # Need to recreate each message object from the files.
        return (self._message_from_path(f, message_id=f) for f in self.keys())

    def put(self, key, value):
        if not fnmatch.fnmatch(key, self.namefilter):
            msg = 'Message {} does not match filter {}'.format(key,
                                                               self.namefilter)
            raise ValueError(msg)
        super().put(key, value)
        logging.debug('Storing %s to file', key)
        with open(os.path.join(self.directory, key), 'wb') as f:
            f.write(value.as_bytes())

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def pop(self, key):
        result = super().pop(key)
        logging.debug('Removing file %s', key)
        path = os.path.join(self.directory, key)
        try:
            os.remove(path)
        except OSError:
            logging.error('file %s cannot be deleted', path)
        return result
