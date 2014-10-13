# caches.py - cache class for corpora
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
import logging

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
