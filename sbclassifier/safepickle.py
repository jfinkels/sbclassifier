# safepickle.py - pickle functions with concurrency locks
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
import pickle
import shutil

from lockfile import FileLock
from tempfile import NamedTemporaryFile


#: The number of seconds for which to acquire a file lock. An exception is
#: raised if the file is still locked after this number of seconds.
DEFAULT_TIMEOUT = 20


def pickle_read(filename):
    """Read pickle file contents with a lock."""
    with FileLock(filename, timeout=DEFAULT_TIMEOUT):
        with open(filename, 'rb') as f:
            return pickle.load(f)


def pickle_write(filename, value, protocol=pickle.HIGHEST_PROTOCOL):
    """Store value as a pickle without creating corruption."""
    with FileLock(filename, timeout=DEFAULT_TIMEOUT):
        # Be as defensive as possible: dump the pickle data to a temporary file
        # first, then move the data to the requested filename second.
        with NamedTemporaryFile(delete=False) as fp:
            pickle.dump(value, fp, protocol)
        shutil.move(fp.name, filename)
