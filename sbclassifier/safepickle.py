import logging
import os
import pickle

import lockfile


def pickle_read(filename):
    """Read pickle file contents with a lock."""
    lock = lockfile.FileLock(filename)
    lock.acquire(timeout=20)
    try:
        return pickle.load(open(filename, 'rb'))
    finally:
        lock.release()


def pickle_write(filename, value, protocol=0):
    '''Store value as a pickle without creating corruption'''

    lock = lockfile.FileLock(filename)
    lock.acquire(timeout=20)

    try:
        # Be as defensive as possible.  Always keep a safe copy.
        tmp = filename + '.tmp'
        fp = None
        try:
            fp = open(tmp, 'wb')
            pickle.dump(value, fp, protocol)
            fp.close()
        except IOError as e:
            logging.warning('Failed update: %s', e)
            if fp is not None:
                os.remove(tmp)
            raise
        try:
            # With *nix we can just rename, and (as long as permissions
            # are correct) the old file will vanish.  With win32, this
            # won't work - the Python help says that there may not be
            # a way to do an atomic replace, so we rename the old one,
            # put the new one there, and then delete the old one.  If
            # something goes wrong, there is at least a copy of the old
            # one.
            os.rename(tmp, filename)
        except OSError:
            os.rename(filename, filename + '.bak')
            os.rename(tmp, filename)
            os.remove(filename + '.bak')
    finally:
        lock.release()
