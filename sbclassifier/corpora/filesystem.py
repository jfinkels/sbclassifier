# filesystem.py - classes for a corpus of messages stored on the filesystem
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
"""FileCorpus.py - Corpus composed of file system artifacts

Classes:
    FileCorpus - an observable dictionary of FileMessages
    ExpiryFileCorpus - a FileCorpus of young files
    FileMessage - a subject of Spambayes training
    FileMessageFactory - a factory to create FileMessage objects
    GzipFileMessage - A FileMessage zipped for less storage
    GzipFileMessageFactory - factory to create GzipFileMessage objects

Abstract:
    These classes are concrete implementations of the Corpus framework.

    FileCorpus is designed to manage corpora that are directories of
    message files.

    ExpiryFileCorpus is an ExpiryCorpus of file messages.

    FileMessage manages messages that are files in the file system.

    FileMessageFactory is responsible for the creation of FileMessages,
    in response to requests to a corpus for messages.

    GzipFileMessage and GzipFileMessageFactory are used to persist messages
    as zipped files.  This can save a bit of persistent storage, though the
    ability of the compresser to do very much deflation is limited due to the
    relatively small size of the average textual message.  Still, for a large
    corpus, this could amount to a significant space savings.

    See Corpus.__doc__ for more information.

To Do:
    o Suggestions?
"""

from __future__ import generators

__author__ = "Tim Stone <tim@fourstonesExpressions.com>"
__credits__ = "Richie Hindle, Tim Peters, all the spambayes contributors."

import logging

import os
import fnmatch
import time

from sbclassifier.message import from_bytes as message_from_bytes
from sbclassifier.corpora.base import Corpus

VERBOSE = True
DEFAULT_CACHE_SIZE = 2 ** 8


# TODO I think this should just be implemented by creating a FileCache class, a
# subclass of Cache, that simply stores messages on the filesystem.
class FileCorpus(Corpus):

    def __init__(self, directory, filter='*', cache_size=DEFAULT_CACHE_SIZE):
        super().__init__(cache_size)

        self.directory = directory
        self.filter = filter

        # This assumes that the directory exists.  A horrible death occurs
        # otherwise. We *could* simply create it, but that will likely only
        # mask errors.
        #
        # This will not pick up any changes to the corpus that are made through
        # the file system. The key list is established in __init__, and if
        # anybody stores files in the directory, even if they match the filter,
        # they won't make it into the key list.  The same problem exists if
        # anybody removes files. This *could* be a problem.  If so, we can
        # maybe override the keys() method to account for this, but there would
        # be training side-effects...  The short of it is that corpora that are
        # managed by FileCorpus should *only* be managed by FileCorpus (at
        # least for now).  External changes that must be made to the corpus
        # should for the moment be handled by a complete retraining.
        for filename in os.listdir(directory):
            if fnmatch.fnmatch(filename, filter):
                self._load_message(filename)

    # def makeMessage(self, key, content=None):
    #     '''Ask our factory to make a Message'''
    #     msg = self.factory.create(key, self.directory, content)
    #     return msg

    def _message_path(self, message):
        """Returns the path to the specified message, relative to the directory
        specified in the constructor of this class.

        `message` is an instance of :class:`Message`.

        """
        return os.path.join(self.directory, message.id())

    def _message_path_from_id(self, message_id):
        return os.path.join(self.directory, message_id)

    def _load_message(self, filename):
        """Loads a message from the filesystem into the in-memory cache."""
        fullpath = self._message_path_from_id(filename)
        with open(fullpath, 'rb') as f:
            message = message_from_bytes(f.read(), message_id=filename)
        # The key for this file in the cache is the filename.
        self.message_cache.put(filename, message)

    def add_message(self, message, message_id=None, *args, **kw):
        # First, store the message on the filesystem. Then call the
        # add_message() method in the superclass. The message.key() is assumed
        # to be a filename, and the message is stored at that location.
        key = message.id() if message_id is None else message_id
        if not fnmatch.fnmatch(key, self.filter):
            msg = 'Message {} does not match filter {}'.format(key,
                                                               self.filter)
            raise ValueError(msg)
        logging.debug('writing message %s to file', key)
        # TODO this is not safe! the message may have a malicious key (for
        # example, a key containing '../')...
        filename = self._message_path(message)
        with open(filename, 'wb') as f:
            f.write(message.as_bytes())
        # superclass processing *MUST* be done *LAST!*.
        super().add_message(message, key, *args, **kw)

    def remove_message(self, message, *args, **kw):
        """Removes the specified message from the corpus and from the
        filesystem as well.

        """
        key = message.id()
        logging.debug('deleting message file %s', key)
        filename = self._message_path(message)
        try:
            os.remove(filename)
        except OSError as e:
            # The file probably isn't there anymore.  Maybe a virus
            # protection program got there first?
            logging.error('file %s cannot be deleted: %s', filename,
                          e.strerror)
        # superclass processing *MUST* be done
        # perform superclass processing *LAST!*
        super().remove_message(message, *args, **kw)

    def __repr__(self):
        nummsgs = len(self)
        s = 's' if nummsgs != 1 else ''
        lst = ', {}'.format(self.keys()) if VERBOSE and nummsgs > 0 else ''
        return ('<{} object at {:8.8x}, directory: {},'
                ' {} message{}{}>').format(self.__class__.__name__, id(self),
                                           self.directory, nummsgs, s, lst)


class ExpiryFileCorpus(FileCorpus):
    '''FileCorpus of "young" file system artifacts'''

    def __init__(self, expireBefore, *args, **kw):
        self.expireBefore = expireBefore
        # Only check for expiry after this time.
        self.expiry_due = time.time()
        super().__init__(*args, **kw)

    def remove_expired_messages(self):
        # Only check for expired messages after this time.  We set this to the
        # closest-to-expiry message's expiry time, so that this method can be
        # called very regularly, and most of the time it will just immediately
        # return.
        if time.time() < self.expiry_due:
            return

        self.expiry_due = time.time() + self.expireBefore
        # Iterate over a copy of the list because the keys will be modified
        # during the loop.
        for key in list(self.keys()):
            msg = self[key]
            timestamp = msg.createTimestamp()
            end_time = timestamp + self.expireBefore
            if end_time < time.time():
                logging.debug('message %s has expired', msg.id())
                self.remove_message(msg, do_training=False)
            elif end_time < self.expiry_due:
                self.expiry_due = end_time


# class FileMessage(object):
#     '''Message that persists as a file system artifact.'''

#     message_class = Message

#     def __init__(self, file_name=None, directory=None):
#         '''Constructor(message file name, corpus directory name)'''
#         self.file_name = file_name
#         self.directory = directory
#         self.loaded = False
#         self._msg = self.message_class()

#     def __getattr__(self, att):
#         """Pretend we are a subclass of message.SBHeaderMessage."""
#         if hasattr(self, "_msg") and hasattr(self._msg, att):
#             return getattr(self._msg, att)
#         raise AttributeError()

#     def __getitem__(self, k):
#         """Pretend we are a subclass of message.SBHeaderMessage."""
#         if hasattr(self, "_msg"):
#             return self._msg[k]
#         raise TypeError()

#     def __setitem__(self, k, v):
#         """Pretend we are a subclass of message.SBHeaderMessage."""
#         if hasattr(self, "_msg"):
#             self._msg[k] = v
#             return
#         raise TypeError()

#     def as_string(self, unixfrom=False):
#         self.load()  # ensure that the substance is loaded
#         return self._msg.as_string(unixfrom)

#     def load(self):
#         '''Read the Message substance from the file'''
#         # This is a tricky one!  Some people might have a combination
#         # of gzip and non-gzip messages, especially when they first
#         # change to or from gzip.  They should be able to see (but
#         # not create) either type, so a FileMessage load needs to be
#         # able to load gzip messages, even though it is a FileMessage
#         # subclass (GzipFileMessage) that adds the ability to store
#         # messages gzipped.  If someone can think of a classier (pun
#         # intended) way of doing this, be my guest.
#         if self.loaded:
#             return

#         assert self.file_name is not None, \
#             "Must set filename before using FileMessage instances."

#         logging.debug('loading %s', self.file_name)

#         pn = self.pathname()

#         fp = gzip.open(pn, 'rb')
#         try:
#             self._msg = email.message_from_bytes(fp.read(),
#                                                  _class=self.message_class)
#         except IOError as e:
#             if str(e) == 'Not a gzipped file' or \
#                str(e) == 'Unknown compression method':
#                 # We've probably got both gzipped messages and
#                 # non-gzipped messages, and need to work with both.
#                 fp.close()
#                 # TODO this used to open the file in binary mode
#                 #with open(self.pathname(), 'rb') as fp:
#                 with open(self.pathname()) as fp:
#                     self._msg = email.message_from_string(
#                         fp.read(), _class=self.message_class)
#             else:
#                 # Don't shadow other errors.
#                 raise
#         else:
#             fp.close()
#         self.loaded = True

#     def store(self):
#         '''Write the Message substance to the file'''

#         assert self.file_name is not None, \
#             "Must set filename before using FileMessage instances."

#         logging.debug('storing %s', self.file_name)

#         with open(self.pathname(), 'wb') as fp:
#             fp.write(bytes(self.as_string(), 'utf-8'))

#     def remove(self):
#         '''Message hara-kiri'''
#         logging.debug('physically deleting file %s', self.pathname())
#         try:
#             os.unlink(self.pathname())
#         except OSError:
#             # The file probably isn't there anymore.  Maybe a virus
#             # protection program got there first?
#             logging.error('file %s cannot be deleted', self.pathname())

#     def name(self):
#         '''A unique name for the message'''
#         assert self.file_name is not None, \
#             "Must set filename before using FileMessage instances."
#         return self.file_name

#     def key(self):
#         '''The key of this message in the msgs dictionary'''
#         assert self.file_name is not None, \
#             "Must set filename before using FileMessage instances."
#         return self.file_name

#     def __repr__(self):
#         '''Instance as a representative string'''
#         sub = self.as_string()

#         if not VERBOSE:
#             if len(sub) > 20:
#                 if len(sub) > 40:
#                     sub = sub[:20] + '...' + sub[-20:]
#                 else:
#                     sub = sub[:20]

#         return "<%s object at %8.8x, file: %s, %s>" % \
#             (self.__class__.__name__,
#              id(self), self.pathname(), sub)

#     def __str__(self):
#         '''Instance as a printable string'''
#         return self.__repr__()

#     def createTimestamp(self):
#         '''Return the create timestamp for the file'''
#         # make sure we don't die if someone has
#         # removed the file out from underneath us
#         try:
#             stats = os.stat(self.pathname())
#         except OSError:
#             ctime = time.time()
#         else:
#             ctime = stats[stat.ST_CTIME]
#         return ctime


# class MessageFactory:  # (MessageFactory):
#     # Subclass must define a concrete message klass.
#     klass = None

#     def create(self, key, directory, content=None):
#         '''Create a message object from a filename in a directory'''
#         if content:
#             msg = email.message_from_string(content,
#                                             _class=self.klass)
#             msg.file_name = key
#             msg.directory = directory
#             msg.loaded = True
#             return msg
#         return self.klass(key, directory)


# class FileMessageFactory(MessageFactory):
#     '''MessageFactory for FileMessage objects'''
#     klass = FileMessage


# class GzipFileMessage(FileMessage):
#     '''Message that persists as a zipped file system artifact.'''
#     def store(self):
#         '''Write the Message substance to the file'''
#         assert self.file_name is not None, \
#             "Must set filename before using FileMessage instances."

#         logging.debug('storing %s', self.file_name)

#         pn = self.pathname()
#         with gzip.open(pn, 'wb') as gz:
#             gz.write(bytes(self.as_string(), 'utf-8'))
#             gz.flush()


# class GzipFileMessageFactory(MessageFactory):
#     '''MessageFactory for FileMessage objects'''
#     klass = GzipFileMessage
