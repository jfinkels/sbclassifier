# message.py - classes that represent email messages
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
"""message.py - Core Spambayes classes.

Classes:
    Message - an email.Message.Message, extended with spambayes methods
    SBHeaderMessage - A Message with spambayes header manipulations
    MessageInfoDB - persistent state storage for Message, using dbm
    MessageInfoZODB - persistent state storage for Message, using ZODB
    MessageInfoPickle - persistent state storage for Message, using pickle

Abstract:

    MessageInfoDB is a simple shelve persistency class for the persistent
    state of a Message obect.  The MessageInfoDB currently does not provide
    iterators, but should at some point.  This would allow us to, for
    example, see how many messages have been trained differently than their
    classification, for fp/fn assessment purposes.

    Message is an extension of the email package Message class, to
    include persistent message information. The persistent state
    currently consists of the message id, its current classification, and
    its current training.  The payload is not persisted.

    SBHeaderMessage extends Message to include spambayes header specific
    manipulations.

Usage:
    A typical classification usage pattern would be something like:

    >>> import email
    >>> # substance comes from somewhere else
    >>> msg = email.message_from_string(substance, _class=SBHeaderMessage)
    >>> id = msg.setIdFromPayload()

    >>> if id is None:
    >>>     msg.setId(time())   # or some unique identifier

    >>> msg.delSBHeaders()      # never include sb headers in a classification

    >>> # bayes object is your responsibility
    >>> (prob, clues) = bayes.spamprob(msg.asTokens(), evidence=True)

    >>> msg.addSBHeaders(prob, clues)


    A typical usage pattern to train as spam would be something like:

    >>> import email
    >>> # substance comes from somewhere else
    >>> msg = email.message_from_string(substance, _class=SBHeaderMessage)
    >>> id = msg.setId(msgid)     # id is a fname, outlook msg id, something...

    >>> msg.delSBHeaders()        # never include sb headers in a train

    >>> if msg.getTraining() == False:   # could be None, can't do boolean test
    >>>     bayes.unlearn(msg.asTokens(), False)  # untrain the ham

    >>> bayes.learn(msg.asTokens(), True) # train as spam
    >>> msg.rememberTraining(True)


To Do:
    o Suggestions?
"""

__author__ = "Tim Stone <tim@fourstonesExpressions.com>"
__credits__ = "Mark Hammond, Tony Meyer, all the spambayes contributors."

import email
from email.generator import Generator
from email.header import Header
from email.message import Message as _Message
from enum import Enum
from io import StringIO
import math
import re
import traceback
# import warnings

from sbclassifier.classifiers.constants import HAM_CUTOFF
from sbclassifier.classifiers.constants import SPAM_CUTOFF
# from sbclassifier.tokenizer import tokenize

# Spambayes classifies each message by inserting a new header into
# the message.  This header can then be used by your email client
# (provided your client supports filtering) to move spam into a
# separate folder (recommended), delete it (not recommended), etc.
# This option specifies the name of the header that Spambayes inserts.
# The default value should work just fine, but you may change it to
# anything that you wish.
CLASSIFICATION_HEADER_NAME = 'X-Spambayes-Classification'

# The header that Spambayes inserts into each email has a name,
# (Classification header name, above), and a value.  If the classifier
# determines that this email is probably spam, it places a header named
# as above with a value as specified by this string.  The default
# value should work just fine, but you may change it to anything
# that you wish.
#HEADER_SPAM_STRING = 'spam'

#: As for Spam Designation, but for emails classified as Ham.
#HEADER_HAM_STRING = 'ham'

# As for Spam/Ham Designation, but for emails which the
# classifer wasn't sure about (ie. the spam probability fell between
# the Ham and Spam Cutoffs).  Emails that have this classification
# should always be the subject of training.
#HEADER_UNSURE_STRING = 'unsure'

# Probability (score) header name
SCORE_HEADER_NAME = 'X-Spambayes-Spam-Probability'

# Level header name
THERMOSTAT_HEADER_NAME = 'X-Spambayes-Level'

# Evidence header name
EVIDENCE_HEADER_NAME = 'X-Spambayes-Evidence'

# Spambayes id header name
MAILID_HEADER_NAME = 'X-Spambayes-MailId'

# sb_mboxtrain.py and sb_filter.py can add a header that details
# how a message was trained, which lets you keep track of it, and
# appropriately re-train messages.  However, if you would rather
# mboxtrain/sb_filter didn't rewrite the message files, you can disable
# this option.
INCLUDE_TRAINED = True

#: When training on a message, the name of the header to add with how it was
#: trained
TRAINED_HEADER_NAME = 'X-Spambayes-Trained'

STATS_START_KEY = "Statistics start date"
STATS_STORAGE_KEY = "Persistent statistics"


CRLF_RE = re.compile(r'\r\n|\r|\n')


Classification = Enum('Classification', 'spam ham unsure')


def from_bytes(b, message_id=None):
    message = email.message_from_bytes(b, _class=Message)
    if message_id is not None:
        message.set_id(message_id)
    return message

def from_string(s, message_id=None):
    message = email.message_from_string(s, _class=Message)
    if message_id is not None:
        message.set_id(message_id)
    return message


def force_crlf(data):
    """Make sure data uses CRLF for line termination."""
    return CRLF_RE.sub('\r\n', data)


class Message(_Message):
    '''An email.Message.Message extended for SpamBayes'''

    def __init__(self, message_id=None):
        super().__init__()

        # persistent state
        # (non-persistent state includes all of email.Message.Message state)
        #self.stored_attributes = ['c', 't', 'date_modified', ]
        #self.getDBKey = self.getId
        self.messageid = None
        self.c = None
        self.t = None
        #self.date_modified = None

        if message_id is not None:
            self.set_id(message_id)

    # # This whole message info database thing is a real mess.  It really
    # # ought to be a property of the Message class, not each instance.
    # # So we want to access it via classmethods.  However, we have treated
    # # it as a regular attribute, so need to make it a property.  To make
    # # a classmethod property, we have to jump through some hoops, which we
    # # deserve for not doing it right in the first place.
    # _message_info_db = None

    # @classmethod
    # def _get_class_message_info_db(klass):
    #     # If, the first time we access the attribute, it hasn't been
    #     # set, then we load up the default one.
    #     if klass._message_info_db is None:
    #         # TODO Before, there was some crazy selection of different database
    #         # types; for now we just use the one backed by DBM.
    #         klass._message_info_db = MessageInfoDB(PERSISTENT_STORAGE_FILE)
    #     return klass._message_info_db

    # @classmethod
    # def _set_class_message_info_db(klass, value):
    #     klass._message_info_db = value

    # @property
    # def message_info_db(self):
    #     return self._get_class_message_info_db()

    # @message_info_db.setter
    # def _set_message_info_db(self, value):
    #     self._set_class_message_info_db(value)

    # This function (and it's hackishness) can be avoided by using
    # email.message_from_string(text, _class=SBHeaderMessage)
    # i.e. instead of doing this:
    #   >>> msg = spambayes.message.SBHeaderMessage()
    #   >>> msg.setPayload(substance)
    # you do this:
    #   >>> msg = email.message_from_string(substance, _class=SBHeaderMessage)
    # imapfilter has an example of this in action
    # def setPayload(self, payload):
    #     """DEPRECATED.

    #     This function does not work (as a result of using private
    #     methods in a hackish way) in Python 2.4, so is now deprecated.
    #     Use *_from_string as described above.

    #     More: Python 2.4 has a new email package, and the private functions
    #     are gone.  So this won't even work.  We have to do something to
    #     get this to work, for the 1.0.x branch, so use a different ugly
    #     hack.
    #     """
    #     warnings.warn("setPayload is deprecated. Use "
    #                   "email.message_from_string(payload, _class="
    #                   "Message) instead.",
    #                   DeprecationWarning, 2)
    #     new_me = email.message_from_string(payload, _class=Message)
    #     self.__dict__.update(new_me.__dict__)

    def set_id(self, new_id):
        if self.messageid and self.messageid != new_id:
            raise ValueError('message ID has already been set, cannot be'
                             ' changed: {!r} to {!r}'.format(self.messageid, new_id))
        if new_id is None:
            raise ValueError('message ID must not be None')
        if not isinstance(new_id, str):
            raise TypeError('message ID must be a string')
        if new_id in (STATS_START_KEY, STATS_STORAGE_KEY):
            raise ValueError('message ID must not be {}'.format(new_id))
        self.messageid = new_id
        #self.message_info_db.load_msg(self)

    def id(self):
        return self.messageid

    # def getId(self):
    #     return self.messageid

    # def tokenize(self):
    #     return tokenize(self)

    def as_string(self, unixfrom=False, mangle_from_=True):
        # The email package stores line endings in the "internal" Python
        # format ('\n').  It is up to whoever transmits that information to
        # convert to appropriate line endings (according to RFC822, that is
        # \r\n *only*).  imaplib *should* take care of this for us (in the
        # append function), but does not, so we do it here
        try:
            fp = StringIO()
            g = Generator(fp, mangle_from_=mangle_from_)
            g.flatten(self, unixfrom)
            return force_crlf(fp.getvalue())
        except TypeError:
            parts = []
            for part in self.get_payload():
                parts.append(part.as_string(unixfrom))
            return force_crlf("\n".join(parts))

    # def modified(self):
    #     if self.messageid:    # only persist if key is present
    #         self.message_info_db.store_msg(self)

    def classification(self):
        return self.c  # .name

    def set_classification(self, classification_or_probability):
        if isinstance(classification_or_probability, Classification):
            self.c = classification_or_probability
            return self.c
        if isinstance(classification_or_probability, float):
            # For the sake of brevity, rename the variable.
            prob = classification_or_probability
            if prob < HAM_CUTOFF:
                self.c = Classification.ham
            elif prob > SPAM_CUTOFF:
                self.c = Classification.spam
            else:
                self.c = Classification.unsure
            return self.c
        raise ValueError('argument must be Classification enum value or'
                         ' probability as a float in [0, 1].')

    def remember_trained(self, is_spam):
        # isSpam == None means no training has been done
        self.t = is_spam
        #self.modified()

    def is_trained(self):
        return self.t

    def __repr__(self):
        return "Message{!r}".format(self.__getstate__())

    def __getstate__(self):
        return (self.messageid, self.c, self.t)

    def __setstate__(self, t):
        (self.messageid, self.c, self.t) = t

    # def setPayload(self, payload):
    #     """DEPRECATED.
    #     """
    #     warnings.warn("setPayload is deprecated. Use "
    #                   "email.message_from_string(payload, _class="
    #                   "SBHeaderMessage) instead.",
    #                   DeprecationWarning, 2)
    #     new_me = email.message_from_string(payload, _class=SBHeaderMessage)
    #     self.__dict__.update(new_me.__dict__)

    def set_id_from_payload(self):
        try:
            self.set_id(self[MAILID_HEADER_NAME])
        except ValueError:
            return None
        return self.messageid

    def add_sb_headers(self, prob, clues, include_thermostat=False,
                       include_score=False, header_score_digits=2,
                       header_score_logarithm=False, include_evidence=False,
                       clue_mailheader_cutoff=0.5, add_unique_id=True,
                       notate_to=None, notate_subject=None):
        """Add hammie header, and remember message's classification.  Also,
        add optional headers if needed.

        `include_score`: You can have Spambayes insert a header with the
        calculated spam probability into each mail.  If you can view headers
        with your mailer, then you can see this information, which can be
        interesting and even instructive if you're a serious SpamBayes junkie.

        `include_thermostat`: You can have spambayes insert a header with the
        calculated spam probability, expressed as a number of '*'s, into each
        mail (the more '*'s, the higher the probability it is spam). If your
        mailer supports it, you can use this information to fine tune your
        classification of ham/spam, ignoring the classification given.

        `include_evidence`: You can have spambayes insert a header into mail,
        with the evidence that it used to classify that message (a collection
        of words with ham and spam probabilities).  If you can view headers
        with your mailer, then this may give you some insight as to why a
        particular message was scored in a particular way.

        `add_unique_id`: If you wish to be able to find a specific message (via
        the 'find' box on the home page), or use the SMTP proxy to train using
        cached messages, you will need to know the unique id of each message.
        This option adds this information to a header added to each message.

        `header_score_digits`: Accuracy of the score in the header in decimal
        digits.

        `header_score_logarithm` Set this option to augment scores of 1.00 or
        0.00 by a logarithmic "one-ness" or "zero-ness" score (basically it
        shows the "number of zeros" or "number of nines" next to the score
        value).

        `clue_mailheader_cutoff`: The range of clues that are added to the
        "debug" header in the E-mail. All clues that have their probability
        smaller than this number, or larger than one minus this number are
        added to the header such that you can see why spambayes thinks this is
        ham/spam or why it is unsure.  The default is to show all clues, but
        you can reduce that by setting showclue to a lower value, such as 0.1

        `notate_to`: Some email clients (Outlook Express, for example) can only
        set up filtering rules on a limited set of headers.  These clients
        cannot test for the existence/value of an arbitrary header and filter
        mail based on that information.  To accommodate these kind of mail
        clients, you can add "spam", "ham", or "unsure" to the recipient list.
        A filter rule can then use this to see if one of these words (followed
        by a comma) is in the recipient list, and route the mail to an
        appropriate folder, or take whatever other action is supported and
        appropriate for the mail classification.

        As it interferes with replying, you may only wish to do this for spam
        messages; simply tick the boxes of the classifications take should be
        identified in this fashion.

        `notate_subject`: This option will add the same information as 'Notate
        To', but to the start of the mail subject line.

        """
        self.set_classification(prob)
        self[CLASSIFICATION_HEADER_NAME] = self.c.name

        if include_score:
            disp = "%.*f" % (header_score_digits, prob)
            if header_score_logarithm:
                if prob <= 0.005 and prob > 0.0:
                    x = -math.log10(prob)
                    disp += " (%d)" % x
                if prob >= 0.995 and prob < 1.0:
                    x = -math.log10(1.0-prob)
                    disp += " (%d)" % x
            self[SCORE_HEADER_NAME] = disp

        if include_thermostat:
            self[THERMOSTAT_HEADER_NAME] = '*' * int(prob * 10)

        if include_evidence:
            hco = clue_mailheader_cutoff
            sco = 1 - hco
            evd = []
            for word, score in clues:
                if word in (b'*H*', b'*S*') or score <= hco or score >= sco:
                    if isinstance(word, str):
                        word = Header(word, charset='utf-8').encode()
                    try:
                        evd.append("%r: %.2f" % (word, score))
                    except TypeError:
                        evd.append("%r: %s" % (word, score))

            # Line-wrap this header, because it can get very long.  We don't
            # use email.Header.Header because that can explode with unencoded
            # non-ASCII characters.  We can't use textwrap because that's 2.3.
            wrappedEvd = []
            headerName = EVIDENCE_HEADER_NAME
            lineLength = len(headerName) + len(': ')
            for component, index in zip(evd, list(range(len(evd)))):
                wrappedEvd.append(component)
                lineLength += len(component)
                if index < len(evd)-1:
                    if lineLength + len('; ') + len(evd[index+1]) < 78:
                        wrappedEvd.append('; ')
                    else:
                        wrappedEvd.append(';\n\t')
                        lineLength = 8
            self[headerName] = "".join(wrappedEvd)

        if add_unique_id:
            self[MAILID_HEADER_NAME] = self.messageid

        self.add_notations(notate_to or (), notate_subject or ())

    def add_notations(self, notate_to, notate_subject):
        """Add the appropriate string to the subject: and/or to: header.

        This is a reasonably ugly method of including the classification, but
        no-one has a better idea about how to allow filtering in 'stripped
        down' mailers (i.e. Outlook Express), so, for the moment, this is it.

        """
        # options["Headers", "notate_to"] (and notate_subject) can be
        # either a single string (like "spam") or a tuple (like
        # ("unsure", "spam")).  In Python 2.3 checking for a string in
        # something that could be a string or a tuple works fine, but
        # it dies in Python 2.2, because you can't do 'string in string',
        # only 'character in string', so we allow for that.
        # if isinstance(notate_to, str):
        #     notate_to = (notate_to,)
        if self.c in notate_to:
            # Once, we treated the To: header just like the Subject: one,
            # but that doesn't really make sense - and OE stripped the
            # comma that we added, treating it as a separator, so it
            # wasn't much use anyway.  So we now convert the classification
            # to an invalid address, and add that.
            address = "{}@spambayes.invalid".format(self.c.name)
            try:
                self.replace_header("To", "{},{}".format(address, self["To"]))
            except KeyError:
                self["To"] = address

        # if isinstance(notate_subject, str):
        #     notate_subject = (notate_subject,)
        if self.c in notate_subject:
            try:
                self.replace_header("Subject", "%s,%s" % (self.c.name,
                                                          self["Subject"]))
            except KeyError:
                self["Subject"] = self.c.name

    def remove_notations(self, remove_subject_notations=False,
                         remove_to_notations=False):
        """If present, remove our notation from the subject: and/or to: header
        of the message.

        This is somewhat problematic, as we cannot be 100% positive that we
        added the notation.  It's almost certain to be us with the to: header,
        but someone else might have played with the subject: header.  However,
        as long as the user doesn't turn this option on and off, this will all
        work nicely.

        See also [ 848365 ] Remove subject annotations from message review
                            page
        """
        subject = self["Subject"]
        if subject:
            ham = Classification.ham.name + ','
            spam = Classification.spam.name + ','
            unsure = Classification.unsure.name + ','
            if remove_subject_notations:
                for disp in (ham, spam, unsure):
                    if subject.startswith(disp):
                        self.replace_header("Subject", subject[len(disp):])
                        # Only remove one, maximum.
                        break
        to = self["To"]
        if to:
            ham = "%s@spambayes.invalid," % (Classification.ham.name,)
            spam = "%s@spambayes.invalid," % (Classification.spam.name,)
            unsure = "%s@spambayes.invalid," % (Classification.unsure.name,)
            if remove_to_notations:
                for disp in (ham, spam, unsure):
                    if to.startswith(disp):
                        self.replace_header("To", to[len(disp):])
                        # Only remove one, maximum.
                        break

    def current_sb_headers(self):
        """Return a dictionary containing the current values of the SpamBayes
        headers.

        This can be used to restore the values after using the
        :func:`remove_sb_headers` function."""
        headers = {}
        for header_name in [CLASSIFICATION_HEADER_NAME,
                            MAILID_HEADER_NAME,
                            CLASSIFICATION_HEADER_NAME + "-ID",
                            THERMOSTAT_HEADER_NAME,
                            EVIDENCE_HEADER_NAME,
                            SCORE_HEADER_NAME,
                            TRAINED_HEADER_NAME]:
            value = self[header_name]
            if value is not None:
                headers[header_name] = value
        return headers

    def remove_sb_headers(self, remove_to_notations=True,
                          remove_subject_notations=True):
        for name in [CLASSIFICATION_HEADER_NAME, MAILID_HEADER_NAME,
                     CLASSIFICATION_HEADER_NAME + "-ID",
                     THERMOSTAT_HEADER_NAME, EVIDENCE_HEADER_NAME,
                     SCORE_HEADER_NAME, TRAINED_HEADER_NAME]:
            del self[name]
        # Also delete notations - typically this is called just before
        # training, and we don't want them there for that.
        self.remove_notations(remove_to_notations, remove_subject_notations)


# Utility function to insert an exception header into the given RFC822 text.
# This is used by both sb_server and sb_imapfilter, so it's handy to have
# it available separately.
def insert_exception_header(string_msg, msg_id=None):
    """Insert an exception header into the given RFC822 message (as text).

    Returns a tuple of the new message text and the exception details.

    """
    stream = StringIO()
    traceback.print_exc(file=stream)
    details = stream.getvalue()

    # Build the header.  This will strip leading whitespace from
    # the lines, so we add a leading space to maintain indentation.
    detailLines = details.strip().split('\n')
    spacedDetails = '\n '.join(detailLines)
    headerName = 'X-Spambayes-Exception'
    header = Header(spacedDetails, header_name=headerName)

    # Insert the exception header, and optionally also insert the id header,
    # otherwise we might keep doing this message over and over again.
    # We also ensure that the line endings are /r/n as RFC822 requires.
    try:
        headers, body = re.split(r'\n\r?\n', string_msg, 1)
    except ValueError:
        # No body - this is a bad message!
        headers = string_msg
        body = ""
    header = re.sub(r'\r?\n', '\r\n', str(header))
    headers += "\n%s: %s\r\n" % (headerName, header)
    if msg_id:
        headers += "%s: %s\r\n" % \
                   (MAILID_HEADER_NAME, msg_id)
    return (headers + '\r\n' + body, details)
