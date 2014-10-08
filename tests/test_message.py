# test_message.py - unit tests for the sbclassifier.message module
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
import email
import itertools
import math
import os
import sys
import tempfile
import time
import unittest

from sbclassifier.classifiers import Classifier
from sbclassifier.message import MAILID_HEADER_NAME
from sbclassifier.message import CLASSIFICATION_HEADER_NAME
from sbclassifier.message import EVIDENCE_HEADER_NAME
from sbclassifier.message import SCORE_HEADER_NAME
from sbclassifier.message import TRAINED_HEADER_NAME
from sbclassifier.message import THERMOSTAT_HEADER_NAME
from sbclassifier.message import HEADER_HAM_STRING
from sbclassifier.message import HEADER_SPAM_STRING
from sbclassifier.message import HEADER_UNSURE_STRING
from sbclassifier.message import insert_exception_header
from sbclassifier.message import Message
from sbclassifier.message import MessageInfoDB
from sbclassifier.message import MessageInfoPickle
from sbclassifier.message import SBHeaderMessage
from sbclassifier.tokenizer import tokenize

# We borrow the test messages that test_sb_server uses.
# I doubt it really makes much difference, but if we wanted more than
# one message of each type (the tests should all handle this ok) then
# Richie's hammer.py script has code for generating any number of
# randomly composed email messages.
#
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


def keys_to_bytes(d):
    return {bytes(k, 'utf-8'): v for k, v in d.items()}


def split_evidence(evidence):
    evidence = [s.split(':') for s in
                [s.strip() for s in evidence.split(';')]]
    result = {":".join(clue[:-1])[2:-1]: float(clue[-1]) for clue in evidence}
    return keys_to_bytes(result)


class MessageTest(unittest.TestCase):
    def setUp(self):
        self.msg = email.message_from_string(spam1, _class=Message)

    def test_persistent_state(self):
        self.assertEqual(self.msg.stored_attributes, ['c', 't',
                                                      'date_modified'])

    def test_initialisation(self):
        self.assertEqual(self.msg.id, None)
        self.assertEqual(self.msg.c, None)
        self.assertEqual(self.msg.t, None)

    def test_setId(self):
        # Verify that you can't change the id.
        self.msg.id = "test"
        self.assertRaises(ValueError, self.msg.setId, "test2")

        # Verify that you can't set the id to None.
        self.msg.id = None
        self.assertRaises(ValueError, self.msg.setId, None)

        # Verify that id must be a string.
        self.assertRaises(TypeError, self.msg.setId, 1)
        self.assertRaises(TypeError, self.msg.setId, False)
        self.assertRaises(TypeError, self.msg.setId, [])

        id = "Test"
        self.msg.setId(id)
        self.assertEqual(self.msg.id, id)

        # Check info db load_msg is called.
        self.msg.id = None
        saved = self.msg.message_info_db.load_msg
        self.done = False
        try:
            self.msg.message_info_db.load_msg = self._fake_setState
            self.msg.setId(id)
            self.assertEqual(self.done, True)
        finally:
            self.msg.message_info_db.load_msg = saved

    def test_getId(self):
        self.assertEqual(self.msg.getId(), None)
        id = "test"
        self.msg.id = id
        self.assertEqual(self.msg.getId(), id)

    def test_tokenize(self):
        toks = self.msg.tokenize()
        self.assertEqual(tuple(tokenize(spam1)), tuple(toks))

    def test_force_CRLF(self):
        self.assertTrue('\r' not in good1)
        lines = self.msg._force_CRLF(good1).split('\n')
        for line in lines:
            if line:
                self.assertTrue(line.endswith('\r'))

    def test_as_string_endings(self):
        self.assertTrue('\r' not in spam1)
        lines = self.msg.as_string().split('\n')
        for line in lines:
            if line:
                self.assertTrue(line.endswith('\r'))

    def _fake_setState(self, state):
        self.done = True

    def test_modified(self):
        saved = self.msg.message_info_db.store_msg
        try:
            self.msg.message_info_db.store_msg = self._fake_setState
            self.done = False
            self.msg.modified()
            self.assertEqual(self.done, False)
            self.msg.id = "Test"
            self.msg.modified()
            self.assertEqual(self.done, True)
        finally:
            self.msg.message_info_db.store_msg = saved

    def test_GetClassification(self):
        self.msg.c = 's'
        self.assertEqual(self.msg.GetClassification(), HEADER_SPAM_STRING)
        self.msg.c = 'h'
        self.assertEqual(self.msg.GetClassification(), HEADER_HAM_STRING)
        self.msg.c = 'u'
        self.assertEqual(self.msg.GetClassification(), HEADER_UNSURE_STRING)
        self.msg.c = 'a'
        self.assertEqual(self.msg.GetClassification(), None)

    def test_RememberClassification(self):
        self.msg.RememberClassification(HEADER_SPAM_STRING)
        self.assertEqual(self.msg.c, 's')
        self.msg.RememberClassification(HEADER_HAM_STRING)
        self.assertEqual(self.msg.c, 'h')
        self.msg.RememberClassification(HEADER_UNSURE_STRING)
        self.assertEqual(self.msg.c, 'u')
        self.assertRaises(ValueError, self.msg.RememberClassification, "a")

        # Check that self.msg.modified is called.
        saved = self.msg.modified
        self.done = False
        try:
            self.msg.modified = self._fake_modified
            self.msg.RememberClassification(HEADER_UNSURE_STRING)
            self.assertEqual(self.done, True)
        finally:
            self.msg.modified = saved

    def _fake_modified(self):
        self.done = True

    def test_GetAndRememberTrained(self):
        t = "test"
        saved = self.msg.modified
        self.done = False
        try:
            self.msg.modified = self._fake_modified
            self.msg.RememberTrained(t)
            self.assertEqual(self.done, True)
        finally:
            self.msg.modified = saved
        self.assertEqual(self.msg.GetTrained(), t)


class SBHeaderMessageTest(unittest.TestCase):
    def setUp(self):
        self.msg = email.message_from_string(spam1, _class=SBHeaderMessage)
        # Get a prob and some clues.
        c = Classifier()
        self.u_prob, clues = c.spamprob(tokenize(good1), True)
        c.learn(tokenize(good1), False)
        self.g_prob, clues = c.spamprob(tokenize(good1), True)
        c.unlearn(tokenize(good1), False)
        c.learn(tokenize(spam1), True)
        self.s_prob, self.clues = c.spamprob(tokenize(spam1), True)
        self.ham = HEADER_HAM_STRING
        self.spam = HEADER_SPAM_STRING
        self.unsure = HEADER_UNSURE_STRING
        self.to = "tony.meyer@gmail.com;ta-meyer@ihug.co.nz"
        self.msg["to"] = self.to

    def test_setIdFromPayload(self):
        id = self.msg.setIdFromPayload()
        self.assertEqual(id, None)
        self.assertEqual(self.msg.id, None)
        msgid = "test"
        msg = "".join((MAILID_HEADER_NAME, ": ", msgid, "\r\n", good1))
        msg = email.message_from_string(msg, _class=SBHeaderMessage)
        id = msg.setIdFromPayload()
        self.assertEqual(id, msgid)
        self.assertEqual(msg.id, msgid)

    def test_disposition_header_ham(self):
        name = CLASSIFICATION_HEADER_NAME
        self.msg.addSBHeaders(self.g_prob, self.clues)
        self.assertEqual(self.msg[name], self.ham)
        self.assertEqual(self.msg.GetClassification(), self.ham)

    def test_disposition_header_spam(self):
        name = CLASSIFICATION_HEADER_NAME
        self.msg.addSBHeaders(self.s_prob, self.clues)
        self.assertEqual(self.msg[name], self.spam)
        self.assertEqual(self.msg.GetClassification(), self.spam)

    def test_disposition_header_unsure(self):
        name = CLASSIFICATION_HEADER_NAME
        self.msg.addSBHeaders(self.u_prob, self.clues)
        self.assertEqual(self.msg[name], self.unsure)
        self.assertEqual(self.msg.GetClassification(), self.unsure)

    def test_score_header_off(self):
        self.msg.addSBHeaders(self.g_prob, self.clues)
        self.assertEqual(self.msg[SCORE_HEADER_NAME], None)

    def test_score_header(self):
        self.msg.addSBHeaders(self.g_prob, self.clues, include_score=True,
                              header_score_digits=21)
        self.assertEqual(self.msg[SCORE_HEADER_NAME], "%.21f" % (self.g_prob,))

    def test_score_header_log(self):
        self.msg.addSBHeaders(self.s_prob, self.clues, include_score=True,
                              header_score_digits=21,
                              header_score_logarithm=True)
        self.assertTrue(self.msg[SCORE_HEADER_NAME].
                     startswith("%.21f" % (self.s_prob,)))
        self.assertTrue(self.msg[SCORE_HEADER_NAME].
                     endswith(" (%d)" % (-math.log10(1.0-self.s_prob),)))

    def test_thermostat_header_off(self):
        self.msg.addSBHeaders(self.u_prob, self.clues)
        self.assertEqual(self.msg[THERMOSTAT_HEADER_NAME], None)

    def test_thermostat_header_unsure(self):
        self.msg.addSBHeaders(self.u_prob, self.clues, include_thermostat=True)
        self.assertEqual(self.msg[THERMOSTAT_HEADER_NAME], "*****")

    def test_thermostat_header_spam(self):
        self.msg.addSBHeaders(self.s_prob, self.clues, include_thermostat=True)
        self.assertEqual(self.msg[THERMOSTAT_HEADER_NAME], "*********")

    def test_thermostat_header_ham(self):
        self.msg.addSBHeaders(self.g_prob, self.clues, include_thermostat=True)
        self.assertEqual(self.msg[THERMOSTAT_HEADER_NAME], "")

    def test_evidence_header(self):
        self.msg.addSBHeaders(self.g_prob, self.clues, include_evidence=True)
        header = self.msg[EVIDENCE_HEADER_NAME]
        header_clues = split_evidence(header)
        for word, score in self.clues:
            self.assertTrue(word in header_clues)
            self.assertEqual(round(score, 2), header_clues[word])

    def test_evidence_header_partial(self):
        self.msg.addSBHeaders(self.g_prob, self.clues, include_evidence=True,
                              clue_mailheader_cutoff=0.1)
        header = self.msg[EVIDENCE_HEADER_NAME]
        header_clues = split_evidence(header)
        for word, score in self.clues:
            if score <= 0.1 or score >= 0.9:
                self.assertTrue(word in header_clues)
                self.assertEqual(round(score, 2), header_clues[word])
            else:
                self.assertTrue(word not in header_clues)

    def test_evidence_header_empty(self):
        self.msg.addSBHeaders(self.g_prob, self.clues, include_evidence=True,
                              clue_mailheader_cutoff=0.0)
        header = self.msg[EVIDENCE_HEADER_NAME]
        header_clues = split_evidence(header)
        for word, score in self.clues:
            if word in (b'*H*', b'*S*'):
                self.assertTrue(word in header_clues)
                self.assertEqual(round(score, 2), header_clues[word])
            else:
                self.assertTrue(word not in header_clues)

    def test_evidence_header_off(self):
        self.msg.addSBHeaders(self.g_prob, self.clues)
        self.assertEqual(self.msg[EVIDENCE_HEADER_NAME], None)

    def test_notate_to_off(self):
        self.msg.addSBHeaders(self.g_prob, self.clues)
        self.msg.addSBHeaders(self.u_prob, self.clues)
        self.msg.addSBHeaders(self.s_prob, self.clues)
        self.assertEqual(self.msg["To"], self.to)

    def test_notate_to_ham(self):
        self.msg.addSBHeaders(self.g_prob, self.clues, notate_to=(self.ham, ))
        disp, orig = self.msg["To"].split(',', 1)
        self.assertEqual(orig, self.to)
        self.assertEqual(disp, "%s@spambayes.invalid" % (self.ham,))

    def test_notate_to_unsure(self):
        self.msg.addSBHeaders(self.u_prob, self.clues,
                              notate_to=(self.ham, self.unsure))
        disp, orig = self.msg["To"].split(',', 1)
        self.assertEqual(orig, self.to)
        self.assertEqual(disp, "%s@spambayes.invalid" % (self.unsure,))

    def test_notate_to_spam(self):
        self.msg.addSBHeaders(self.s_prob, self.clues,
                              notate_to=(self.ham, self.spam, self.unsure))
        disp, orig = self.msg["To"].split(',', 1)
        self.assertEqual(orig, self.to)
        self.assertEqual(disp, "%s@spambayes.invalid" % (self.spam,))

    def test_notate_subject_off(self):
        subject = self.msg["Subject"]
        self.msg.addSBHeaders(self.g_prob, self.clues)
        self.msg.addSBHeaders(self.u_prob, self.clues)
        self.msg.addSBHeaders(self.s_prob, self.clues)
        self.assertEqual(self.msg["Subject"], subject)

    def test_notate_subject_ham(self):
        subject = self.msg["Subject"]
        self.msg.addSBHeaders(self.g_prob, self.clues,
                              notate_subject=(self.ham ,))
        disp, orig = self.msg["Subject"].split(',', 1)
        self.assertEqual(orig, subject)
        self.assertEqual(disp, self.ham)

    def test_notate_subject_unsure(self):
        subject = self.msg["Subject"]
        self.msg.addSBHeaders(self.u_prob, self.clues,
                              notate_subject=(self.ham, self.unsure))
        disp, orig = self.msg["Subject"].split(',', 1)
        self.assertEqual(orig, subject)
        self.assertEqual(disp, self.unsure)

    def test_notate_subject_spam(self):
        subject = self.msg["Subject"]
        self.msg.addSBHeaders(self.s_prob, self.clues,
                              notate_subject=(self.ham, self.spam,
                                              self.unsure))
        disp, orig = self.msg["Subject"].split(',', 1)
        self.assertEqual(orig, subject)
        self.assertEqual(disp, self.spam)

    @unittest.skip("don't know how to fix this")
    def test_notate_to_changed(self):
        saved_ham = HEADER_HAM_STRING
        notate_to = NOTATE_TO  # options.get_option("Headers", "notate_to")
        saved_to = notate_to.allowed_values
        try:
            #options["Headers", "header_ham_string"] = "bacon"
            header_strings = (HEADER_HAM_STRING, HEADER_SPAM_STRING,
                              HEADER_UNSURE_STRING)
            notate_to = NOTATE_TO  # options.get_option("Headers", "notate_to")
            notate_to.allowed_values = header_strings
            self.ham = HEADER_HAM_STRING
            result = self.test_notate_to_ham()
            # Just be sure that it's using the new value.
            self.assertEqual(self.msg["To"].split(',', 1)[0],
                             "bacon@spambayes.invalid")
        finally:
            # If we leave these changed, then lots of other tests will
            # fail.
            #options["Headers", "header_ham_string"] = saved_ham
            self.ham = saved_ham
            notate_to.allowed_values = saved_to
        return result

    def test_id_header(self):
        id = "test"
        self.msg.id = id
        self.msg.addSBHeaders(self.g_prob, self.clues)
        self.assertEqual(self.msg[MAILID_HEADER_NAME], id)

    def test_id_header_off(self):
        id = "test"
        self.msg.id = id
        self.msg.addSBHeaders(self.g_prob, self.clues, add_unique_id=False)
        self.assertEqual(self.msg[MAILID_HEADER_NAME], None)

    def test_currentSBHeaders(self):
        sbheaders = self.msg.currentSBHeaders()
        self.assertEqual({}, sbheaders)
        headers = {CLASSIFICATION_HEADER_NAME: '1',
                   MAILID_HEADER_NAME: '2',
                   CLASSIFICATION_HEADER_NAME + "-ID": '3',
                   THERMOSTAT_HEADER_NAME: '4',
                   EVIDENCE_HEADER_NAME: '5',
                   SCORE_HEADER_NAME: '6',
                   TRAINED_HEADER_NAME: '7',
                   }
        for name, val in list(headers.items()):
            self.msg[name] = val
        sbheaders = self.msg.currentSBHeaders()
        self.assertEqual(headers, sbheaders)

    def test_delSBHeaders(self):
        headers = (CLASSIFICATION_HEADER_NAME,
                   MAILID_HEADER_NAME,
                   CLASSIFICATION_HEADER_NAME + "-ID",
                   THERMOSTAT_HEADER_NAME,
                   EVIDENCE_HEADER_NAME,
                   SCORE_HEADER_NAME,
                   TRAINED_HEADER_NAME,)
        for header in headers:
            self.msg[header] = "test"
        for header in headers:
            self.assertTrue(header in list(self.msg.keys()))
        self.msg.delSBHeaders()
        for header in headers:
            self.assertTrue(header not in list(self.msg.keys()))

    def test_delNotations(self):
        # Add each type of notation to each header and check that it
        # is removed.
        headers = ['subject', 'to']
        dispositions = [self.ham, self.spam, self.unsure]
        for headername, disp in itertools.product(headers, dispositions):
            # Add a notation to the header
            header = self.msg[headername]
            self.assertEqual(header.find(disp), -1)
            #options["Headers", "notate_%s" % (headername,)] = \
            #    (self.ham, self.unsure, self.spam)
            prob = {self.ham: self.g_prob, self.spam: self.s_prob,
                    self.unsure: self.u_prob}[disp]
            if headername == 'subject':
                self.msg.addSBHeaders(prob, self.clues,
                                      notate_subject=dispositions)
            else:  # headername == 'to':
                self.msg.addSBHeaders(prob, self.clues,
                                      notate_to=dispositions)
            self.assertNotEqual(self.msg[headername].find(disp), -1)
            # Remove it
            if headername == 'subject':
                self.msg.delNotations(remove_subject_notations=True)
            else:  # headername == 'to':
                self.msg.delNotations(remove_to_notations=True)
            self.assertEqual(self.msg[headername], header)

    def test_delNotations_missing(self):
        # Add each type of notation to each header and check that it
        # is removed.
        headers = ['subject', 'to']
        dispositions = [self.ham, self.spam, self.unsure]
        for headername, disp in itertools.product(headers, dispositions):
            # Add a notation to the header
            header = self.msg[headername]
            self.assertEqual(header.find(disp), -1)
            prob = {self.ham: self.g_prob, self.spam: self.s_prob,
                    self.unsure: self.u_prob}[disp]
            self.msg.addSBHeaders(prob, self.clues)
            self.assertEqual(self.msg[headername].find(disp), -1)
            # Remove it
            self.msg.delNotations()
            self.assertEqual(self.msg[headername], header)

    def test_delNotations_no_header(self):
        # Check that it works if there is no subject/to header.
        del self.msg['subject']
        self.msg.delNotations(remove_subject_notations=True)
        self.assertEqual(self.msg['subject'], None)

        del self.msg['to']
        self.msg.delNotations(remove_to_notations=True)
        self.assertEqual(self.msg['to'], None)

    def test_delNotations_only_once_subject(self):
        self._test_delNotations_only_once("subject")

    def test_delNotations_only_once_to(self):
        self._test_delNotations_only_once("to")

    def _test_delNotations_only_once(self, headername):
        # Check that only one disposition is removed, even if more than
        # one is present.
        dispositions = (self.ham, self.spam, self.unsure)
        for disp in dispositions:
            # Add a notation to the header
            header = self.msg[headername]
            self.assertEqual(header.find(disp), -1)
            prob = {self.ham: self.g_prob, self.spam: self.s_prob,
                    self.unsure: self.u_prob}[disp]
            if headername == 'subject':
                self.msg.addSBHeaders(prob, self.clues,
                                      notate_subject=dispositions)
            else:  # headername == 'to'
                self.msg.addSBHeaders(prob, self.clues, notate_to=dispositions)
            self.assertNotEqual(self.msg[headername].find(disp), -1)
            header2 = self.msg[headername]
            # Add a second notation
            if headername == 'subject':
                self.msg.addSBHeaders(prob, self.clues,
                                      notate_subject=dispositions)
            else:  # headername == 'to'
                self.msg.addSBHeaders(prob, self.clues, notate_to=dispositions)
            self.assertNotEqual(self.msg[headername].
                                replace(disp, "", 1).find(disp), -1)
            # Remove it
            if headername == 'subject':
                self.msg.delNotations(remove_subject_notations=True)
            else:  # headername == 'to'
                self.msg.delNotations(remove_to_notations=True)
            self.assertEqual(self.msg[headername], header2)
            # Restore for next time round the loop
            self.msg.replace_header(headername, header)


@unittest.skip('hey')
class MessageInfoBaseTest(unittest.TestCase):
    def setUp(self):
        self.databasefile = tempfile.NamedTemporaryFile()
        self.db = self.klass(self.databasefile.name, self.mode)

    def test_mode(self):
        self.assertEqual(self.mode, self.db.mode)

    def test_load_msg_missing(self):
        msg = email.message_from_string(good1, _class=Message)
        msg.id = "Test"
        dummy_values = "a", "b"
        msg.c, msg.t = dummy_values
        self.db.load_msg(msg)
        self.assertEqual((msg.c, msg.t), dummy_values)

    def test_load_msg_compat(self):
        msg = email.message_from_string(good1, _class=Message)
        msg.id = "Test"
        dummy_values = "a", "b"
        self.db.db[msg.id] = dummy_values
        self.db.load_msg(msg)
        self.assertEqual((msg.c, msg.t), dummy_values)

    def test_load_msg(self):
        msg = email.message_from_string(good1, _class=Message)
        msg.id = "Test"
        dummy_values = [('a', 1), ('b', 2)]
        self.db.db[msg.id] = dummy_values
        self.db.load_msg(msg)
        for att, val in dummy_values:
            self.assertEqual(getattr(msg, att), val)

    def test_store_msg(self):
        msg = email.message_from_string(good1, _class=Message)
        msg.id = "Test"

        saved = self.db.store
        self.done = False
        try:
            self.db.store = self._fake_store
            self.db.store_msg(msg)
        finally:
            self.db.store = saved
        self.assertEqual(self.done, True)
        correct = [(att, getattr(msg, att))
                   for att in msg.stored_attributes]
        db_version = dict(self.db.db[msg.id])
        correct_version = dict(correct)
        correct_version["date_modified"], time.time()
        self.assertEqual(db_version, correct_version)

    def _fake_store(self):
        self.done = True

    def test_remove_msg(self):
        msg = email.message_from_string(good1, _class=Message)
        msg.id = "Test"
        self.db.db[msg.id] = "test"
        saved = self.db.store
        self.done = False
        try:
            self.db.store = self._fake_store
            self.db.remove_msg(msg)
        finally:
            self.db.store = saved
        self.assertEqual(self.done, True)
        self.assertRaises(KeyError, self.db.db.__getitem__, msg.id)

    def test_load(self):
        # Create a db to try and load.
        data = {"1": ('a', 'b', 'c'),
                "2": ('d', 'e', 'f'),
                "3": "test"}
        for k, v in list(data.items()):
            self.db.db[k] = v
        self.db.store()
        fn = self.db.db_name
        self.db.close()
        db2 = self.klass(fn, self.mode)
        try:
            self.assertEqual(len(list(db2.db.keys())), len(list(data.keys())))
            for k, v in list(data.items()):
                self.assertEqual(db2.db[k], v)
        finally:
            db2.close()

    def test_load_new(self):
        # Load from a non-existing db (i.e. create new).
        self.assertEqual(list(self.db.db.keys()), [])


class MessageInfoPickleTest(MessageInfoBaseTest):
    def setUp(self):
        self.mode = 1
        self.klass = MessageInfoPickle
        MessageInfoBaseTest.setUp(self)

    # def tearDown(self):
    #     try:
    #         os.remove(TEMP_PICKLE_NAME)
    #     except OSError:
    #         pass

    def store(self):
        if self.db is not None:
            self.db.sync()


class MessageInfoDBTest(MessageInfoBaseTest):
    def setUp(self):
        self.mode = 'c'
        self.klass = MessageInfoDB
        MessageInfoBaseTest.setUp(self)

    def tearDown(self):
        self.db.close()
        # try:
        #     # DBM module adds a .db suffix when opening a file.
        #     os.remove(TEMP_DBM_NAME + '.db')
        # except OSError:
        #     pass

    def store(self):
        if self.db is not None:
            self.db.sync()

    def _fake_close(self):
        self.done += 1

    # TODO this should not be skipped
    @unittest.skip
    def test_close(self):
        saved_db = self.db.db.close
        saved_dbm = self.db.dbm.close
        try:
            self.done = 0
            self.db.db.close = self._fake_close
            self.db.dbm.close = self._fake_close
            self.db.close()
            self.assertEqual(self.done, 2)
        finally:
            # If we don't put these back (whatever happens), then
            # the db isn't closed and can't be deleted in tearDown.
            self.db.db.close = saved_db
            self.db.dbm.close = saved_dbm


class UtilitiesTest(unittest.TestCase):
    def _verify_details(self, details):
        loc = details.find(__file__)
        self.assertNotEqual(loc, -1)
        loc = details.find("Exception: Test")
        self.assertNotEqual(loc, -1)

    def _verify_exception_header(self, msg, details):
        msg = email.message_from_string(msg)
        details = "\r\n ".join(details.strip().split('\n'))
        headerName = 'X-Spambayes-Exception'
        header = email.header.Header(details, header_name=headerName)
        self.assertEqual(msg[headerName].replace('\r\n', '\n'),
                         str(header).replace('\r\n', '\n'))

    def test_insert_exception_header(self):
        # Cause an exception to insert.
        try:
            raise Exception("Test")
        except Exception:
            msg, details = insert_exception_header(good1)
        self._verify_details(details)
        self._verify_exception_header(msg, details)

    def test_insert_exception_header_and_id(self):
        # Cause an exception to insert.
        try:
            raise Exception("Test")
        except Exception:
            id = "Message ID"
            msg, details = insert_exception_header(good1, id)
        self._verify_details(details)
        self._verify_exception_header(msg, details)
        # Check that ID header is inserted.
        msg = email.message_from_string(msg)
        headerName = MAILID_HEADER_NAME
        header = email.header.Header(id, header_name=headerName)
        self.assertEqual(msg[headerName], str(header).replace('\n', '\r\n'))

    def test_insert_exception_header_no_separator(self):
        # Cause an exception to insert.
        try:
            raise Exception("Test")
        except Exception:
            msg, details = insert_exception_header(malformed1)
        self._verify_details(details)
        self._verify_exception_header(msg, details)


# def suite():
#     suite = unittest.TestSuite()
#     classes = (MessageTest,
#                SBHeaderMessageTest,
#                MessageInfoPickleTest,
#                UtilitiesTest,
#                )
#     from spambayes import dbmstorage
#     try:
#         dbmstorage.open_best()
#     except dbmstorage.error:
#         print("Skipping MessageInfoDBTest - no dbm module available")
#         from spambayes import message

#         def always_pickle():
#             return "__test.pik", "pickle"
#         message.database_type = always_pickle
#     except TypeError:
#         # We need an argument, so TypeError will be raised
#         # when it *is* available.
#         classes += (MessageInfoDBTest,)
#     for cls in classes:
#         suite.addTest(unittest.makeSuite(cls))
#     return suite
