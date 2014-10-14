# test_dnsutils.py - unit tests for the sbclassifier.dnsutils module
#
# Copyright (C) 2002-2013 Python Software Foundation; All Rights Reserved
# Copyright 2014 Jeffrey Finkelstein.
#
# This file is part of sbclassifier, which is licensed under the Python
# Software Foundation License; for more information, see LICENSE.txt.
from sbclassifier.dnsutils import dns_lookup
from sbclassifier.dnsutils import reverse_dns_lookup


def test_dns_lookup():
    assert '8.8.8.8' in dns_lookup('google-public-dns-a.google.com')


def test_reverse_dns_lookup():
    assert 'google-public-dns-a.google.com' in reverse_dns_lookup('8.8.8.8')
